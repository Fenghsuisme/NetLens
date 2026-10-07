# -*- coding: utf-8 -*-
"""
check_rules.py — Semgrep 規則品質檢查

偵測五類問題，前三類都是實測確認會造成大量誤報的缺陷：

  ① 語意化 metavariable
     Semgrep 中 $大寫 一律是 metavariable，不是字面變數名。
     寫 `echo $API_KEY;` 以為在匹配名為 api_key 的變數，
     實際等同 `echo $任意變數;`——匹配每一個 echo 敘述。
     實測 php-sensitive-info-exposure-cwe200 因此在 150 筆 clean
     樣本上產生 49 個誤報，是全庫最高。

  ② 重複 pattern
     $DB.query(...) 與 $CONN.query(...) 是同一條規則。
     metavariable 的名稱不影響匹配範圍。
     重複本身無害，但通常代表作者誤以為它們不同，
     是①的前兆，也讓 per-rule 統計失真。

  ③ 裸 sink
     `path.join(...)` 這種只標 sink、不帶任何約束的 pattern。
     在兩階段架構中，規則同時擔任「偵測器」與「片段選點器」，
     過寬的 sink 會讓片段抽到錯誤的函式——這損失的是召回，不只是精確度。
     裸 sink 未必是錯的（高召回是刻意設計），但數量需要被看見。

  ④ CWE 對應斷裂
     規則的 metadata.cwe 不在 A_CLASS_CWES 內時，
     finding 會走 semgrep_only，永遠不送 CodeBERT——
     等於該規則在 e2e 管道上沒有作用，且誤報完全沒有過濾。
     已因此漏過 CWE-326、CWE-327 兩次。

  ⑤ Semgrep 驗證失敗
     YAML 合法但 Semgrep 規則無效（pattern 語法錯、schema 不符）。
     yaml.safe_load 讀得過、前四項也看不出來，但實跑時整條 parse error
     靜默失效——本輪就有一條 PHP 規則因此消失，只有實跑 semgrep 才看得到。
     以 semgrep --validate --json 偵測，逐檔歸屬錯誤位置。

用法：
    python check_rules.py                    掃描 rules/ 下全部
    python check_rules.py rules/php.yml      指定檔案
    python check_rules.py --strict           有問題時回傳非零（供 CI 用）
    python check_rules.py --no-validate      略過⑤，加快互動式檢查
"""
import argparse
import collections
import json
import glob
import os
import re
import shutil
import subprocess
import sys

try:
    import yaml
except ImportError:
    print("需要 pyyaml：pip install pyyaml")
    sys.exit(1)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from transport_layer import A_CLASS_CWES, SKIP_CWES
except Exception:
    A_CLASS_CWES, SKIP_CWES = set(), set()

# cwe_catalog.json 決定 finding 能不能被對應到類別。
# 不在 catalog 內的 CWE，cwe_to_category 回 None，finding 會被直接丟棄。
try:
    with open("config/cwe_catalog.json", encoding="utf-8") as _fh:
        CATALOG = {k for k in json.load(_fh) if str(k).startswith("CWE-")}
except Exception:
    CATALOG = set()

# PHP 超全域與 $this 是字面量，Semgrep 不當成 metavariable
PHP_LITERALS = {"$_GET", "$_POST", "$_REQUEST", "$_SERVER", "$_ENV",
                "$_COOKIE", "$_FILES", "$_SESSION", "$this", "$GLOBALS"}

# 帶明顯語意的 metavariable 名稱 → 作者八成想當字面量用
SEMANTIC = re.compile(
    r"\$(API_?KEY|SECRET|PASSWORD|PASSWD|PWD|TOKEN|CONNECTION_STRING|"
    r"CONN_STR|CREDENTIAL|DSN|EMAIL|ROLE|ACTION|USERNAME|USER_ID|"
    r"PRIVATE_KEY|ADMIN|SESSION_ID)\b")

MV = re.compile(r"\$[A-Z_][A-Z0-9_]*")
BARE_SINK = re.compile(r"^[\w$.]+\(\.\.\.\)$")

# 這些 key 底下的 pattern 是「排除條件」，不是偵測目標
NEG_KEYS = {"pattern-not", "pattern-not-inside", "pattern-not-regex",
            "metavariable-pattern", "pattern-sanitizers"}


def normalize(p):
    """把 metavariable 名稱統一，用來偵測實質重複的 pattern。"""
    return MV.sub(lambda m: m.group(0) if m.group(0) in PHP_LITERALS else "$M", p)


def collect_patterns(node, in_neg=False, out=None):
    """遞迴抽出所有『正向』pattern 字串（排除 pattern-not 等）。"""
    if out is None:
        out = []
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "pattern" and isinstance(v, str):
                if not in_neg:
                    out.append(v)
            else:
                collect_patterns(v, in_neg or k in NEG_KEYS, out)
    elif isinstance(node, list):
        for x in node:
            collect_patterns(x, in_neg, out)
    return out


def load_rules(path):
    try:
        doc = yaml.safe_load(open(path, encoding="utf-8"))
    except Exception as e:
        return None, f"YAML 解析失敗：{e}"
    if doc is None:
        return [], None
    rules = doc if isinstance(doc, list) else doc.get("rules", [])
    if not isinstance(rules, list):
        return [], "找不到 rules 陣列"
    return rules, None


def constrained_metavars(node, out=None):
    """
    收集已被 metavariable-regex / metavariable-pattern / metavariable-comparison
    約束的 metavariable 名稱。

    這些不算①，因為作者已經明確限定了它的匹配範圍——
    例如 `boolean $ADMIN = $T.equals(...)` 搭配
    metavariable-regex: $ADMIN → (?i).*(admin|root|bypass).*
    是正確用法，不是把 metavariable 誤當字面量。
    """
    if out is None:
        out = set()
    if isinstance(node, dict):
        for k, v in node.items():
            if k in ("metavariable-regex", "metavariable-pattern",
                     "metavariable-comparison", "metavariable-analysis"):
                if isinstance(v, dict) and v.get("metavariable"):
                    out.add(v["metavariable"])
                elif isinstance(v, list):
                    for x in v:
                        if isinstance(x, dict) and x.get("metavariable"):
                            out.add(x["metavariable"])
            else:
                constrained_metavars(v, out)
    elif isinstance(node, list):
        for x in node:
            constrained_metavars(x, out)
    return out


def _semgrep_exe():
    """找出可用的 semgrep 執行檔（PATH 優先，其次同 venv、再其次專案 .venv）。"""
    exe = shutil.which("semgrep")
    if exe:
        return exe
    here = os.path.dirname(os.path.abspath(__file__))
    for cand in (os.path.join(os.path.dirname(sys.executable), "semgrep"),
                 os.path.join(here, ".venv", "bin", "semgrep")):
        if os.path.exists(cand):
            return cand
    return None


def validate_configs(paths):
    """
    ⑤ 用 semgrep --validate 抓「YAML 合法但 Semgrep 無效」的規則。

    這類規則 yaml.safe_load 讀得過、check_rules 前四項也看不出來，
    但實跑時整條 parse error 靜默失效（本輪就有一條 PHP 規則因此消失）。
    --validate 的退出碼不可靠，改解析 --json 的 errors；
    每個 error 的 spans[0].file / start.line 提供檔案與行號歸屬。

    回傳 {檔案: [(行, 類型, rule_id, 訊息首行)]}；semgrep 不可用時回傳 None。
    """
    exe = _semgrep_exe()
    if not exe:
        return None
    local = [p for p in paths if os.path.exists(p)]
    if not local:
        return {}
    cmd = [exe, "--validate", "--json"]
    for p in local:
        cmd += ["--config", p]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except Exception:
        return None
    # 設定全部合法時，semgrep --validate 的 stdout 為空（訊息走 stderr），
    # 只有偵測到錯誤才在 stdout 輸出 JSON。空 stdout 即代表零錯誤。
    stdout = (out.stdout or "").strip()
    if not stdout:
        return {}
    try:
        data = json.loads(stdout)
    except Exception:
        return None
    grouped = collections.defaultdict(list)
    for e in data.get("errors", []):
        if e.get("level") != "error":
            continue
        t = e.get("type")
        if isinstance(t, list):
            t = t[0] if t else "?"
        msg = (e.get("message") or e.get("long_msg") or e.get("short_msg") or "").strip()
        head = msg.splitlines()[0] if msg else ""
        span = (e.get("spans") or [{}])[0]
        f = span.get("file", "?")
        line = (span.get("start") or {}).get("line")
        grouped[f].append((line, t, e.get("rule_id"), head))
    return dict(grouped)


def check_file(path):
    rules, err = load_rules(path)
    if err:
        return {"path": path, "error": err}

    issues = {"semantic": [], "dup": [], "bare": [],
              "orphan": [], "nocwe": [], "bclass": []}
    for r in rules:
        if not isinstance(r, dict):
            continue
        rid = r.get("id", "?")
        pats = collect_patterns(r)
        bound = constrained_metavars(r)

        for p in pats:
            for m in SEMANTIC.finditer(p):
                if m.group(0) in bound:
                    continue        # 已被 metavariable-regex 等限定，非缺陷
                issues["semantic"].append((rid, m.group(0), p.strip()[:70]))

        counts = collections.Counter(normalize(p) for p in pats)
        for np, n in counts.items():
            if n > 1:
                issues["dup"].append((rid, n, np[:70]))

        for p in pats:
            if BARE_SINK.match(p.strip()):
                issues["bare"].append((rid, p.strip()))

        raw = (r.get("metadata") or {}).get("cwe")
        cwes = []
        if raw:
            for x in (raw if isinstance(raw, list) else [raw]):
                mm = re.search(r"CWE[-\s]?(\d+)", str(x))
                if mm:
                    cwes.append(f"CWE-{mm.group(1)}")

        # ④ 只有兩種情況是真缺陷：
        #    缺 metadata.cwe        → 傳輸層無法分流，finding 直接丟棄
        #    CWE 不在 cwe_catalog   → cwe_to_category 回 None，finding 丟棄
        #                             （CWE-326 / CWE-327 就是這樣漏掉的）
        # 「CWE 不在 A_CLASS_CWES」不是缺陷 —— B 類 CWE 走 semgrep_only
        # 是架構設計，只是這些 finding 不經模型過濾，列為資訊供參考。
        if not cwes:
            issues["nocwe"].append(rid)
        else:
            orphan = [c for c in cwes if CATALOG and c not in CATALOG]
            if orphan:
                issues["orphan"].append((rid, orphan))
            elif A_CLASS_CWES and not any(c in A_CLASS_CWES for c in cwes):
                issues["bclass"].append((rid, cwes))

    return {"path": path, "n_rules": len(rules), "issues": issues}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="*", help="規則檔（預設 rules/*.yml）")
    ap.add_argument("--strict", action="store_true",
                    help="發現①②④時回傳非零（供 CI 用）")
    ap.add_argument("--show-bare", action="store_true",
                    help="列出所有裸 sink（預設只計數）")
    ap.add_argument("--show-bclass", action="store_true",
                    help="列出 B 類規則（預設只計數）")
    ap.add_argument("--no-validate", action="store_true",
                    help="略過 semgrep --validate（⑤），加快互動式檢查")
    args = ap.parse_args()

    paths = args.paths or sorted(glob.glob("rules/*.yml"))
    if not paths:
        print("找不到規則檔")
        return 1

    tot = collections.Counter()
    hard_fail = 0
    val_fail = 0

    for path in paths:
        res = check_file(path)
        if res.get("error"):
            print(f"\n❌ {path}: {res['error']}")
            hard_fail += 1
            continue
        iss = res["issues"]
        n = sum(len(v) for v in iss.values())
        if n == 0:
            continue

        print(f"\n{'=' * 72}\n{path}　（{res['n_rules']} 條規則）\n{'=' * 72}")

        if iss["semantic"]:
            print("\n① 語意化 metavariable（$大寫 是萬用字元，不是變數名）")
            for rid, mv, p in iss["semantic"]:
                print(f"    {rid}")
                print(f"      {mv} ← 等同任意變數　|　{p}")
            tot["semantic"] += len(iss["semantic"])

        if iss["dup"]:
            print("\n② 重複 pattern（metavariable 名稱不影響匹配）")
            for rid, cnt, p in iss["dup"]:
                print(f"    {rid}　×{cnt}　{p}")
            tot["dup"] += len(iss["dup"])

        if iss["orphan"]:
            print("\n④ CWE 不在 cwe_catalog.json（finding 會被直接丟棄）")
            for rid, cwes in iss["orphan"]:
                print(f"    {rid}　{cwes}")
            tot["orphan"] += len(iss["orphan"])

        if iss["nocwe"]:
            print("\n④ 缺 metadata.cwe（finding 會被直接丟棄）")
            for rid in iss["nocwe"]:
                print(f"    {rid}")
            tot["nocwe"] += len(iss["nocwe"])

        if iss["bclass"] and args.show_bclass:
            print("\n〔資訊〕B 類 CWE：走 semgrep_only，不經模型過濾")
            for rid, cwes in iss["bclass"]:
                print(f"    {rid}　{cwes}")
        tot["bclass"] += len(iss["bclass"])

        if iss["bare"]:
            by_rule = collections.Counter(r for r, _ in iss["bare"])
            print(f"\n③ 裸 sink　{len(iss['bare'])} 個，分布於 {len(by_rule)} 條規則")
            for rid, c in by_rule.most_common(5):
                print(f"    {rid}　{c} 個")
            if args.show_bare:
                for rid, p in iss["bare"]:
                    print(f"      {rid}: {p}")
            tot["bare"] += len(iss["bare"])

    # ⑤ Semgrep 驗證：抓 YAML 合法但 Semgrep 無效、會靜默失效的規則
    val_note = ""
    if args.no_validate:
        val_note = "（--no-validate 已略過）"
    else:
        grouped = validate_configs(paths)
        if grouped is None:
            val_note = "（semgrep 不可用，未執行）"
        elif grouped:
            print(f"\n{'=' * 72}\n⑤ Semgrep 驗證失敗（規則會靜默 parse error 失效）\n{'=' * 72}")
            for f in sorted(grouped):
                print(f"\n{f}")
                for line, typ, rid, head in grouped[f]:
                    loc = f":{line}" if line else ""
                    who = f"{rid}　" if rid else ""
                    print(f"    {typ}{loc}　{who}{head}")
                    val_fail += 1

    print(f"\n{'=' * 72}\n總計")
    print(f"{'=' * 72}")
    print(f"  ① 語意化 metavariable   {tot['semantic']:>4}   ← 確定缺陷，應修")
    print(f"  ② 重複 pattern          {tot['dup']:>4}   ← 通常是①的前兆")
    print(f"  ③ 裸 sink               {tot['bare']:>4}   ← 需判斷，未必是錯")
    print(f"  ④ CWE 對應斷裂          {tot['orphan'] + tot['nocwe']:>4}   ← 確定缺陷，finding 被丟棄")
    print(f"  ⑤ Semgrep 驗證失敗      {val_fail:>4}   ← 確定缺陷，規則靜默失效 {val_note}")
    print(f"\n  〔資訊〕B 類規則        {tot['bclass']:>4}   "
          f"走 semgrep_only，無模型過濾（--show-bclass 列出）")

    if args.strict and (tot["semantic"] or tot["orphan"] or tot["nocwe"]
                        or hard_fail or val_fail):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())