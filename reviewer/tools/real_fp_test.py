# -*- coding: utf-8 -*-
"""
real_fp_test.py — 在真實專案上跑完整管道（Semgrep + CodeBERT），量噪音密度

真實專案沒有漏洞標籤，故「不量召回」；量的是使用者實際會看到的輸出：
  - 每千行幾個 finding（confirmed + disputed 才會呈現）
  - verdict 分佈（confirmed / disputed / filtered / engine_only）
  - 哪條規則、哪個類別在真實碼上爆量（找放寬過頭的規則）

用法（在 reviewer/ 根目錄、有模型的機器上）：
    # 1) 先把要測的專案 clone 到某個資料夾，例如：
    #    mkdir -p /tmp/proj && cd /tmp/proj
    #    git clone --depth 1 https://github.com/pallets/flask
    #    git clone --depth 1 https://github.com/expressjs/express
    #    ...
    # 2) 回到 reviewer/，逐個掃：
    python tools/real_fp_test.py /tmp/proj/flask /tmp/proj/express ...

    # 只跑規則（不載模型，快，看原始 semgrep 噪音）：
    python tools/real_fp_test.py --no-model /tmp/proj/flask ...

    # 已有 scan.py 的 JSON，只重算報告：
    python tools/real_fp_test.py --from-json out_flask.json out_express.json
"""
import argparse
import json
import os
import subprocess
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCAN = os.path.join(ROOT, "scan.py")
EXTS = {".py", ".js", ".ts", ".java", ".php", ".c", ".cpp", ".cs", ".go", ".rb"}
SKIP_DIRS = {"node_modules", ".git", "venv", ".venv", "__pycache__",
             "dist", "build", "target", "vendor", ".idea", ".vscode", "test", "tests"}


def count_loc(path):
    """統計專案內受支援語言檔的總行數（粗略，排除常見非原始碼目錄）。"""
    total = 0
    if os.path.isfile(path):
        paths = [path]
    else:
        paths = []
        for r, dirs, names in os.walk(path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
            for n in names:
                if os.path.splitext(n)[1].lower() in EXTS:
                    paths.append(os.path.join(r, n))
    for p in paths:
        try:
            with open(p, encoding="utf-8", errors="ignore") as f:
                total += sum(1 for _ in f)
        except Exception:
            pass
    return total


def run_scan(proj, no_model):
    """跑 scan.py --out，回傳 payload dict。"""
    name = os.path.basename(os.path.normpath(proj))
    out = os.path.join(ROOT, f"realfp_{name}.json")
    cmd = [sys.executable, SCAN, proj, "--out", out]
    if no_model:
        cmd.append("--no-model")
    print(f"  掃描 {name} ...", flush=True)
    r = subprocess.run(cmd, capture_output=True, text=True)
    if not os.path.exists(out):
        print(f"    ⚠️ scan.py 失敗：{r.stdout[-400:]}{r.stderr[-400:]}")
        return None
    return json.load(open(out, encoding="utf-8"))


def tally(payload, loc, agg):
    """把單一專案的結果併入彙總。"""
    for res in payload.get("results", []):
        for verdict in ("confirmed", "disputed", "filtered", "engine_only"):
            items = res.get(verdict, [])
            agg["verdict"][verdict] += len(items)
            for it in items:
                rule = it.get("engine_rule") or it.get("rule") or "?"
                cat = it.get("engine_category_zh") or it.get("category_zh") or "?"
                if verdict in ("confirmed", "disputed"):   # 只有這兩種會呈現給使用者
                    agg["rule_shown"][rule] += 1
                    agg["cat_shown"][cat] += 1
    agg["loc"] += loc


def report(agg, n_proj):
    loc = max(agg["loc"], 1)
    kloc = loc / 1000
    v = agg["verdict"]
    shown = v["confirmed"] + v["disputed"]
    print("\n" + "=" * 70)
    print(f"真實專案噪音報告（{n_proj} 個專案，共 {agg['loc']:,} 行受支援原始碼）")
    print("=" * 70)
    print(f"\nverdict 分佈：")
    print(f"  ✅ confirmed（呈現）      {v['confirmed']:>6}")
    print(f"  🔍 disputed （呈現）      {v['disputed']:>6}")
    print(f"  ⚪ filtered （模型壓掉）  {v['filtered']:>6}")
    print(f"  📋 engine_only（B類未判） {v['engine_only']:>6}")
    print(f"\n【關鍵指標】呈現給使用者的 finding 密度")
    print(f"  confirmed+disputed = {shown}　→ {shown/kloc:.2f} 個 / KLOC")
    filt = v["filtered"]; total_model = filt + shown
    if total_model:
        print(f"  模型過濾率（A類）    {filt}/{total_model} = {filt/total_model*100:.1f}%")
    print(f"\n呈現 finding 最多的規則（前 15，找放寬過頭的）：")
    for rule, c in agg["rule_shown"].most_common(15):
        print(f"  {c:>5}  {rule}")
    print(f"\n呈現 finding 的類別分佈：")
    for cat, c in agg["cat_shown"].most_common():
        print(f"  {c:>5}  {cat}")


def main():
    ap = argparse.ArgumentParser(description="真實專案完整管道噪音測試")
    ap.add_argument("projects", nargs="*", help="專案目錄（或 --from-json 的 JSON 檔）")
    ap.add_argument("--no-model", action="store_true", help="只跑規則，不載模型")
    ap.add_argument("--from-json", action="store_true", help="直接讀既有 scan.py JSON")
    args = ap.parse_args()
    if not args.projects:
        print("請提供專案目錄，見檔頭用法說明")
        return 1

    agg = {"verdict": Counter(), "rule_shown": Counter(),
           "cat_shown": Counter(), "loc": 0}
    n = 0
    for p in args.projects:
        if args.from_json:
            payload = json.load(open(p, encoding="utf-8"))
            # 從 JSON 反推 LOC：加總結果檔行數
            loc = sum(count_loc(res["file"]) for res in payload.get("results", [])
                      if os.path.exists(res.get("file", "")))
        else:
            payload = run_scan(p, args.no_model)
            if payload is None:
                continue
            loc = count_loc(p)
        tally(payload, loc, agg)
        n += 1
    if n:
        report(agg, n)
    return 0


if __name__ == "__main__":
    sys.exit(main())
