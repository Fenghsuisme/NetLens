# -*- coding: utf-8 -*-
"""
transport_layer.py — Semgrep → CodeBERT 傳輸層

架構定位：Semgrep 高召回選點 → 傳輸層抽取片段 → CodeBERT 高精確分類

職責：
  1. 跑 Semgrep 拿到所有 finding（每個含規則ID、CWE、命中行號）
  2. 依 CWE 分流：
     - A 類（12種可從片段判定）→ 抽取所在函式 → 送 CodeBERT
     - B 類（SSRF/IDOR/權限等）→ 不送 CodeBERT，直接列報告（標「僅Semgrep」）
     - 孤兒 CWE（20/400/770/476）→ 跳過
  3. 抽取片段：以命中行為中心，抽出「整個函式」（含資料流上下文）
  4. 輸出片段列表，每個帶原始位置（供 CodeBERT 判定後對回）

設計說明：
  - 規則是 pattern 模式（高召回），會框出所有可疑點（含安全的），
    由 CodeBERT 負責過濾誤報 → 這是兩階段架構的核心分工
  - 一行可能被多規則命中 → 每個 finding 分開處理
  - 片段用「整個函式」而非固定行數，因為漏洞判斷需要完整函式邏輯

執行：
  python transport_layer.py <程式碼檔案>
  或 import 後呼叫 extract_snippets(code, language)
"""
import os
import re
import sys
import json
import subprocess
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from core.config_loader import cwe_to_category, get_category

# 惡意套件偵測（typosquatting）
# 獨立模組而非 Semgrep 規則，因為需計算與熱門套件的編輯距離，
# pattern 比對無法做到，且惡意套件名無法用黑名單窮舉
try:
    from typosquat_detector import scan_imports
    HAS_TYPOSQUAT = True
except ImportError:
    HAS_TYPOSQUAT = False

RULES_DIR = "rules"

# ── 完整規則集（單一事實來源）──
# 生產掃描與評估必須使用同一套規則，否則兩者量的不是同一個系統。
# 舊版 scan.py 呼叫 process(code, lang) 未傳 rules_path，
# 只載入 rules/{lang}.yml 一份——七份補強規則與官方規則從未在產品中執行過。
SUPPLEMENT_RULES = [
    "rules/supplement_hardcoded.yml", "rules/supplement_sqli.yml",
    "rules/supplement_xss.yml", "rules/supplement_path.yml",
    "rules/supplement_crypto.yml", "rules/supplement_proto.yml",
    "rules/supplement_codeexec.yml", "rules/supplement_backdoor.yml",
    "rules/supplement_csrf.yml", "rules/supplement_upload.yml",
]
OFFICIAL_RULES = ["p/security-audit"]


def rule_paths(language, with_official=True):
    """回傳該語言應載入的完整規則集。"""
    paths = [os.path.join(RULES_DIR, f"{language}.yml")]
    paths += [p for p in SUPPLEMENT_RULES if os.path.exists(p)]
    if with_official:
        paths += OFFICIAL_RULES
    return paths


def _detect_semgrep_cmd():
    """
    偵測可用的 Semgrep 呼叫方式。

    背景：
      這台開發機的應用程式控制原則（AppLocker/WDAC）會封鎖 semgrep.exe
      （WinError 4551），但 Python 模組本身未被封鎖，
      因此可退回 `python -m semgrep` 執行。

    回傳：可用的指令前綴 list，例如 ["semgrep"] 或 [sys.executable, "-m", "semgrep"]
    """
    global _SEMGREP_CMD
    if _SEMGREP_CMD is not None:
        return _SEMGREP_CMD

    candidates = [
        ["semgrep"],
        [sys.executable, "-m", "semgrep"],
    ]
    for cmd in candidates:
        try:
            r = subprocess.run(cmd + ["--version"],
                               capture_output=True, timeout=60)
            # returncode 0 或有輸出即視為可用
            if r.returncode == 0 or r.stdout:
                _SEMGREP_CMD = cmd
                return cmd
        except Exception:
            continue
    # 都不行，仍回傳預設，讓後續呼叫拋出明確錯誤
    _SEMGREP_CMD = ["semgrep"]
    return _SEMGREP_CMD


_SEMGREP_CMD = None


class SemgrepExecutionError(RuntimeError):
    """
    Semgrep 執行失敗（非「掃描結果為空」）。

    設計理由：
      這台開發機的資安軟體會週期性封鎖 semgrep.exe（WinError 4551），
      若把執行失敗靜默處理成「沒有 finding」，
      會讓實驗把「工具掛了」誤算成「規則沒抓到」，導致召回率被低估。
      因此改為拋出例外，由呼叫端決定要中止還是記錄。

    修復方式：pip install --upgrade --force-reinstall semgrep
    """
    pass


# ══════════════════════════════════════════════════
#  CWE 分類：兩個彼此獨立的概念
# ══════════════════════════════════════════════════
#
# FRAGMENT_JUDGEABLE_CWES —— 「單一函式片段是否足以判定」
#   這是架構性質，與模型能力無關。SQL 注入看一個函式就能判斷；
#   CSRF 需要看整條請求處理路徑才知道 token 驗證是否缺席。
#   用途：scan.py 的軟閘門。若 Semgrep 標的是片段可判的類別，
#         而模型卻回答需要跨檔案上下文的類別，該判定無效。
#
# MODEL_ELIGIBLE_CWES —— 「模型有沒有這個輸出類別」
#   這是模型能力，由 config/vuln_categories.json 的 codebert_supported 決定。
#   用途：process() 決定 finding 送 CodeBERT 或走 semgrep_only。
#
# 兩者曾被合併在單一的 A_CLASS_CWES 中，導致 codebert_supported 開啟 B 類後
# 無法只調整其一。拆分後 MODEL_ELIGIBLE_CWES 由 config 動態產生，
# config 成為唯一事實來源（先前手動同步已漏過 CWE-326、CWE-327 兩次）。

FRAGMENT_JUDGEABLE_CWES = {
    "CWE-89",   # SQL 注入
    "CWE-78",   # 指令注入
    "CWE-77",   # 指令注入（另一 CWE）
    "CWE-94",   # 程式碼執行
    "CWE-79",   # XSS
    "CWE-22",   # 路徑遊走
    "CWE-328",  # 弱雜湊（MD5/SHA1）
    "CWE-327",  # 弱演算法（DES/3DES/RC4/ECB）
    "CWE-326",  # 加密強度不足
    "CWE-916",  # 密碼雜湊強度不足
    "CWE-295",  # 憑證驗證不當
    "CWE-798",  # 硬編碼密碼
    "CWE-502",  # 不安全反序列化
    "CWE-1321", # 原型污染
    "CWE-829",  # 惡意套件/不受信任引入
}


def _load_model_eligible_cwes():
    """
    從 config/vuln_categories.json 取出所有 codebert_supported 類別的 CWE。
    讀取失敗時退回 FRAGMENT_JUDGEABLE_CWES，確保管道仍可運作。
    """
    try:
        with open(os.path.join("config", "vuln_categories.json"),
                  encoding="utf-8") as fh:
            cats = json.load(fh)
    except Exception:
        return set(FRAGMENT_JUDGEABLE_CWES)

    out = set()
    for name, info in cats.items():
        if name == "_meta" or not isinstance(info, dict):
            continue
        if not info.get("codebert_supported"):
            continue
        if info.get("primary_cwe"):
            out.add(info["primary_cwe"])
        out.update(info.get("related_cwe") or [])
    return out or set(FRAGMENT_JUDGEABLE_CWES)


MODEL_ELIGIBLE_CWES = _load_model_eligible_cwes()

# 舊名稱，供既有腳本沿用。語意等同「片段可判定」。
A_CLASS_CWES = FRAGMENT_JUDGEABLE_CWES

# 孤兒 CWE：誤報率高，完全跳過
SKIP_CWES = {"CWE-20", "CWE-400", "CWE-770", "CWE-476"}

# 只啟用「已用測試集評估過」的語言。未評估語言（typescript/csharp/c/cpp）的規則
# 未經召回/誤報驗證，實測在真實碼上大量誤報（bench：ts 規則佔全體噪音 43%），
# 故暫不掃描其副檔名。日後要支援 TypeScript：先驗證/收窄 rules/typescript.yml，
# 再取消下行註解即可（規則檔已保留）。
LANG_EXT = {
    "python": ".py", "javascript": ".js",
    "php": ".php", "java": ".java",
    # ── 未評估、暫停用（日後驗證規則後再啟用）──
    # "typescript": ".ts",
    # "csharp": ".cs", "c": ".c", "cpp": ".cpp",
}
INDENT_LANGS = {"python"}   # 靠縮排判斷函式邊界的語言


# ══════════════════════════════════════════════════
#  函式邊界偵測
# ══════════════════════════════════════════════════
def _extract_function_indent(lines, hit_idx):
    """縮排語言（Python）：往上找 def，往下找縮排回到 def 層級"""
    n = len(lines)
    func_start = hit_idx
    def_indent = 0
    found_def = False
    for i in range(hit_idx, -1, -1):
        m = re.match(r'^(\s*)(async\s+)?def\s+\w+', lines[i])
        if m:
            func_start = i
            def_indent = len(m.group(1))
            found_def = True
            break
    if not found_def:
        # 沒找到 def（可能是模組層級程式碼）→ 取命中行 ±8
        return max(0, hit_idx - 8), min(n - 1, hit_idx + 8)

    func_end = n - 1
    for i in range(func_start + 1, n):
        if lines[i].strip() == "":
            continue
        indent = len(lines[i]) - len(lines[i].lstrip())
        if indent <= def_indent:
            func_end = i - 1
            break
    return func_start, func_end


def _extract_function_brace(lines, hit_idx):
    """大括號語言：往上找函式起點，往下大括號配對找終點"""
    n = len(lines)
    func_start = None
    for i in range(hit_idx, -1, -1):
        line = lines[i]
        is_func = (
            re.search(r'\bfunction\b', line) or
            re.search(r'=>\s*\{', line) or
            re.search(r'\)\s*\{\s*$', line) or
            re.search(r'\b(public|private|protected|static)\b.*\(', line) or
            re.search(r'\bfunc\b', line)
        )
        if is_func and "{" in line:
            func_start = i
            break
    if func_start is None:
        # 找不到函式起點 → 取命中行 ±8
        return max(0, hit_idx - 8), min(n - 1, hit_idx + 8)

    depth = 0
    started = False
    func_end = min(n - 1, hit_idx + 20)
    for i in range(func_start, n):
        depth += lines[i].count("{") - lines[i].count("}")
        if "{" in lines[i]:
            started = True
        if started and depth <= 0:
            func_end = i
            break
    return func_start, func_end


# 各語言的 import 行特徵
_IMPORT_PATTERNS = {
    "python": re.compile(r"^\s*(import\s+\w|from\s+[\w.]+\s+import)"),
    "javascript": re.compile(
        r"^\s*(import\s|const\s+.*=\s*require\(|let\s+.*=\s*require\(|var\s+.*=\s*require\()"),
    "typescript": re.compile(
        r"^\s*(import\s|const\s+.*=\s*require\()"),
    "java": re.compile(r"^\s*(import\s+|package\s+)"),
    "php": re.compile(r"^\s*(use\s+|require(_once)?\s|include(_once)?\s)"),
    "csharp": re.compile(r"^\s*(using\s+|namespace\s+)"),
    "c": re.compile(r"^\s*#include"),
    "cpp": re.compile(r"^\s*#include"),
}
MAX_IMPORT_LINES = 25      # 最多帶多少行 import，避免片段過長


def _extract_imports(lines, language, before_idx):
    """
    抽出檔案開頭的 import 區塊。

    為什麼需要：
      實測片段管道比整檔輸入低 17pp，落差最大的幾類
      （不安全反序列化 -26.7、原型污染 -40.0、弱加密 -23.3）
      判斷依據都在 import 行——
        import pickle    不安全反序列化的強訊號
        import hashlib   弱加密
        from x import y  惡意套件本身即在 import 行
      只抽函式本體會丟失這些關鍵上下文。
    """
    pat = _IMPORT_PATTERNS.get(language)
    if pat is None:
        return []
    out = []
    for i in range(min(before_idx, len(lines))):
        if pat.match(lines[i]):
            out.append(lines[i])
            if len(out) >= MAX_IMPORT_LINES:
                break
    return out


def extract_enclosing_function(code, hit_line, language, with_imports=True):
    """
    給定命中行號（1-indexed），抽出所在的整個函式。
    with_imports=True 時，會把檔案開頭的 import 區塊一併帶上，
    因為部分漏洞類型的判斷依據在 import 行（見 _extract_imports 說明）。

    回傳 (snippet_text, start_line, end_line)（後兩者為 1-indexed，
    指函式本體的範圍，不含補上的 import）
    """
    lines = code.split("\n")
    hit_idx = hit_line - 1
    if hit_idx < 0 or hit_idx >= len(lines):
        return code, 1, len(lines)

    if language in INDENT_LANGS:
        s, e = _extract_function_indent(lines, hit_idx)
    else:
        s, e = _extract_function_brace(lines, hit_idx)

    body = lines[s:e + 1]

    if with_imports:
        imports = _extract_imports(lines, language, s)
        # 只在 import 不在函式範圍內時才補上（避免重複）
        if imports:
            body = imports + [""] + body

    snippet = "\n".join(body)
    return snippet, s + 1, e + 1


# ══════════════════════════════════════════════════
#  Semgrep 執行
# ══════════════════════════════════════════════════
def _normalize_cwes(raw):
    """
    正規化 CWE 欄位，回傳「所有」CWE 編號的 list。

    相容兩種格式：
      自訂規則：["CWE-89"]                                → 純編號
      官方規則：["CWE-89: Improper Neutralization of..."]  → 帶描述

    為什麼要回傳全部（而非只取第一個）：
      官方 p/security-audit 的規則常同時掛多個 CWE，例如
        cwe: ["CWE-20: Improper Input Validation",
              "CWE-89: SQL Injection"]
      舊版只取 raw[0]，遇到這種規則會拿到 CWE-20 —— 它在 SKIP_CWES 裡，
      整筆 finding 就被丟棄，即使第二個 CWE-89 屬 A 類。
      這是靜默的召回損失（不會報錯、也不會出現在任何統計裡）。
    """
    if not raw:
        return []
    items = raw if isinstance(raw, list) else [raw]
    out = []
    for x in items:
        m = re.search(r"CWE[-\s]?(\d+)", str(x))
        if m:
            c = f"CWE-{m.group(1)}"
            if c not in out:
                out.append(c)
    return out


def _pick_primary_cwe(cwes):
    """
    從多個 CWE 中挑出代表值，供 finding["cwe"] 使用（相容舊呼叫端）。

    優先序：A 類 > 非孤兒 > 第一個
      這確保 ["CWE-20", "CWE-89"] 會回傳 CWE-89 而非 CWE-20。

    注意：此為「有利於召回」的選擇。若某規則同時掛了不相關的 A 類 CWE，
    會被歸到該 A 類。實測若發現誤報上升，應改為只信任 metadata 的第一個
    語意 CWE，或在 config 端維護規則白名單。
    """
    if not cwes:
        return None
    for c in cwes:
        if c in A_CLASS_CWES:
            return c
    for c in cwes:
        if c not in SKIP_CWES:
            return c
    return cwes[0]


def _normalize_cwe(raw):
    """舊介面：回傳單一代表 CWE。保留供既有腳本呼叫。"""
    return _pick_primary_cwe(_normalize_cwes(raw))


def run_semgrep(code, language, rules_path=None):
    """
    跑 Semgrep，回傳 finding 列表。

    rules_path 可以是：
      None      → 預設 rules/{language}.yml（單一檔案）
      str       → 單一本地路徑或線上 config（"p/security-audit"）
      list/tuple→ 多份規則，合併為一次 semgrep 呼叫

    傳 list 時只啟動一次 subprocess。九份規則分九次呼叫約需 14 秒，
    合併為一次約 2 秒——對 MCP Server 的互動式使用，這個差異是關鍵。
    """
    os.environ["PYTHONUTF8"] = "1"
    if rules_path is None:
        rules = [os.path.join(RULES_DIR, f"{language}.yml")]
    elif isinstance(rules_path, (list, tuple)):
        rules = list(rules_path)
    else:
        rules = [rules_path]

    # 線上 config（p/... r/...）不做存在性檢查；本地檔案不存在則略過
    valid = [r for r in rules
             if str(r).startswith(("p/", "r/")) or os.path.exists(r)]
    if not valid:
        return []

    ext = LANG_EXT.get(language, ".txt")
    tmp = out = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=ext, delete=False,
                                         encoding="utf-8") as f:
            f.write(code)
            tmp = f.name
        out = tmp + ".json"
        cmd = _detect_semgrep_cmd()
        config_args = []
        for r in valid:
            config_args += ["--config", str(r)]
        proc = subprocess.run(
            cmd + config_args + ["--no-git-ignore",
                                 "--json", "--quiet", "--output", out, tmp],
            capture_output=True, timeout=180,
        )
        if not os.path.exists(out):
            # 執行失敗（如防毒封鎖 WinError 4551、規則錯誤等）
            # 拋出例外而非回傳空 list，避免「執行失敗」被誤認為「沒有漏洞」
            err = (proc.stderr or b"").decode("utf-8", errors="ignore")[:200]
            raise SemgrepExecutionError(
                f"Semgrep 未產生輸出（returncode={proc.returncode}）{err}")
        data = json.load(open(out, encoding="utf-8"))
        findings = []
        for r in data.get("results", []):
            extra = r.get("extra", {})
            meta = extra.get("metadata", {})
            cwes = _normalize_cwes(meta.get("cwe"))
            findings.append({
                "rule_id": r.get("check_id", ""),
                "cwes": cwes,                          # 完整列表
                "cwe": _pick_primary_cwe(cwes),        # 代表值（相容舊呼叫端）
                "start_line": r.get("start", {}).get("line"),
                "end_line": r.get("end", {}).get("line"),
                "message": extra.get("message", ""),
                "severity": extra.get("severity", ""),
            })
        return findings
    except SemgrepExecutionError:
        raise
    except FileNotFoundError:
        raise SemgrepExecutionError(
            "找不到 semgrep 指令，請確認已安裝且在 PATH 中")
    except Exception as e:
        # 其他例外（如 WinError 4551 防毒封鎖）一律視為執行失敗
        raise SemgrepExecutionError(f"{type(e).__name__}: {e}")
    finally:
        for p in (tmp, out):
            if p and os.path.exists(p):
                os.unlink(p)


# ══════════════════════════════════════════════════
#  主流程：分流 + 抽取
# ══════════════════════════════════════════════════
def process(code, language, rules_path=None):
    """
    完整傳輸流程。回傳 dict：
      {
        "to_codebert": [ {片段, 位置, semgrep_cwe, semgrep_category}, ... ],  # A類
        "semgrep_only": [ {位置, cwe, category, message}, ... ],              # B類
        "skipped": [ {位置, cwe}, ... ],                                      # 孤兒
      }
    """
    findings = run_semgrep(code, language, rules_path)

    # 多份規則常對同一位置回報相同 CWE（例如自訂規則與官方規則重疊），
    # 去重避免同一漏洞被抽取多次片段、送模型多次。
    _seen = set()
    _deduped = []
    for f in findings:
        sig = (f.get("start_line"), tuple(f.get("cwes") or []))
        if sig in _seen:
            continue
        _seen.add(sig)
        _deduped.append(f)
    findings = _deduped

    to_codebert = []
    semgrep_only = []
    skipped = []

    for f in findings:
        cwes = f.get("cwes") or ([f["cwe"]] if f.get("cwe") else [])
        line = f["start_line"]
        if not cwes or not line:
            continue

        # 孤兒 CWE → 跳過（須「全部」都是孤兒才跳過；
        # 只要有一個非孤兒，就依該 CWE 分流）
        if all(c in SKIP_CWES for c in cwes):
            skipped.append({"line": line, "cwe": cwes[0]})
            continue

        cwe = _pick_primary_cwe(cwes)
        category = cwe_to_category(cwe)
        cat_zh = get_category(category).get("name_zh") if category else cwe

        # 分流依據是「模型有沒有這個輸出類別」（codebert_supported），
        # 而非「片段夠不夠判定」。後者交由下游閘門處理，
        # 因此 to_codebert 的項目會帶上 fragment_judgeable 旗標。
        if any(c in MODEL_ELIGIBLE_CWES for c in cwes):
            # A 類 → 抽片段送 CodeBERT
            snippet, s, e = extract_enclosing_function(code, line, language)
            to_codebert.append({
                "snippet": snippet,
                "snippet_start": s,
                "snippet_end": e,
                "hit_line": line,
                "semgrep_rule": f["rule_id"],
                "semgrep_cwe": cwe,
                "semgrep_cwes": cwes,
                "semgrep_category": category,
                "semgrep_category_zh": cat_zh,
                # 供 scan.py 的軟閘門判斷：Semgrep 標的是否為片段可判定的類別。
                # 若是，而模型卻回答需要跨檔案上下文的類別，該判定無效。
                "fragment_judgeable": any(c in FRAGMENT_JUDGEABLE_CWES
                                          for c in cwes),
            })
        else:
            # B 類 → 只列報告
            semgrep_only.append({
                "line": line,
                "cwe": cwe,
                "cwes": cwes,
                "category": category,
                "category_zh": cat_zh,
                "message": f["message"],
                "severity": f["severity"],
            })

    # ── 惡意套件偵測（不經 Semgrep）──
    # CWE-829 屬 A 類，但偵測方式是 import 分析而非 pattern 比對，
    # 故獨立於 Semgrep 流程之外，結果併入 to_codebert 供模型複核
    malicious_imports = []
    if HAS_TYPOSQUAT:
        try:
            for f in scan_imports(code, language):
                snippet, s, e = extract_enclosing_function(code, f["line"], language)
                item = {
                    "snippet": snippet,
                    "snippet_start": s,
                    "snippet_end": e,
                    "hit_line": f["line"],
                    "semgrep_rule": "typosquat_detector",
                    "semgrep_cwe": "CWE-829",
                    "semgrep_cwes": ["CWE-829"],
                    "semgrep_category": "malicious_import",
                    "semgrep_category_zh": "惡意套件",
                    "fragment_judgeable": True,
                    "package": f["package"],
                    "reason": f["reason"],
                    "similar_to": f.get("similar_to"),
                    "confidence": f["confidence"],
                }
                to_codebert.append(item)
                malicious_imports.append(item)
        except Exception:
            pass

    return {
        "to_codebert": to_codebert,
        "semgrep_only": semgrep_only,
        "skipped": skipped,
        "malicious_imports": malicious_imports,
    }


def process_all(code, language, rules=None, with_official=True):
    """
    跑「完整規則集」。生產掃描應使用此函式，而非 process()。

    process() 一次只吃一份規則檔，預設 rules/{language}.yml。
    直接呼叫 process(code, lang) 會漏掉七份補強規則與官方規則——
    這正是舊版 scan.py 的狀況，五輪補強成果在產品中完全未生效。

    參數：
      rules          規則檔清單，None = rule_paths(language)
      with_official  是否納入 p/security-audit（離線環境可關閉）

    回傳格式與 process() 相同，可直接替換。
    所有規則合併為單次 semgrep 呼叫，不是逐份執行。
    """
    if rules is None:
        rules = rule_paths(language, with_official=with_official)
    return process(code, language, rules_path=list(rules))


def _demo(path):
    """命令列測試：對一個檔案跑傳輸層，印出結果"""
    if not os.path.exists(path):
        print(f"❌ 找不到 {path}")
        return
    ext = os.path.splitext(path)[1].lower()
    lang = next((l for l, e in LANG_EXT.items() if e == ext), None)
    if not lang:
        print(f"❌ 不支援的副檔名 {ext}")
        return

    code = open(path, encoding="utf-8").read()
    result = process(code, lang)

    print("=" * 70)
    print(f"傳輸層處理結果：{path}（{lang}）")
    print("=" * 70)

    print(f"\n【送 CodeBERT 的片段】（A類，{len(result['to_codebert'])} 個）")
    for i, item in enumerate(result["to_codebert"], 1):
        print(f"\n── 片段 {i} ──")
        print(f"  Semgrep 命中：第 {item['hit_line']} 行，"
              f"{item['semgrep_category_zh']}（{item['semgrep_cwe']}）")
        print(f"  抽取函式：第 {item['snippet_start']}-{item['snippet_end']} 行")
        print(f"  片段內容：")
        for ln in item["snippet"].split("\n"):
            print(f"    | {ln}")

    print(f"\n【僅 Semgrep 偵測】（B類，{len(result['semgrep_only'])} 個）")
    for item in result["semgrep_only"]:
        print(f"  第 {item['line']} 行：{item['category_zh']}（{item['cwe']}）")

    mi = result.get("malicious_imports", [])
    if mi:
        print(f"\n【惡意套件偵測】（typosquatting，{len(mi)} 個）")
        for item in mi:
            sim = f"　可能想引用：{item['similar_to']}" if item.get("similar_to") else ""
            print(f"  第 {item['hit_line']} 行　{item['package']}"
                  f"　{item['reason']}（{item['confidence']}）{sim}")

    print(f"\n【跳過】（孤兒CWE，{len(result['skipped'])} 個）")
    for item in result["skipped"]:
        print(f"  第 {item['line']} 行：{item['cwe']}")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        _demo(sys.argv[1])
    else:
        print("用法：python transport_layer.py <程式碼檔案>")