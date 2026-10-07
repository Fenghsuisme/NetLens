# -*- coding: utf-8 -*-
"""
core/analyzer.py — 新版整合分析器（接融合層）

與舊版 code_analyzer.py 的差別：
  - 三個引擎的偵測邏輯保留（import 掃描 / Semgrep / CodeBERT）
  - 報告組裝改由 core/fusion.py 負責（過濾誤報、合併多引擎、對齊 CWE）
  - 輸出為結構化的 ScanReport（支援單檔，未來可擴充多檔專案掃描）

舊的 code_analyzer.py 保留不動，作為備份與現有 app 的相依。

用法：
  from core.analyzer import analyze_code, analyze_project
  report = analyze_code(code, "login.py")
"""
import os
import json
import subprocess
import tempfile
from pathlib import Path

from core.fusion import fuse_file, build_scan_report

# ── 路徑設定（相對於 reviewer/）──────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
_REVIEWER_ROOT = os.path.dirname(_HERE)
RULES_DIR = os.path.join(_REVIEWER_ROOT, "rules")
BLACKLIST_DIR = os.path.join(_REVIEWER_ROOT, "blacklists")
MODEL_DIR = os.path.join(_REVIEWER_ROOT, "models", "codebert_v4")

LANGUAGE_MAP = {
    ".py": "python", ".js": "javascript", ".ts": "typescript",
    ".jsx": "javascript", ".tsx": "typescript", ".php": "php",
    ".java": "java", ".cs": "csharp", ".go": "go", ".rb": "ruby",
    ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".hpp": "cpp",
}

SAFE_STDLIB = {
    "python": {"os","sys","re","json","math","time","datetime","collections",
        "itertools","functools","pathlib","typing","abc","io","copy","random",
        "string","hashlib","hmac","secrets","logging","unittest","dataclasses",
        "enum","contextlib","threading","multiprocessing","queue","socket","ssl",
        "http","urllib","email","html","xml","csv","sqlite3","struct","array","decimal"},
    "javascript": {"fs","path","os","http","https","url","crypto","events","stream",
        "util","child_process","cluster","net","dns","readline","zlib","buffer"},
    "java": {"java.util","java.io","java.nio","java.lang","java.math","java.net",
        "java.security","java.time","java.text","java.beans","java.awt","javax.swing"},
    "csharp": {"System","System.IO","System.Net","System.Text","System.Collections",
        "System.Threading","System.Linq","System.Security","System.Diagnostics",
        "System.Runtime","Microsoft.AspNetCore","Microsoft.Extensions"},
}

# ── CodeBERT（延遲載入，可選）─────────────────────
_tokenizer = None
_model = None
_torch = None
_device = None


def _lazy_load_model():
    """只在第一次需要時載入 torch + 模型；載入失敗回傳 None（系統仍可只跑前兩層）"""
    global _tokenizer, _model, _torch, _device
    if _model is not None:
        return _tokenizer, _model
    if not os.path.exists(MODEL_DIR):
        return None, None
    try:
        import torch
        from transformers import AutoTokenizer, AutoModelForSequenceClassification
        _torch = torch
        _device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        _tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR)
        _model = AutoModelForSequenceClassification.from_pretrained(MODEL_DIR).to(_device)
        _model.eval()
        return _tokenizer, _model
    except Exception as e:
        print(f"  [analyzer] CodeBERT 載入失敗，略過語意層：{e}")
        return None, None


def _predict_codebert(code):
    """回傳 {'label':int,'confidence':float} 或 None"""
    tok, mdl = _lazy_load_model()
    if mdl is None:
        return None
    try:
        inputs = tok(code[:1000], return_tensors="pt", max_length=512,
                     truncation=True, padding=True)
        inputs = {k: v.to(_device) for k, v in inputs.items()}
        with _torch.no_grad():
            logits = mdl(**inputs).logits
            probs = _torch.softmax(logits, dim=1)
            label = int(_torch.argmax(probs, dim=1).item())
            conf = float(probs[0][label].item())
        return {"label": label, "confidence": round(conf, 4)}
    except Exception as e:
        print(f"  [analyzer] CodeBERT 推論失敗：{e}")
        return None


# ── 黑名單 import 掃描 ────────────────────────────
def _load_blacklist():
    p = os.path.join(BLACKLIST_DIR, "malicious_packages.json")
    if os.path.exists(p):
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def _extract_blacklisted_imports(code, language):
    """只回傳命中黑名單的 import（融合層只需要這個）"""
    bl = set(_load_blacklist().get(language, []))
    if not bl:
        return []
    hits = []
    for i, line in enumerate(code.split("\n"), 1):
        line = line.strip()
        pkg = None
        if language == "python":
            if line.startswith("import "):
                pkg = line[7:].split(".")[0].split(" as ")[0].split("#")[0].strip()
            elif line.startswith("from "):
                pkg = line[5:].split(" import")[0].split(".")[0].strip()
        elif language in ("javascript", "typescript"):
            if "require(" in line:
                try: pkg = line.split("require(")[1].split(")")[0].strip("'\"")
                except Exception: pass
        if pkg and pkg in bl:
            hits.append({"line": i, "package": pkg})
    return hits


# ── Semgrep ───────────────────────────────────────
def _clean_snippet(text):
    """過濾 Semgrep 免費版的佔位訊息，回傳乾淨的程式碼片段"""
    t = (text or "").strip()
    if t in ("requires login", "requires login to see", ""):
        return ""
    return t


def _run_semgrep(code, language):
    ext = {v: k for k, v in LANGUAGE_MAP.items()}.get(language, ".txt")
    tmp_path = out_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=ext, delete=False,
                                         encoding="utf-8") as tmp:
            tmp.write(code); tmp_path = tmp.name
        out_path = tmp_path + ".json"
        rule_file = os.path.join(RULES_DIR, f"{language}.yml")
        config = rule_file if os.path.exists(rule_file) else "p/security-audit"
        subprocess.run(["semgrep","--config",config,"--no-git-ignore","--json",
                        "--quiet","--output",out_path,tmp_path],
                       timeout=60, capture_output=True)
        if not os.path.exists(out_path):
            return []
        with open(out_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        findings = []
        for r in data.get("results", []):
            meta = r.get("extra", {}).get("metadata", {})
            findings.append({
                "rule_id": r.get("check_id", ""),
                "severity": r.get("extra", {}).get("severity", "WARNING"),
                "line_start": r.get("start", {}).get("line", 0),
                "cwe": meta.get("cwe", []),
                "code_snippet": _clean_snippet(r.get("extra", {}).get("lines", "")),
            })
        return findings
    except subprocess.TimeoutExpired:
        return []
    except Exception as e:
        print(f"  [analyzer] Semgrep 失敗：{e}")
        return []
    finally:
        for p in (tmp_path, out_path):
            if p and os.path.exists(p):
                os.unlink(p)


# ── 對外：分析單一檔案（回傳 FileReport）──────────
def analyze_file(code, file_path, use_codebert=True):
    language = LANGUAGE_MAP.get(Path(file_path).suffix.lower(), "python")
    semgrep_raw = _run_semgrep(code, language)
    blacklist_raw = _extract_blacklisted_imports(code, language)
    codebert_raw = _predict_codebert(code) if use_codebert else None
    return fuse_file(file_path, language, semgrep_raw, codebert_raw, blacklist_raw)


# ── 對外：分析單段程式碼（回傳 ScanReport）────────
def analyze_code(code, file_path="code.py", use_codebert=True):
    fr = analyze_file(code, file_path, use_codebert)
    return build_scan_report([fr], scan_type="single_file")


# ── 對外：分析整個專案（回傳 ScanReport）──────────
def analyze_project(root_dir, use_codebert=True, max_files=500):
    """遞迴掃描資料夾內所有支援語言的檔案"""
    file_reports = []
    count = 0
    for dirpath, dirnames, filenames in os.walk(root_dir):
        # 跳過常見無關資料夾
        dirnames[:] = [d for d in dirnames if d not in
                       {".git","node_modules","venv","__pycache__",".venv","dist","build"}]
        for fn in filenames:
            ext = Path(fn).suffix.lower()
            if ext not in LANGUAGE_MAP:
                continue
            if count >= max_files:
                break
            full = os.path.join(dirpath, fn)
            try:
                with open(full, "r", encoding="utf-8", errors="ignore") as f:
                    code = f.read()
            except Exception:
                continue
            rel = os.path.relpath(full, root_dir)
            file_reports.append(analyze_file(code, rel, use_codebert))
            count += 1
    return build_scan_report(file_reports, scan_type="project")


# ── 文字報告輸出（給 CLI/debug 用）────────────────
def format_report(report):
    lines = []
    lines.append("=" * 60)
    lines.append(f"{report['verdict']}　風險分數：{report['risk_score']}/100")
    o = report["overall_summary"]
    lines.append(f"檔案數：{o['files_scanned']}　"
                 f"CRITICAL:{o['critical']} HIGH:{o['high']} "
                 f"MEDIUM:{o['medium']} LOW:{o['low']}")
    for fr in report["files"]:
        if fr["summary"]["total"] == 0:
            continue
        lines.append("")
        lines.append(f"檔案：{fr['file_path']}（{fr['language']}）")
        lines.append("-" * 60)
        for f in fr["findings"]:
            src = "+".join(f["sources"])
            conf = f"　信心{f['confidence']:.0%}" if f["confidence"] else ""
            lines.append(f"  第{f['line']:>3}行 [{f['severity']:<8}] "
                         f"{f['display_name']}（{f['cwe'] or '—'}）"
                         f"　來源：{src}{conf}")
            if f["code_snippet"]:
                lines.append(f"        {f['code_snippet'][:70]}")
    lines.append("=" * 60)
    return "\n".join(lines)


if __name__ == "__main__":
    test_code = '''import os
import requests
import colourama

def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)

def run(cmd):
    os.system(cmd)

password = "hardcoded_secret_123"
'''
    report = analyze_code(test_code, "test.py")
    print(format_report(report))