# -*- coding: utf-8 -*-
"""
audit_dataset_quality.py — 訓練資料品質稽核

檢查四件事：
  1. 近似重複（模板化）：去掉註解/數字/變數名後，還剩幾種「骨架」？
     → 這是最重要的檢查。若 2500 筆只有 10 種骨架，模型等於只看到 10 筆。
  2. 標籤與程式碼一致性：用關鍵字啟發法，看程式碼像不像標籤說的漏洞
  3. 程式碼長度分布：太短的都是玩具程式碼
  4. 各來源的品質對比：合成 vs CVEfixes vs 組員，誰的品質好

執行：python audit_dataset_quality.py
"""
import os
import re
import sys
import hashlib
from collections import Counter, defaultdict

import pandas as pd

# 已移入子目錄，需往上一層才能 import 到 reviewer/ 下的模組
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.config_loader import label_to_category, get_category

TRAIN_CSV = "dataset/train_18.csv"
REPORT = "dataset/quality_report.txt"

# 各類漏洞的典型關鍵字
SIGNATURES = {
    "sql_injection": ["select", "insert into", "update ", "delete from", "query", "execute(", "cursor", "where"],
    "command_injection": ["os.system", "subprocess", "shell_exec", "runtime.getruntime", "child_process", "popen", "exec("],
    "xss": ["innerhtml", "document.write", "echo", "render_template_string", "mark_safe", "getwriter", "<script"],
    "path_traversal": ["open(", "file_get_contents", "readfile", "../", "include(", "fopen", "new file(", "path.join"],
    "weak_cryptography": ["md5", "sha1", "des", "ecb", "hashlib", "messagedigest", "createhash"],
    "hardcoded_secret": ["password =", "password=", "api_key", "apikey", "secret =", "token =", "aws_"],
    "code_execution": ["eval(", "exec(", "new function", "compile(", "scriptengine", "assert("],
    "data_exfiltration": ["requests.post", "fetch(", "axios", "curl", "httpurlconnection", "urlopen", "send("],
    "backdoor": ["backdoor", "admin", "master", "bypass", "debug", "== 'root'", "secret_key"],
    "insecure_deserialization": ["pickle", "unserialize", "objectinputstream", "yaml.load", "marshal", "readobject"],
    "prototype_pollution": ["__proto__", "prototype[", "constructor", "merge", "object.assign"],
    "malicious_import": ["import", "require(", "install", "pip", "npm"],
    "csrf": ["csrf", "samesite", "token", "referer", "origin"],
    "ssrf": ["requests.get", "urlopen", "axios.get", "fetch(", "new url(", "openconnection", "curl_"],
    "idor": ["findbyid", "find_by_id", "request.args", "req.params", "req.query", "getparameter", "$_get"],
    "file_upload": ["upload", "getoriginalfilename", "$_files", "move_uploaded_file", "multer", "filename"],
    "broken_access_control": ["role", "permission", "isadmin", "is_admin", "authorize", "access", "admin"],
    "clean": [],
}


def _skeleton(code):
    """
    把程式碼抽成「骨架」：移除註解、字串內容、數字、空白，
    只留下結構。用來偵測「同一模板換編號」的近似重複。
    """
    s = str(code)
    # 移除各語言註解
    s = re.sub(r"#.*|//.*|/\*.*?\*/", "", s, flags=re.DOTALL)
    # 字串內容換成佔位
    s = re.sub(r'"[^"]*"|\'[^\']*\'', '""', s)
    # 數字換成佔位
    s = re.sub(r"\b\d+\b", "0", s)
    # 空白全部移除
    s = re.sub(r"\s+", "", s)
    return hashlib.md5(s.lower().encode()).hexdigest()


def main():
    if not os.path.exists(TRAIN_CSV):
        print(f"❌ 找不到 {TRAIN_CSV}")
        return

    df = pd.read_csv(TRAIN_CSV)
    print(f"稽核 {TRAIN_CSV}：{len(df)} 筆\n")

    df["_skel"] = df["code"].apply(_skeleton)
    df["_len"] = df["code"].astype(str).str.len()

    lines = []
    lines.append("=" * 72)
    lines.append("訓練資料品質稽核報告")
    lines.append("=" * 72)

    # ── 1. 全體近似重複 ──
    total_unique = df["_skel"].nunique()
    lines.append(f"\n【檢查1：近似重複（模板化）】")
    lines.append(f"總筆數：{len(df)}")
    lines.append(f"不同「程式碼骨架」數：{total_unique}")
    lines.append(f"多樣性：{total_unique/len(df)*100:.1f}%  "
                 f"（100%=每筆都不同；越低代表越多重複模板）")
    if total_unique / len(df) < 0.3:
        lines.append("⚠️ 嚴重模板化！大量資料是同一模板換數字/變數名，模型學不到東西")
    elif total_unique / len(df) < 0.6:
        lines.append("⚠️ 中度模板化，多樣性偏低")
    else:
        lines.append("✓ 多樣性正常")

    # ── 2. 各類別的多樣性 ──
    lines.append(f"\n【各類別多樣性】")
    lines.append(f"  {'label':<6} {'類別':<22} {'筆數':>6} {'骨架數':>7} {'多樣性':>8}")
    lines.append("  " + "-" * 56)
    for label in sorted(df["label"].unique()):
        sub = df[df["label"] == label]
        uniq = sub["_skel"].nunique()
        ratio = uniq / len(sub) * 100
        cat = label_to_category(label)
        info = get_category(cat) if cat else None
        zh = info.get("name_zh", str(label)) if info else str(label)
        flag = ""
        if ratio < 30:
            flag = "  ⚠️嚴重模板化"
        elif ratio < 60:
            flag = "  ⚠️偏低"
        lines.append(f"  {label:<6} {zh:<22} {len(sub):>6} {uniq:>7} {ratio:>7.1f}%{flag}")

    # ── 3. 各來源的多樣性 ──
    lines.append(f"\n【各資料來源多樣性】")
    lines.append(f"  {'來源':<24} {'筆數':>6} {'骨架數':>7} {'多樣性':>8} {'平均長度':>8}")
    lines.append("  " + "-" * 60)
    for src in df["source"].value_counts().index:
        sub = df[df["source"] == src]
        uniq = sub["_skel"].nunique()
        ratio = uniq / len(sub) * 100
        avg_len = sub["_len"].mean()
        flag = "  ⚠️" if ratio < 40 else ""
        lines.append(f"  {src:<24} {len(sub):>6} {uniq:>7} {ratio:>7.1f}% {avg_len:>8.0f}{flag}")

    # ── 4. 標籤一致性（關鍵字啟發） ──
    lines.append(f"\n【檢查2：標籤與程式碼一致性（抽樣 200 筆/類）】")
    lines.append(f"  {'label':<6} {'類別':<22} {'抽樣':>5} {'疑似錯置':>8} {'錯置率':>8}")
    lines.append("  " + "-" * 56)
    for label in sorted(df["label"].unique()):
        cat = label_to_category(label)
        if not cat or cat == "clean":
            continue
        sigs = SIGNATURES.get(cat, [])
        if not sigs:
            continue
        sub = df[df["label"] == label].sample(n=min(200, (df["label"] == label).sum()),
                                              random_state=42)
        mismatch = 0
        for code in sub["code"]:
            low = str(code).lower()
            if not any(s in low for s in sigs):
                mismatch += 1
        rate = mismatch / len(sub) * 100
        info = get_category(cat)
        zh = info.get("name_zh", cat)
        flag = "  ⚠️" if rate > 30 else ""
        lines.append(f"  {label:<6} {zh:<22} {len(sub):>5} {mismatch:>8} {rate:>7.1f}%{flag}")

    # ── 5. 長度分布 ──
    lines.append(f"\n【檢查3：程式碼長度】")
    lines.append(f"  平均：{df['_len'].mean():.0f} 字元")
    lines.append(f"  中位數：{df['_len'].median():.0f}")
    lines.append(f"  最短：{df['_len'].min()}　最長：{df['_len'].max()}")
    short = (df["_len"] < 100).sum()
    lines.append(f"  少於100字元（可能是玩具程式碼）：{short} 筆（{short/len(df)*100:.1f}%）")

    report = "\n".join(lines)
    open(REPORT, "w", encoding="utf-8").write(report)
    print(report)
    print(f"\n✅ 報告：{REPORT}")


if __name__ == "__main__":
    main()