# -*- coding: utf-8 -*-
"""
audit_comment_leak.py — 稽核「註解洩漏答案」問題

檢查訓練資料的註解是否直接寫出漏洞是什麼。
若模型能靠讀註解作弊，驗證集分數會虛高，但真實程式碼掃描會失效。

檢查：
  1. 含有漏洞標記註解的比例（各來源、各類別）
  2. 移除註解後，程式碼還剩多少內容
  3. 列出最常見的洩漏註解樣式

執行：python audit_comment_leak.py
"""
import os
import re
import sys
from collections import Counter, defaultdict

import pandas as pd

# 已移入子目錄，需往上一層才能 import 到 reviewer/ 下的模組
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.config_loader import label_to_category, get_category

TRAIN_CSV = "dataset/train_18.csv"
REPORT = "dataset/comment_leak_report.txt"

# 洩漏答案的註解關鍵字（英文為主，AI 生成常用）
LEAK_KEYWORDS = [
    "hidden vulnerability", "vulnerability:", "vulnerable:", "security issue",
    "this is vulnerable", "insecure:", "flaw:", "weakness:",
    "note: this", "warning: this", "bug:", "exploit",
    "sql injection", "command injection", "xss", "cross-site",
    "path traversal", "idor", "ssrf", "csrf", "deserialization",
    "hardcoded", "backdoor", "prototype pollution",
    "漏洞", "不安全", "有問題",
]

def extract_comments(code, lang):
    """抽出所有註解文字"""
    comments = []
    s = str(code)
    # Python / shell 風格
    comments += re.findall(r"#(.*)", s)
    # C 風格單行
    comments += re.findall(r"//(.*)", s)
    # C 風格多行
    comments += re.findall(r"/\*(.*?)\*/", s, re.DOTALL)
    # docstring
    comments += re.findall(r'"""(.*?)"""', s, re.DOTALL)
    return " ".join(comments)


def has_leak(comment_text):
    low = comment_text.lower()
    hits = [k for k in LEAK_KEYWORDS if k in low]
    return hits


def strip_comments(code):
    s = str(code)
    s = re.sub(r'""".*?"""', "", s, flags=re.DOTALL)
    s = re.sub(r"/\*.*?\*/", "", s, flags=re.DOTALL)
    s = re.sub(r"#.*", "", s)
    s = re.sub(r"//.*", "", s)
    return s


def main():
    df = pd.read_csv(TRAIN_CSV)
    print(f"稽核 {len(df)} 筆...\n")

    leak_flags = []
    leak_samples = []
    all_leak_phrases = Counter()

    for _, row in df.iterrows():
        cmt = extract_comments(row["code"], row.get("language", ""))
        hits = has_leak(cmt)
        leak_flags.append(len(hits) > 0)
        if hits:
            all_leak_phrases.update(hits)
            if len(leak_samples) < 15:
                snippet = cmt.strip()[:120]
                leak_samples.append((row["label"], row["source"], snippet))

    df["_leak"] = leak_flags
    df["_len_orig"] = df["code"].astype(str).str.len()
    df["_len_nocmt"] = df["code"].apply(lambda c: len(strip_comments(c)))
    df["_cmt_ratio"] = 1 - df["_len_nocmt"] / df["_len_orig"].clip(lower=1)

    lines = []
    lines.append("=" * 74)
    lines.append("註解洩漏答案 稽核報告")
    lines.append("=" * 74)

    total_leak = df["_leak"].sum()
    lines.append(f"\n【總覽】")
    lines.append(f"總筆數：{len(df)}")
    lines.append(f"含有洩漏答案註解：{total_leak} 筆（{total_leak/len(df)*100:.1f}%）")
    lines.append(f"註解佔程式碼比例（平均）：{df['_cmt_ratio'].mean()*100:.1f}%")
    if total_leak / len(df) > 0.3:
        lines.append("⚠️ 嚴重！大量資料的註解直接寫出漏洞，模型可能靠讀註解作弊")
    elif total_leak / len(df) > 0.1:
        lines.append("⚠️ 中度洩漏，建議移除註解後重訓")
    else:
        lines.append("✓ 洩漏程度低")

    lines.append(f"\n【各來源的洩漏率】")
    lines.append(f"  {'來源':<24} {'筆數':>6} {'洩漏':>6} {'洩漏率':>8} {'註解佔比':>8}")
    lines.append("  " + "-" * 58)
    for src in df["source"].value_counts().index:
        sub = df[df["source"] == src]
        n_leak = sub["_leak"].sum()
        rate = n_leak / len(sub) * 100
        flag = "  ⚠️" if rate > 30 else ""
        lines.append(f"  {src:<24} {len(sub):>6} {n_leak:>6} {rate:>7.1f}% "
                     f"{sub['_cmt_ratio'].mean()*100:>7.1f}%{flag}")

    lines.append(f"\n【各類別的洩漏率】")
    lines.append(f"  {'label':<6} {'類別':<22} {'筆數':>6} {'洩漏率':>8}")
    lines.append("  " + "-" * 46)
    for label in sorted(df["label"].unique()):
        sub = df[df["label"] == label]
        rate = sub["_leak"].sum() / len(sub) * 100
        cat = label_to_category(label)
        info = get_category(cat) if cat else None
        zh = info.get("name_zh", str(label)) if info else str(label)
        flag = "  ⚠️" if rate > 30 else ""
        lines.append(f"  {label:<6} {zh:<22} {len(sub):>6} {rate:>7.1f}%{flag}")

    lines.append(f"\n【最常出現的洩漏字眼 TOP 15】")
    for phrase, cnt in all_leak_phrases.most_common(15):
        lines.append(f"  \"{phrase}\" : {cnt} 次")

    lines.append(f"\n【洩漏註解範例】")
    for label, src, snippet in leak_samples[:10]:
        cat = label_to_category(label)
        info = get_category(cat) if cat else None
        zh = info.get("name_zh", str(label)) if info else str(label)
        lines.append(f"  [{zh} / {src}]")
        lines.append(f"     {snippet}")

    report = "\n".join(lines)
    open(REPORT, "w", encoding="utf-8").write(report)
    print(report)
    print(f"\n✅ 報告：{REPORT}")


if __name__ == "__main__":
    main()