# -*- coding: utf-8 -*-
"""
integrate_teammate_data.py — 掃描組員的 CWE 資料夾,轉成本專案格式並統計

組員資料結構:
  <根目錄>/CWE-89/xxx_codellama.java
           CWE-79/xxx_qwen2.5-coder.js
           ...
  - 資料夾名 = CWE 編號
  - 副檔名 = 語言
  - 檔名含生成模型(codellama / qwen2.5-coder)

用法:
  python integrate_teammate_data.py <組員資料夾路徑>
  例:python integrate_teammate_data.py ../teammate_data

輸出:
  dataset/teammate_aligned.csv       轉換後的資料
  dataset/teammate_report.txt        統計報告
"""
import os
import sys
import re
import hashlib
from collections import defaultdict, Counter

import pandas as pd

# 已移入子目錄，需往上一層才能 import 到 reviewer/ 下的模組
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.config_loader import cwe_to_category, get_category, get_cwe_info

# 副檔名 → 語言
EXT_LANG = {
    ".py": "python", ".js": "javascript", ".ts": "typescript",
    ".jsx": "javascript", ".tsx": "typescript",
    ".php": "php", ".java": "java", ".cs": "csharp",
    ".c": "c", ".cpp": "cpp", ".cc": "cpp", ".h": "c", ".hpp": "cpp",
}

OUT_CSV = "dataset/teammate_aligned.csv"
REPORT = "dataset/teammate_report.txt"
MIN_CODE_LEN = 30


def _detect_model(filename):
    """從檔名推測生成模型"""
    low = filename.lower()
    if "codellama" in low:
        return "codellama"
    if "qwen" in low:
        return "qwen"
    if "gemini" in low:
        return "gemini"
    if "gpt" in low:
        return "gpt"
    return "unknown"


def _norm_cwe(name):
    """資料夾名 → 標準 CWE 格式。'CWE-89' / 'cwe89' / '89' → 'CWE-89'"""
    m = re.search(r"(\d+)", str(name))
    return f"CWE-{m.group(1)}" if m else None


def main():
    if len(sys.argv) < 2:
        print("用法:python integrate_teammate_data.py <組員資料夾路徑>")
        print("例:python integrate_teammate_data.py ../teammate_data")
        return

    root = sys.argv[1]
    if not os.path.isdir(root):
        print(f"❌ 找不到資料夾:{root}")
        return

    rows = []
    # 統計用
    per_cwe = defaultdict(lambda: defaultdict(int))  # cwe -> lang -> count
    unmapped_cwe = []
    model_counter = Counter()
    skipped_short = 0
    skipped_ext = 0
    seen_fp = set()
    dup = 0

    # 遍歷:第一層資料夾名 = CWE
    for entry in sorted(os.listdir(root)):
        cwe_dir = os.path.join(root, entry)
        if not os.path.isdir(cwe_dir):
            continue
        cwe = _norm_cwe(entry)
        if cwe is None:
            continue

        category = cwe_to_category(cwe)
        # 遞迴掃這個 CWE 資料夾底下所有檔案(含未來的語言子資料夾)
        for dirpath, _, filenames in os.walk(cwe_dir):
            for fn in filenames:
                ext = os.path.splitext(fn)[1].lower()
                lang = EXT_LANG.get(ext)
                if lang is None:
                    skipped_ext += 1
                    continue
                full = os.path.join(dirpath, fn)
                try:
                    with open(full, "r", encoding="utf-8", errors="ignore") as f:
                        code = f.read().strip()
                except Exception:
                    continue
                if len(code) < MIN_CODE_LEN:
                    skipped_short += 1
                    continue

                # 去重
                fp = hashlib.md5(re.sub(r"\s+", "", code).lower().encode()).hexdigest()
                if fp in seen_fp:
                    dup += 1
                    continue
                seen_fp.add(fp)

                model = _detect_model(fn)
                model_counter[model] += 1
                per_cwe[cwe][lang] += 1

                if category is None:
                    # CWE 對不上本專案類別,記錄但仍保留原始資訊
                    unmapped_cwe.append(cwe)
                    continue

                info = get_category(category)
                rows.append({
                    "code": code,
                    "language": lang,
                    "label": info["label"],
                    "category": category,
                    "category_zh": info.get("name_zh", category),
                    "cwe": cwe,
                    "source": f"teammate_{model}",
                })

    # 輸出 CSV
    os.makedirs("dataset", exist_ok=True)
    if rows:
        df = pd.DataFrame(rows)
        df.to_csv(OUT_CSV, index=False, encoding="utf-8")

    # ── 報告 ──
    lines = []
    lines.append("=" * 62)
    lines.append("組員資料整合報告")
    lines.append("=" * 62)
    lines.append(f"\n來源資料夾:{root}")
    lines.append(f"成功轉換:{len(rows)} 筆")
    lines.append(f"去重移除:{dup}　過短跳過:{skipped_short}　非程式檔跳過:{skipped_ext}")

    lines.append(f"\n生成模型分布:")
    for m, c in model_counter.most_common():
        lines.append(f"  {m:<14} {c}")

    lines.append(f"\n各 CWE 資料量(對應本專案類別):")
    lines.append(f"  {'CWE':<10} {'類別':<22} {'label':<6} {'總數':>5}  語言分布")
    lines.append("  " + "-" * 66)
    for cwe in sorted(per_cwe.keys(), key=lambda x: int(re.search(r'\d+', x).group())):
        category = cwe_to_category(cwe)
        info = get_category(category) if category else None
        if info:
            zh = info.get("name_zh", "")
            label = info["label"]
            tag = "" if label < 13 else " ★新類別"
        else:
            zh = "(對不上)"
            label = "-"
            tag = " ⚠️未認領"
        total = sum(per_cwe[cwe].values())
        langs = ", ".join(f"{l}:{n}" for l, n in sorted(per_cwe[cwe].items()))
        lines.append(f"  {cwe:<10} {zh:<22} {str(label):<6} {total:>5}  {langs}{tag}")

    if unmapped_cwe:
        uniq = sorted(set(unmapped_cwe))
        lines.append(f"\n⚠️ 對不上本專案類別的 CWE(資料未納入):{uniq}")

    report = "\n".join(lines)
    with open(REPORT, "w", encoding="utf-8") as f:
        f.write(report)
    print(report)
    print(f"\n✅ 轉換結果:{OUT_CSV}")
    print(f"✅ 報告:{REPORT}")


if __name__ == "__main__":
    main()