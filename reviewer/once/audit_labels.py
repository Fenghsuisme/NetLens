# -*- coding: utf-8 -*-
"""
盤點 dataset 資料夾底下所有 CSV 出現過的 label / category / category_zh，
以及各語言的 semgrep 規則檔裡用到的 CWE 編號。
目的：做標準化對照表前，先看清楚現況全貌。
"""
import os
import glob
import re
from collections import Counter, defaultdict

import pandas as pd

DATASET_DIR = "dataset"
RULES_DIR = "rules"

print("=" * 60)
print("一、資料集標籤盤點")
print("=" * 60)

csv_files = glob.glob(os.path.join(DATASET_DIR, "**", "*.csv"), recursive=True)
if not csv_files:
    print(f"（在 {DATASET_DIR} 底下找不到任何 CSV）")

# 彙整所有 CSV 的 category / label 對應
cat_counter = Counter()
label_to_cats = defaultdict(set)
cat_to_zh = defaultdict(set)

for path in csv_files:
    try:
        df = pd.read_csv(path)
    except Exception as e:
        print(f"  讀取失敗 {path}: {e}")
        continue

    cols = df.columns.tolist()
    print(f"\n檔案：{path}")
    print(f"  筆數：{len(df)}　欄位：{cols}")

    if "category" in df.columns:
        vc = df["category"].value_counts()
        for cat, cnt in vc.items():
            cat_counter[str(cat)] += cnt
        # label ↔ category 對應
        if "label" in df.columns:
            for _, row in df[["label", "category"]].drop_duplicates().iterrows():
                label_to_cats[str(row["label"])].add(str(row["category"]))
        # category ↔ 中文
        if "category_zh" in df.columns:
            for _, row in df[["category", "category_zh"]].drop_duplicates().iterrows():
                cat_to_zh[str(row["category"])].add(str(row["category_zh"]))

print("\n" + "=" * 60)
print("二、所有出現過的 category（含出現次數）")
print("=" * 60)
for cat, cnt in sorted(cat_counter.items(), key=lambda x: -x[1]):
    zh = " / ".join(sorted(cat_to_zh.get(cat, []))) if cat in cat_to_zh else ""
    print(f"  {cat:<28} {cnt:>7}  {zh}")

print("\n" + "=" * 60)
print("三、label → category 對應（檢查同一個 label 是否對到多個 category）")
print("=" * 60)
for label in sorted(label_to_cats.keys()):
    cats = sorted(label_to_cats[label])
    flag = "  ⚠️ 多重對應" if len(cats) > 1 else ""
    print(f"  label {label:>3} → {cats}{flag}")

print("\n" + "=" * 60)
print("四、Semgrep 規則檔用到的 CWE 編號")
print("=" * 60)
for yml in sorted(glob.glob(os.path.join(RULES_DIR, "*.yml"))):
    content = open(yml, encoding="utf-8").read()
    cwes = sorted(set(re.findall(r"CWE-\d+", content)))
    print(f"\n{os.path.basename(yml)}（{len(cwes)} 種 CWE）：")
    print("  " + ", ".join(cwes))

print("\n完成")