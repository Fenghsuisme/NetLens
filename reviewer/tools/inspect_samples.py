# -*- coding: utf-8 -*-
"""
inspect_samples.py — 抽樣檢視混淆類別的實際程式碼

把互相混淆的類別各抽幾筆印出來，肉眼判斷：
  這幾類的程式碼是否真的長得很像？

執行：python inspect_samples.py
"""
import sys, os
import pandas as pd

# 已移入子目錄，需往上一層才能 import 到 reviewer/ 下的模組
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.config_loader import label_to_category, get_category

TRAIN_CSV = "dataset/train_18.csv"
OUT = "dataset/samples_inspect.txt"

# 要檢視的混淆類別
TARGETS = [
    (15, "IDOR"),
    (17, "權限控制缺陷"),
    (14, "SSRF"),
    (16, "不受限檔案上傳"),
    (4,  "資料外洩"),
]
N_PER_CLASS = 3
LANG = "python"   # 固定同語言比較，才看得出差異

df = pd.read_csv(TRAIN_CSV)
df = df[df["language"] == LANG]

lines = []
lines.append("=" * 78)
lines.append(f"混淆類別的實際程式碼抽樣（語言：{LANG}）")
lines.append("目的：判斷這幾類的程式碼是否真的長得很像")
lines.append("=" * 78)

for label, name in TARGETS:
    sub = df[df["label"] == label]
    if len(sub) == 0:
        lines.append(f"\n【{name}】無 {LANG} 樣本")
        continue
    sample = sub.sample(n=min(N_PER_CLASS, len(sub)), random_state=7)
    lines.append(f"\n\n{'='*78}")
    lines.append(f"【label {label} — {name}】（共 {len(sub)} 筆 {LANG}）")
    lines.append("=" * 78)
    for i, (_, row) in enumerate(sample.iterrows(), 1):
        code = str(row["code"])[:700]
        lines.append(f"\n--- 樣本 {i}（來源：{row['source']}）---")
        lines.append(code)
        lines.append("")

report = "\n".join(lines)
open(OUT, "w", encoding="utf-8").write(report)
print(report[:3000])
print(f"\n...（完整內容已存至 {OUT}）")