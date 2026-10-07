# -*- coding: utf-8 -*-
"""
confusion_analysis.py — 混淆矩陣分析：找出哪些類別互相混淆

用已訓好的 v5 模型跑驗證集，產出：
  1. 完整混淆矩陣
  2. 「誰被誤判成誰」的 TOP 排行（最重要）
  3. 互相混淆的配對（雙向混淆 = 語意重疊的鐵證）

執行：python confusion_analysis.py
"""
import os
import numpy as np
import pandas as pd
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from sklearn.metrics import confusion_matrix

MODEL_DIR = "models/codebert_v5"
VAL_CSV = "dataset/val_18.csv"
REPORT = "dataset/confusion_report.txt"
BATCH = 32

LABEL_NAMES = {
    0:"正常程式碼", 1:"指令注入", 2:"SQL注入", 3:"程式碼執行", 4:"資料外洩",
    5:"後門", 6:"弱加密", 7:"硬編碼密碼", 8:"路徑遊走", 9:"不安全反序列化",
    10:"跨站腳本", 11:"原型污染", 12:"惡意套件", 13:"跨站請求偽造",
    14:"SSRF", 15:"IDOR", 16:"不受限檔案上傳", 17:"權限控制缺陷",
}
N = len(LABEL_NAMES)

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"裝置：{device}")

tok = AutoTokenizer.from_pretrained(MODEL_DIR)
model = AutoModelForSequenceClassification.from_pretrained(MODEL_DIR).to(device)
model.eval()

df = pd.read_csv(VAL_CSV)
df["code"] = df["code"].astype(str).str[:2000]
codes = df["code"].tolist()
y_true = df["label"].astype(int).tolist()

print(f"預測 {len(codes)} 筆...")
y_pred = []
with torch.no_grad():
    for i in range(0, len(codes), BATCH):
        batch = codes[i:i+BATCH]
        enc = tok(batch, max_length=512, padding="max_length",
                  truncation=True, return_tensors="pt").to(device)
        logits = model(**enc).logits
        y_pred.extend(torch.argmax(logits, dim=1).cpu().numpy().tolist())
        if (i // BATCH) % 20 == 0:
            print(f"  {i}/{len(codes)}")

cm = confusion_matrix(y_true, y_pred, labels=list(range(N)))

lines = []
lines.append("=" * 78)
lines.append("混淆矩陣分析（v5, 18類）")
lines.append("=" * 78)

# ── 誰被誤判成誰（TOP 20）──
lines.append("\n【最嚴重的誤判 TOP 20】")
lines.append("  真實類別 → 被誤判成 : 次數（佔該類比例）")
lines.append("  " + "-" * 62)
errs = []
for i in range(N):
    total_i = cm[i].sum()
    if total_i == 0:
        continue
    for j in range(N):
        if i != j and cm[i][j] > 0:
            errs.append((cm[i][j], cm[i][j]/total_i, i, j))
errs.sort(reverse=True)
for cnt, ratio, i, j in errs[:20]:
    lines.append(f"  {LABEL_NAMES[i]:<14} → {LABEL_NAMES[j]:<14} : {cnt:>4} ({ratio:>5.1%})")

# ── 雙向混淆配對（語意重疊鐵證）──
lines.append("\n【雙向混淆配對】（A誤判成B，B也誤判成A → 語意重疊）")
lines.append("  " + "-" * 62)
pairs = []
for i in range(N):
    for j in range(i+1, N):
        both = cm[i][j] + cm[j][i]
        if cm[i][j] > 0 and cm[j][i] > 0 and both >= 20:
            ti, tj = cm[i].sum(), cm[j].sum()
            pairs.append((both, i, j, cm[i][j], cm[j][i], ti, tj))
pairs.sort(reverse=True)
for both, i, j, ij, ji, ti, tj in pairs[:15]:
    lines.append(f"  {LABEL_NAMES[i]:<14} ↔ {LABEL_NAMES[j]:<14} : "
                 f"共 {both:>3} 筆互混  ({LABEL_NAMES[i]}→{LABEL_NAMES[j]}:{ij}, 反向:{ji})")

# ── 每類的錯誤去向 ──
lines.append("\n【各類別的錯誤流向】")
for i in range(N):
    total_i = cm[i].sum()
    if total_i == 0:
        continue
    correct = cm[i][i]
    acc = correct / total_i
    tag = "  ⚠️" if acc < 0.7 else ""
    lines.append(f"\n  {LABEL_NAMES[i]}（正確率 {acc:.1%}）{tag}")
    row = [(cm[i][j], j) for j in range(N) if j != i and cm[i][j] > 0]
    row.sort(reverse=True)
    for cnt, j in row[:3]:
        lines.append(f"      誤判成 {LABEL_NAMES[j]:<14} {cnt:>4} 筆 ({cnt/total_i:.1%})")

report = "\n".join(lines)
open(REPORT, "w", encoding="utf-8").write(report)
print("\n" + report)
print(f"\n✅ 報告：{REPORT}")