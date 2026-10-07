# -*- coding: utf-8 -*-
"""
eval_v6.py — 評估已訓好的 v6 模型（17類）

用途：訓練視窗關掉後，重新取得完整評估結果。
不需重訓，直接載入 models/codebert_v6 跑驗證集。

產出：
  1. 訓練歷程（從 checkpoint 的 trainer_state.json 讀取，若存在）
  2. 整體準確率 / F1
  3. 詳細分類報告（每類 precision/recall/f1）
  4. 混淆分析（誰被誤判成誰、雙向混淆配對）

執行：python eval_v6.py
"""
import os
import json
import glob

import numpy as np
import pandas as pd
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from sklearn.metrics import (
    accuracy_score, f1_score, classification_report, confusion_matrix
)

MODEL_DIR = "models/codebert_v6"
VAL_CSV = "dataset/val_17.csv"
REPORT = "dataset/v6_eval_report.txt"
BATCH = 32

LABEL_NAMES = {
    0: "正常程式碼", 1: "指令注入", 2: "SQL 注入", 3: "程式碼執行",
    4: "資料外洩", 5: "後門", 6: "弱加密", 7: "硬編碼密碼",
    8: "路徑遊走", 9: "不安全反序列化", 10: "跨站腳本", 11: "原型污染",
    12: "惡意套件", 13: "跨站請求偽造", 14: "SSRF",
    15: "不受限檔案上傳", 16: "權限控制缺陷",
}
N = len(LABEL_NAMES)

lines = []


def log(s=""):
    print(s)
    lines.append(s)


# ── 1. 讀訓練歷程 ──────────────────────────────
log("=" * 74)
log("v6 模型評估報告（17 類，已剝除註解）")
log("=" * 74)

log("\n【訓練歷程】")
states = sorted(glob.glob(os.path.join(MODEL_DIR, "checkpoint-*", "trainer_state.json")))
if states:
    with open(states[-1], encoding="utf-8") as f:
        st = json.load(f)
    log(f"  （讀自 {states[-1]}）")
    log(f"  {'epoch':<8} {'eval_loss':<12} {'accuracy':<12} {'f1':<12}")
    log("  " + "-" * 44)
    for rec in st.get("log_history", []):
        if "eval_accuracy" in rec:
            log(f"  {rec.get('epoch', 0):<8.0f} "
                f"{rec.get('eval_loss', 0):<12.4f} "
                f"{rec.get('eval_accuracy', 0):<12.4f} "
                f"{rec.get('eval_f1', 0):<12.4f}")
    best = st.get("best_metric")
    if best:
        log(f"\n  最佳 accuracy：{best:.4f}")
else:
    log("  （找不到 checkpoint，略過訓練歷程）")

# ── 2. 重新評估 ────────────────────────────────
if not os.path.exists(MODEL_DIR):
    log(f"\n❌ 找不到模型：{MODEL_DIR}")
    raise SystemExit

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
log(f"\n【重新評估】裝置：{device}")

tok = AutoTokenizer.from_pretrained(MODEL_DIR)
model = AutoModelForSequenceClassification.from_pretrained(MODEL_DIR).to(device)
model.eval()

df = pd.read_csv(VAL_CSV)
df = df.dropna(subset=["code", "label"])
df["code"] = df["code"].astype(str).str[:2000]
codes = df["code"].tolist()
y_true = df["label"].astype(int).tolist()

log(f"  驗證集：{len(codes)} 筆")
y_pred = []
with torch.no_grad():
    for i in range(0, len(codes), BATCH):
        enc = tok(codes[i:i + BATCH], max_length=512, padding="max_length",
                  truncation=True, return_tensors="pt").to(device)
        logits = model(**enc).logits
        y_pred.extend(torch.argmax(logits, dim=1).cpu().numpy().tolist())
        if (i // BATCH) % 30 == 0:
            print(f"    {i}/{len(codes)}")

acc = accuracy_score(y_true, y_pred)
f1 = f1_score(y_true, y_pred, average="weighted")
log(f"\n  驗證準確率：{acc:.4f}")
log(f"  驗證 F1：{f1:.4f}")

# ── 3. 分類報告 ────────────────────────────────
log("\n【詳細分類報告】")
rep = classification_report(
    y_true, y_pred, labels=list(range(N)),
    target_names=[LABEL_NAMES[i] for i in range(N)],
    digits=3, zero_division=0,
)
log(rep)

# ── 4. 混淆分析 ────────────────────────────────
cm = confusion_matrix(y_true, y_pred, labels=list(range(N)))

log("\n【最嚴重的誤判 TOP 15】")
log("  真實類別 → 被誤判成 : 次數（佔該類比例）")
log("  " + "-" * 60)
errs = []
for i in range(N):
    tot = cm[i].sum()
    if tot == 0:
        continue
    for j in range(N):
        if i != j and cm[i][j] > 0:
            errs.append((cm[i][j], cm[i][j] / tot, i, j))
errs.sort(reverse=True)
for cnt, ratio, i, j in errs[:15]:
    log(f"  {LABEL_NAMES[i]:<14} → {LABEL_NAMES[j]:<14} : {cnt:>4} ({ratio:>5.1%})")

log("\n【雙向混淆配對】（語意重疊指標）")
log("  " + "-" * 60)
pairs = []
for i in range(N):
    for j in range(i + 1, N):
        both = cm[i][j] + cm[j][i]
        if cm[i][j] > 0 and cm[j][i] > 0 and both >= 20:
            pairs.append((both, i, j, cm[i][j], cm[j][i]))
pairs.sort(reverse=True)
if pairs:
    for both, i, j, ij, ji in pairs[:12]:
        log(f"  {LABEL_NAMES[i]:<14} ↔ {LABEL_NAMES[j]:<14} : 共 {both:>3} 筆 "
            f"({ij} / {ji})")
else:
    log("  （無明顯雙向混淆）")

log("\n【各類別正確率】")
for i in range(N):
    tot = cm[i].sum()
    if tot == 0:
        continue
    a = cm[i][i] / tot
    tag = "  ⚠️" if a < 0.7 else ("  ✓" if a >= 0.9 else "")
    log(f"  {LABEL_NAMES[i]:<14} {a:>6.1%}  (n={tot}){tag}")

with open(REPORT, "w", encoding="utf-8") as f:
    f.write("\n".join(lines))
print(f"\n✅ 報告已存：{REPORT}")