# -*- coding: utf-8 -*-
"""
train_model_v7.py — CodeBERT 17 類分類訓練（v7）

相對 v6（17類）的改動：
  - 資料變成 function-level，非 file-level
  - 訓練資料已剝除註解（防止模型讀 "# VULNERABILITY: XXX" 作弊）

執行（在 reviewer/ 底下）：
  $env:KMP_DUPLICATE_LIB_OK="TRUE"
  python train_model_v7.py
"""
import os
import numpy as np
import pandas as pd
import torch
from torch.utils.data import Dataset
from transformers import (
    AutoTokenizer, AutoModelForSequenceClassification,
    TrainingArguments, Trainer,
)
from sklearn.metrics import accuracy_score, f1_score, classification_report

# ── 設定 ──────────────────────────────────────────
MODEL_NAME = "microsoft/codebert-base"
OUTPUT_DIR = "models/codebert_v7_obfuscated"
TRAIN_CSV = "dataset/train_17_v7_obfuscated.csv"
VAL_CSV = "dataset/val_17_v7_obfuscated.csv"
NUM_LABELS = 17
MAX_LENGTH = 512
BATCH_SIZE = 8
EPOCHS = 5
LEARNING_RATE = 2e-5
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

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
    10: "跨站腳本",
    11: "原型污染",
    12: "惡意套件",
    13: "跨站請求偽造",
    14: "伺服器端請求偽造",
    15: "不受限檔案上傳",
    16: "權限控制缺陷",
}

print(f"使用裝置：{DEVICE}")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ── 載入 ──────────────────────────────────────────
print("\n載入訓練/驗證資料（已剝除註解）...")
train_df = pd.read_csv(TRAIN_CSV)
val_df = pd.read_csv(VAL_CSV)

for d in (train_df, val_df):
    d.dropna(subset=["code", "label"], inplace=True)
    d["code"] = d["code"].astype(str).str[:2000]
    d["label"] = d["label"].astype(int)

print(f"  訓練集：{len(train_df)} 筆")
print(f"  驗證集：{len(val_df)} 筆")
print("\n訓練集各類別數量：")
for label, name in LABEL_NAMES.items():
    n = (train_df["label"] == label).sum()
    tag = " ★含原IDOR" if label == 16 else ""
    print(f"  {label:2d} {name:<12}：{n:>5} 筆{tag}")

invalid_labels = set(train_df["label"].unique()) - set(LABEL_NAMES.keys())
if invalid_labels:
    raise ValueError(f"❌ 訓練集出現未知 label：{invalid_labels}")

invalid_labels = set(val_df["label"].unique()) - set(LABEL_NAMES.keys())
if invalid_labels:
    raise ValueError(f"❌ 驗證集出現未知 label：{invalid_labels}")

# ── Tokenizer ─────────────────────────────────────
print(f"\n載入 {MODEL_NAME}...")
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)


class CodeDataset(Dataset):
    def __init__(self, df, tokenizer, max_length):
        self.codes = df["code"].tolist()
        self.labels = df["label"].tolist()
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __len__(self):
        return len(self.codes)

    def __getitem__(self, idx):
        enc = self.tokenizer(
            self.codes[idx], max_length=self.max_length,
            padding="max_length", truncation=True, return_tensors="pt",
        )
        return {
            "input_ids": enc["input_ids"].squeeze(),
            "attention_mask": enc["attention_mask"].squeeze(),
            "labels": torch.tensor(self.labels[idx], dtype=torch.long),
        }


train_dataset = CodeDataset(train_df, tokenizer, MAX_LENGTH)
val_dataset = CodeDataset(val_df, tokenizer, MAX_LENGTH)

# ── 模型 ──────────────────────────────────────────
print(f"載入 CodeBERT 模型（{NUM_LABELS} 類別）...")
model = AutoModelForSequenceClassification.from_pretrained(
    MODEL_NAME, num_labels=NUM_LABELS,
    ignore_mismatched_sizes=True, use_safetensors=True,
).to(DEVICE)


def compute_metrics(eval_pred):
    logits, labels = eval_pred
    preds = np.argmax(logits, axis=-1)
    return {
        "accuracy": accuracy_score(labels, preds),
        "f1": f1_score(labels, preds, average="weighted"),
    }


training_args = TrainingArguments(
    output_dir=OUTPUT_DIR,
    num_train_epochs=EPOCHS,
    per_device_train_batch_size=BATCH_SIZE,
    per_device_eval_batch_size=BATCH_SIZE,
    learning_rate=LEARNING_RATE,
    warmup_steps=200,
    weight_decay=0.01,
    eval_strategy="epoch",
    save_strategy="epoch",
    load_best_model_at_end=True,
    metric_for_best_model="accuracy",
    logging_steps=100,
    report_to="none",
    save_total_limit=2,
)

trainer = Trainer(
    model=model, args=training_args,
    train_dataset=train_dataset, eval_dataset=val_dataset,
    compute_metrics=compute_metrics,
)

print(f"\n開始訓練（{NUM_LABELS} 類別，{EPOCHS} epoch）...")
print("本版特點：已剝除註解，模型必須從程式碼結構學習漏洞\n")
trainer.train()

print("\n最終評估：")
results = trainer.evaluate()
print(f"  驗證準確率：{results['eval_accuracy']:.4f}")
print(f"  驗證 F1：{results['eval_f1']:.4f}")

model.save_pretrained(OUTPUT_DIR)
tokenizer.save_pretrained(OUTPUT_DIR)
print(f"\n模型已儲存至：{OUTPUT_DIR}")

print("\n詳細分類報告：")
val_preds = trainer.predict(val_dataset)
pred_labels = np.argmax(val_preds.predictions, axis=-1)
print(classification_report(
    val_df["label"].tolist(), pred_labels,
    target_names=[LABEL_NAMES[i] for i in range(NUM_LABELS)],
    digits=3,
))