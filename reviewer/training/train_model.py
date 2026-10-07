# -*- coding: utf-8 -*-
"""
train_model.py — CodeBERT 18 類分類訓練（v5）

本版變更：
  - 18 類（label 0-17）：原13類 + 新5類（CSRF/SSRF/IDOR/檔案上傳/權限控制缺陷）
  - 讀預切分好的 train_18.csv / val_18.csv（已平衡、防洩漏、stratify）
  - 訓練資料 = 合成 + CVEfixes真實 + 組員資料（多來源混合）
  - 輸出到 codebert_v5

執行（在 reviewer/ 底下）：
  $env:KMP_DUPLICATE_LIB_OK="TRUE"
  python train_model.py
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
OUTPUT_DIR = "models/codebert_v5"
TRAIN_CSV = "dataset/train_18.csv"
VAL_CSV = "dataset/val_18.csv"
NUM_LABELS = 18
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
    15: "不安全的直接物件參考",
    16: "不受限檔案上傳",
    17: "權限控制缺陷",
}

print(f"使用裝置：{DEVICE}")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ── 載入預切分好的資料 ────────────────────────────
print("\n載入訓練/驗證資料...")
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
    tag = " ★新類別" if label >= 13 else ""
    print(f"  {label:2d} {name:<12}：{n:>5} 筆{tag}")

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
print("資料來源：合成 + CVEfixes真實 + 組員生成（多模型混合）\n")
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