import pandas as pd
from datasets import load_dataset
import os

print("載入 CodeSearchNet 正常程式碼...")

all_clean = []

# 四種語言各取 2000 筆
LANGUAGES = {
    "python": 500,
    "javascript": 500,
    "java": 500,
    "php": 500,
}

for lang, count in LANGUAGES.items():
    print(f"  ▸ 載入 {lang}...")
    try:
        ds = load_dataset(
            "code-search-net/code_search_net",
            lang,
            split="train",
        )
        codes = [
            item["whole_func_string"]
            for item in ds.select(range(min(count * 3, len(ds))))
            if item["whole_func_string"]
            and len(item["whole_func_string"]) > 100
            and len(item["whole_func_string"]) < 2000
        ][:count]

        for code in codes:
            all_clean.append({
                "code": code,
                "language": lang,
                "label": 0,
                "category": "clean",
                "category_zh": "正常程式碼",
            })
        print(f"    ✓ 取得 {len(codes)} 筆")
    except Exception as e:
        print(f"    ✗ 失敗：{e}")

# 合併原始資料集
print("\n合併資料集...")
original_df = pd.read_csv("reviewer/dataset/dataset_raw_v1.csv")

# 移除原始資料集裡的正常程式碼（用 CodeSearchNet 的取代）
original_df = original_df[original_df["label"] != 0]
print(f"  ▸ 原始有問題程式碼：{len(original_df)} 筆")

clean_df = pd.DataFrame(all_clean)
print(f"  ▸ CodeSearchNet 正常程式碼：{len(clean_df)} 筆")

# 合併
combined_df = pd.concat([original_df, clean_df], ignore_index=True)
combined_df = combined_df.sample(frac=1, random_state=42).reset_index(drop=True)

print(f"\n合併後總筆數：{len(combined_df)}")
print("\n各類別數量：")
for label in sorted(combined_df["label"].unique()):
    name = combined_df[combined_df["label"] == label]["category_zh"].iloc[0]
    count = (combined_df["label"] == label).sum()
    print(f"  {label:2d} {name}：{count} 筆")

# 儲存
output_file = "reviewer/dataset/dataset_combined_v1.csv"
combined_df.to_csv(output_file, index=False, encoding="utf-8")
print(f"\n已儲存至：{output_file}")