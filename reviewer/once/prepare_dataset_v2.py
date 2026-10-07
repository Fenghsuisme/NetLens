import pandas as pd
from datasets import load_dataset
import os

print("載入 CodeSearchNet 正常程式碼...")

all_clean = []

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
            and len(item["whole_func_string"]) > 200
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

# 載入 v2 資料集
print("\n載入 v2 資料集...")
v2_df = pd.read_csv("reviewer/dataset/v2/dataset_raw.csv")
print(f"  ▸ v2 資料：{len(v2_df)} 筆")

# v2 已經有正常程式碼了（796筆），但我們要替換成 CodeSearchNet 的更真實正常程式碼
v2_problems = v2_df[v2_df["label"] != 0]
print(f"  ▸ v2 有問題程式碼：{len(v2_problems)} 筆")

# 載入 v1.1（包含 Gemini/GPT 真實樣本）
print("\n載入 v1.1 資料集（含 Gemini/GPT 真實樣本）...")
v1_df = pd.read_csv("reviewer/dataset/v1/dataset_combined_v1.csv")
# 只取 Gemini/GPT 來源（這些 code 比較長，且不在 codellama 生成範圍內）
# 簡單用長度區分：v1原始codellama樣本通常較短
v1_long = v1_df[v1_df["code"].str.len() > 400]
print(f"  ▸ v1.1 中長度>400的樣本：{len(v1_long)} 筆")

# 合併：v2有問題程式碼 + CodeSearchNet正常程式碼 + v1.1長樣本
clean_df = pd.DataFrame(all_clean)
combined_df = pd.concat([v2_problems, clean_df, v1_long], ignore_index=True)

# 去重複
before = len(combined_df)
combined_df = combined_df.drop_duplicates(subset=["code"])
after = len(combined_df)
print(f"\n移除重複：{before - after} 筆")

# 打亂
combined_df = combined_df.sample(frac=1, random_state=42).reset_index(drop=True)

print(f"\n合併後總筆數：{len(combined_df)}")
print("\n各類別數量：")
for label in sorted(combined_df["label"].unique()):
    name = combined_df[combined_df["label"] == label]["category_zh"].iloc[0]
    count = (combined_df["label"] == label).sum()
    print(f"  {label:2d} {name}：{count} 筆")

# 儲存
output_file = "reviewer/dataset/dataset_v3.csv"
combined_df.to_csv(output_file, index=False, encoding="utf-8")
print(f"\n已儲存至：{output_file}")