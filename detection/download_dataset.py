import kagglehub
import os
import shutil
import random

# 下載資料集
print("開始下載資料集...")
path = kagglehub.dataset_download("alessandrasala79/ai-vs-human-generated-dataset")
print(f"下載完成，資料集位置：{path}")

# 列出下載後的資料夾結構
for root, dirs, files in os.walk(path):
    level = root.replace(path, '').count(os.sep)
    indent = ' ' * 2 * level
    print(f"{indent}{os.path.basename(root)}/")
    if level < 2:
        subindent = ' ' * 2 * (level + 1)
        for file in files[:5]:
            print(f"{subindent}{file}")
        if len(files) > 5:
            print(f"{subindent}... 還有 {len(files)-5} 個檔案")

import pandas as pd

# 讀取 train.csv 看結構
csv_path = os.path.join(path, "train.csv")
df = pd.read_csv(csv_path)
print("\ntrain.csv 前 10 行：")
print(df.head(10))
print(f"\n總共 {len(df)} 筆資料")
print(f"\n欄位名稱：{df.columns.tolist()}")
print(f"\n標籤分布：\n{df.iloc[:, -1].value_counts()}")