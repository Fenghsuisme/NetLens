import kagglehub
import os
import shutil
import pandas as pd
from tqdm import tqdm

# 下載資料集
print("開始下載 140k Real and Fake Faces...")
path = kagglehub.dataset_download("xhlulu/140k-real-and-fake-faces")
print(f"下載完成，位置：{path}")

# 看一下結構
for root, dirs, files in os.walk(path):
    level = root.replace(path, '').count(os.sep)
    indent = ' ' * 2 * level
    print(f"{indent}{os.path.basename(root)}/")
    if level < 2:
        subindent = ' ' * 2 * (level + 1)
        for file in files[:3]:
            print(f"{subindent}{file}")
        if len(files) > 3:
            print(f"{subindent}... 還有 {len(files)-3} 個檔案")

base = os.path.join(path, "real_vs_fake", "real-vs-fake")
for split in ["train", "valid", "test"]:
    for label in ["real", "fake"]:
        folder = os.path.join(base, split, label)
        count = len(os.listdir(folder))
        print(f"{split}/{label}: {count} 張")