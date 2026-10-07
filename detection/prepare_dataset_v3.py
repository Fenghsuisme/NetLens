import os
import shutil
import pandas as pd
import kagglehub
import random
from tqdm import tqdm

# ─────────────────────────────
# Kaggle dataset
# ─────────────────────────────
kaggle_path = kagglehub.dataset_download(
    "alessandrasala79/ai-vs-human-generated-dataset"
)

# ─────────────────────────────
# StyleGAN dataset
# ─────────────────────────────
stylegan_path = kagglehub.dataset_download(
    "xhlulu/140k-real-and-fake-faces"
)

stylegan_base = os.path.join(
    stylegan_path,
    "real_vs_fake",
    "real-vs-fake"
)

# ─────────────────────────────
# COCO dataset (FiftyOne cache)
# ─────────────────────────────
COCO_PATH = r"C:\Users\user\fiftyone\coco-2017\train\data"

# ─────────────────────────────
# 輸出資料夾（升級成 v3）
# ─────────────────────────────
BASE_DIR = "detection/dataset_v3"

DIRS = {
    "train/real": os.path.join(BASE_DIR, "train", "real"),
    "train/fake": os.path.join(BASE_DIR, "train", "fake"),
    "val/real":   os.path.join(BASE_DIR, "val", "real"),
    "val/fake":   os.path.join(BASE_DIR, "val", "fake"),
}

# ─────────────────────────────
# 清空舊資料
# ─────────────────────────────
if os.path.exists(BASE_DIR):
    print("🧹 清除舊資料集...")
    shutil.rmtree(BASE_DIR)

for d in DIRS.values():
    os.makedirs(d, exist_ok=True)

# ─────────────────────────────
# 參數
# ─────────────────────────────
PER_CLASS = 20000
TRAIN_RATIO = 0.8

COCO_LIMIT = 40000

IMG_EXT = (".jpg", ".jpeg", ".png", ".webp")

# ─────────────────────────────
# utils
# ─────────────────────────────
def split_and_copy(files, dst_train, dst_val, prefix):
    train_count = int(len(files) * TRAIN_RATIO)

    for i, src in enumerate(tqdm(files, desc=prefix)):
        dst_dir = dst_train if i < train_count else dst_val
        dst = os.path.join(dst_dir, f"{prefix}_{os.path.basename(src)}")
        shutil.copy2(src, dst)


# ─────────────────────────────
# 1️⃣ Kaggle dataset
# ─────────────────────────────
print("\n【Kaggle 資料集】")

csv_path = os.path.join(kaggle_path, "train.csv")
df = pd.read_csv(csv_path)

real_df = df[df["label"] == 0].head(PER_CLASS)
fake_df = df[df["label"] == 1].head(PER_CLASS)

def copy_kaggle(subset_df, train_dir, val_dir, desc):
    total = len(subset_df)
    train_count = int(total * TRAIN_RATIO)

    for i, (_, row) in enumerate(tqdm(subset_df.iterrows(), total=total, desc=desc)):
        src = os.path.join(kaggle_path, row["file_name"])
        dst_dir = train_dir if i < train_count else val_dir
        dst = os.path.join(dst_dir, os.path.basename(row["file_name"]))
        shutil.copy2(src, dst)

copy_kaggle(real_df, DIRS["train/real"], DIRS["val/real"], "Kaggle REAL")
copy_kaggle(fake_df, DIRS["train/fake"], DIRS["val/fake"], "Kaggle FAKE")


# ─────────────────────────────
# 2️⃣ StyleGAN dataset
# ─────────────────────────────
print("\n【StyleGAN 資料集】")

sg_real_dir = os.path.join(stylegan_base, "train", "real")
sg_fake_dir = os.path.join(stylegan_base, "train", "fake")

sg_real_files = [os.path.join(sg_real_dir, f) for f in os.listdir(sg_real_dir)[:PER_CLASS]]
sg_fake_files = [os.path.join(sg_fake_dir, f) for f in os.listdir(sg_fake_dir)[:PER_CLASS]]

split_and_copy(sg_real_files, DIRS["train/real"], DIRS["val/real"], "sg_real")
split_and_copy(sg_fake_files, DIRS["train/fake"], DIRS["val/fake"], "sg_fake")


# ─────────────────────────────
# 3️⃣ COCO dataset (REAL)
# ─────────────────────────────
print("\n【COCO REAL 資料集】")

all_imgs = [
    os.path.join(COCO_PATH, f)
    for f in os.listdir(COCO_PATH)
    if f.lower().endswith(IMG_EXT)
]

print(f"COCO total available: {len(all_imgs)}")

selected_coco = random.sample(all_imgs, min(COCO_LIMIT, len(all_imgs)))

split_and_copy(selected_coco, DIRS["train/real"], DIRS["val/real"], "coco")


# ─────────────────────────────
# 📊 統計
# ─────────────────────────────
print("\n【資料集統計】")

for name, d in DIRS.items():
    print(f"{name}: {len(os.listdir(d))} 張")

total_train = len(os.listdir(DIRS["train/real"])) + len(os.listdir(DIRS["train/fake"]))
total_val = len(os.listdir(DIRS["val/real"])) + len(os.listdir(DIRS["val/fake"]))

print(f"\n訓練集總計：{total_train}")
print(f"驗證集總計：{total_val}")
print("\n✅ Dataset v3 完成（已整合 COCO + Kaggle + StyleGAN）")