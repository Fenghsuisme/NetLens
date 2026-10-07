import os
import shutil
import pandas as pd
import kagglehub
import random
from tqdm import tqdm

# =========================
# seed
# =========================
random.seed(42)

# =========================
# BASE DIR (ONLY TRAIN OUTPUT)
# =========================
BASE_DIR = "dataset_v3/train"

TRAIN_REAL = os.path.join(BASE_DIR, "real")
TRAIN_FAKE = os.path.join(BASE_DIR, "fake")

# clean
if os.path.exists(BASE_DIR):
    print("🧹 清除舊 train 資料...")
    shutil.rmtree(BASE_DIR)

os.makedirs(TRAIN_REAL, exist_ok=True)
os.makedirs(TRAIN_FAKE, exist_ok=True)

# =========================
# datasets
# =========================
kaggle_path = kagglehub.dataset_download(
    "alessandrasala79/ai-vs-human-generated-dataset"
)

stylegan_path = kagglehub.dataset_download(
    "xhlulu/140k-real-and-fake-faces"
)

stylegan_base = os.path.join(
    stylegan_path,
    "real_vs_fake",
    "real-vs-fake"
)

COCO_PATH = r"C:\Users\user\fiftyone\coco-2017\train\data"

THISPERSON_DIR = "raw_datasets/fake/thisperson"

# =========================
# utils
# =========================
def get_images(folder, limit=None):
    exts = (".jpg", ".jpeg", ".png", ".webp")

    files = [
        os.path.join(folder, f)
        for f in os.listdir(folder)
        if f.lower().endswith(exts)
    ]

    if limit and len(files) > limit:
        files = random.sample(files, limit)

    return files


def copy_files(files, dst, prefix):
    for i, f in enumerate(tqdm(files, desc=prefix)):
        dst_path = os.path.join(
            dst,
            f"{prefix}_{i}_{os.path.basename(f)}"
        )
        shutil.copy2(f, dst_path)


def sample_kaggle(df, limit):
    return df.sample(n=limit) if len(df) > limit else df

# =========================
# config
# =========================
TRAIN_CFG = {
    "coco_real": 40000,
    "kaggle_real": 25000,
    "stylegan_real": 15000,

    "kaggle_fake": 35000,
    "stylegan_fake": 25000,
    "thisperson_fake": 20000,
}

# =========================
# 1️⃣ Kaggle
# =========================
print("\n【Kaggle TRAIN】")

csv_path = os.path.join(kaggle_path, "train.csv")
df = pd.read_csv(csv_path)

real_df = sample_kaggle(df[df["label"] == 0], TRAIN_CFG["kaggle_real"])
fake_df = sample_kaggle(df[df["label"] == 1], TRAIN_CFG["kaggle_fake"])

for i, (_, row) in enumerate(tqdm(real_df.iterrows(), total=len(real_df))):
    src = os.path.join(kaggle_path, row["file_name"])
    dst = os.path.join(TRAIN_REAL, f"kaggle_real_{i}_{os.path.basename(src)}")
    shutil.copy2(src, dst)

for i, (_, row) in enumerate(tqdm(fake_df.iterrows(), total=len(fake_df))):
    src = os.path.join(kaggle_path, row["file_name"])
    dst = os.path.join(TRAIN_FAKE, f"kaggle_fake_{i}_{os.path.basename(src)}")
    shutil.copy2(src, dst)

# =========================
# 2️⃣ StyleGAN
# =========================
print("\n【StyleGAN TRAIN】")

sg_real = get_images(
    os.path.join(stylegan_base, "train", "real"),
    TRAIN_CFG["stylegan_real"]
)

sg_fake = get_images(
    os.path.join(stylegan_base, "train", "fake"),
    TRAIN_CFG["stylegan_fake"]
)

copy_files(sg_real, TRAIN_REAL, "stylegan_real")
copy_files(sg_fake, TRAIN_FAKE, "stylegan_fake")

# =========================
# 3️⃣ COCO
# =========================
print("\n【COCO TRAIN】")

coco = get_images(COCO_PATH, TRAIN_CFG["coco_real"])
copy_files(coco, TRAIN_REAL, "coco")

# =========================
# 4️⃣ ThisPerson (FAKE ONLY)
# =========================
print("\n【ThisPerson TRAIN】")

tp = get_images(THISPERSON_DIR, TRAIN_CFG["thisperson_fake"])
copy_files(tp, TRAIN_FAKE, "thisperson")

# =========================
# summary
# =========================
print("\n✅ TRAIN DONE")
print("REAL:", len(os.listdir(TRAIN_REAL)))
print("FAKE:", len(os.listdir(TRAIN_FAKE)))