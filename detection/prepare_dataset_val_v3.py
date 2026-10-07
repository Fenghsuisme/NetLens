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
# Kaggle dataset
# =========================
kaggle_path = kagglehub.dataset_download(
    "alessandrasala79/ai-vs-human-generated-dataset"
)

# =========================
# StyleGAN dataset
# =========================
stylegan_path = kagglehub.dataset_download(
    "xhlulu/140k-real-and-fake-faces"
)

stylegan_base = os.path.join(
    stylegan_path,
    "real_vs_fake",
    "real-vs-fake"
)

# =========================
# COCO dataset
# =========================
COCO_PATH = r"C:\Users\user\fiftyone\coco-2017\train\data"

# =========================
# ThisPerson dataset
# =========================
THISPERSON_DIR = "raw_datasets/fake/thisperson"

# =========================
# output
# =========================
BASE_DIR = "dataset_v3/val"

VAL_REAL = os.path.join(BASE_DIR, "real")
VAL_FAKE = os.path.join(BASE_DIR, "fake")

# =========================
# clean
# =========================
if os.path.exists(BASE_DIR):
    print("🧹 清除舊 val 資料...")
    shutil.rmtree(BASE_DIR)

os.makedirs(VAL_REAL, exist_ok=True)
os.makedirs(VAL_FAKE, exist_ok=True)

# =========================
# utils
# =========================
def safe_name(path):
    return os.path.basename(path.replace("\\", "/"))

def get_images(folder, limit=None):
    exts = (".jpg", ".jpeg", ".png", ".webp")

    files = [
        os.path.join(folder, f)
        for f in os.listdir(folder)
        if f.lower().endswith(exts)
    ]

    random.shuffle(files)
    return files[:limit] if limit else files


def copy_files(files, dst, prefix):
    for i, f in enumerate(tqdm(files, desc=prefix)):
        dst_path = os.path.join(
            dst,
            f"{prefix}_{i}_{os.path.basename(f)}"
        )
        shutil.copy2(f, dst_path)

# =========================
# config
# =========================
VAL_CFG = {
    "coco_real": 10000,
    "kaggle_real": 6000,
    "stylegan_real": 4000,

    "kaggle_fake": 9000,
    "stylegan_fake": 6000,
    "thisperson_fake": 5000,
}

# =========================
# 1️⃣ Kaggle
# =========================
print("\n【Kaggle VAL】")

csv_path = os.path.join(kaggle_path, "train.csv")
df = pd.read_csv(csv_path)

real_df = df[df["label"] == 0].head(VAL_CFG["kaggle_real"])
fake_df = df[df["label"] == 1].head(VAL_CFG["kaggle_fake"])

for i, (_, row) in enumerate(tqdm(real_df.iterrows(), total=len(real_df))):
    src = os.path.join(kaggle_path, row["file_name"])
    filename = safe_name(row["file_name"])

    dst = os.path.join(
        VAL_REAL,
        f"kaggle_real_{i}_{filename}"
    )

    shutil.copy2(src, dst)

for i, (_, row) in enumerate(tqdm(fake_df.iterrows(), total=len(fake_df))):
    src = os.path.join(kaggle_path, row["file_name"])
    filename = safe_name(row["file_name"])

    dst = os.path.join(
        VAL_FAKE,
        f"kaggle_fake_{i}_{filename}"
    )

    shutil.copy2(src, dst)

# =========================
# 2️⃣ StyleGAN
# =========================
print("\n【StyleGAN VAL】")

sg_real = get_images(
    os.path.join(stylegan_base, "train", "real"),
    VAL_CFG["stylegan_real"]
)

sg_fake = get_images(
    os.path.join(stylegan_base, "train", "fake"),
    VAL_CFG["stylegan_fake"]
)

copy_files(sg_real, VAL_REAL, "stylegan_real")
copy_files(sg_fake, VAL_FAKE, "stylegan_fake")

# =========================
# 3️⃣ COCO
# =========================
print("\n【COCO VAL】")

coco = get_images(COCO_PATH, VAL_CFG["coco_real"])
copy_files(coco, VAL_REAL, "coco")

# =========================
# 4️⃣ ThisPerson
# =========================
print("\n【ThisPerson VAL】")

tp = get_images(THISPERSON_DIR, VAL_CFG["thisperson_fake"])
copy_files(tp, VAL_FAKE, "thisperson")

# =========================
# summary
# =========================
print("\n✅ VAL DONE")

print("REAL:", len(os.listdir(VAL_REAL)))
print("FAKE:", len(os.listdir(VAL_FAKE)))

print(
    "TOTAL:",
    len(os.listdir(VAL_REAL)) + len(os.listdir(VAL_FAKE))
)