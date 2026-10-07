import os
import shutil
from tqdm import tqdm
import fiftyone.zoo as foz

# ========================
# CONFIG
# ========================
OUTPUT_DIR = "raw_datasets/real/coco"
MAX_SAMPLES = 100000   # 🔥 改成 10萬
SPLIT = "train"

# ========================
# CREATE OUTPUT DIR
# ========================
os.makedirs(OUTPUT_DIR, exist_ok=True)

print("🚀 COCO dataset downloading...")

# ========================
# LOAD COCO
# ========================
dataset = foz.load_zoo_dataset(
    "coco-2017",
    split=SPLIT,
    max_samples=MAX_SAMPLES,
    shuffle=True   # 🔥 避免固定順序
)

print(f"📦 COCO loaded: {len(dataset)} images")

# ========================
# EXPORT
# ========================
success = 0
failed = 0

for i, sample in enumerate(tqdm(dataset, desc="Exporting COCO")):
    try:
        src = sample.filepath

        # skip invalid files
        if not os.path.exists(src):
            failed += 1
            continue

        dst = os.path.join(OUTPUT_DIR, f"coco_{success:06d}.jpg")

        shutil.copy2(src, dst)
        success += 1

    except Exception as e:
        failed += 1
        print(f"❌ Error: {e}")

    # progress log
    if i % 5000 == 0:
        print(f"✔ processed={i}, success={success}, failed={failed}")

print("\n✅ DONE")
print(f"📁 Saved to: {OUTPUT_DIR}")
print(f"✔ Success: {success}")
print(f"❌ Failed: {failed}")