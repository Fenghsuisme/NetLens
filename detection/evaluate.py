import torch
import timm
import numpy as np
from PIL import Image
from torchvision import transforms
import os

# ─────────────────────────────
# CONFIG
# ─────────────────────────────

# 對應 train.py 存的模型
MODEL_PATH = "detection/models/netlens_detector_v7.pth"

# 對應目前使用的 dataset_v3
DATASET_DIR = "detection/datasets/dataset_v3"

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

print("使用裝置：", DEVICE)

# ─────────────────────────────
# LABEL MAPPING（非常重要）
# ─────────────────────────────
#
# ImageFolder 會依照資料夾名稱排序：
#
# fake -> 0
# real -> 1
#
# 所以：
#
# probs[0][0] = fake 的機率
# probs[0][1] = real 的機率
#
# 預測：
#
# predicted == 0 -> fake
# predicted == 1 -> real
#
# ─────────────────────────────

CLASS_MAPPING = {
    0: "fake",
    1: "real"
}

print("class mapping:", CLASS_MAPPING)

# ─────────────────────────────
# MODEL
# ─────────────────────────────

model = timm.create_model(
    "efficientnet_b4",
    pretrained=False,
    in_chans=5,
    num_classes=2
)

model.load_state_dict(
    torch.load(
        MODEL_PATH,
        map_location=DEVICE,
        weights_only=True
    )
)

model = model.to(DEVICE)
model.eval()

print("模型載入完成")

# ─────────────────────────────
# TRANSFORM
# ─────────────────────────────

transform = transforms.Compose([
    transforms.Resize((380, 380)),
    transforms.ToTensor(),
    transforms.Normalize(
        mean=[0.485, 0.456, 0.406],
        std=[0.229, 0.224, 0.225]
    )
])

# ─────────────────────────────
# 單張圖片預測
# ─────────────────────────────

def predict(image_path):
    try:
        image = Image.open(image_path).convert("RGB")
    except Exception:
        print(f"跳過壞圖：{image_path}")
        return None

    tensor = transform(image).unsqueeze(0).to(DEVICE)

    with torch.no_grad():
        output = model(tensor)
        probs = torch.softmax(output, dim=1)

        fake_score = probs[0][0].item()
        real_score = probs[0][1].item()
        predicted = output.argmax(1).item()

    return {
        "fake_score": fake_score,
        "real_score": real_score,
        "predicted": predicted
    }


# ─────────────────────────────
# 評估整個資料夾
# ─────────────────────────────

def evaluate_folder(folder, true_label, label_name):
    """
    true_label:

    fake = 0
    real = 1
    """

    if not os.path.exists(folder):
        print(f"\n⚠ 找不到資料夾：{folder}")
        return None

    files = [
        f for f in os.listdir(folder)
        if f.lower().endswith(
            (".jpg", ".jpeg", ".png", ".webp")
        )
    ]

    if not files:
        print(f"\n⚠ 資料夾是空的：{folder}")
        return None

    correct = 0
    fake_scores = []
    skipped = 0

    for fname in files:
        path = os.path.join(folder, fname)

        result = predict(path)

        if result is None:
            skipped += 1
            continue

        predicted = result["predicted"]
        fake_score = result["fake_score"]

        fake_scores.append(fake_score)

        if predicted == true_label:
            correct += 1

    valid_total = len(files) - skipped

    if valid_total == 0:
        print(f"\n⚠ 全部圖片都損毀：{folder}")
        return None

    acc = correct / valid_total
    avg_fake_score = np.mean(fake_scores)

    print("\n" + "=" * 60)
    print(f"【{label_name}】")
    print("=" * 60)

    print(f"總圖片數量：{len(files)}")
    print(f"有效圖片數量：{valid_total}")
    print(f"損毀圖片數量：{skipped}")
    print(f"正確數量：{correct}")
    print(f"準確率：{acc:.2%}")
    print(f"平均 Fake 分數：{avg_fake_score:.4f}")

    return {
        "name": label_name,
        "total": valid_total,
        "skipped": skipped,
        "correct": correct,
        "acc": acc,
        "avg_fake_score": avg_fake_score
    }


# ─────────────────────────────
# MAIN
# ─────────────────────────────

print("\n" + "=" * 60)
print("NetLens Evaluate Report (dataset_v3)")
print("=" * 60)

results = []

# =========================
# dataset_v3 驗證集
# =========================

r1 = evaluate_folder(
    os.path.join(DATASET_DIR, "val", "real"),
    1,  # real = 1
    "Validation Real Images"
)

r2 = evaluate_folder(
    os.path.join(DATASET_DIR, "val", "fake"),
    0,  # fake = 0
    "Validation Fake Images"
)

# =========================
# 額外測試資料（保留）
# =========================

r3 = evaluate_folder(
    "detection/test_images/real",
    1,
    "External Real Photos"
)

r4 = evaluate_folder(
    "detection/test_images/stylegan",
    0,
    "External StyleGAN Fake"
)

results = [
    r for r in [r1, r2, r3, r4]
    if r is not None
]

# ─────────────────────────────
# SUMMARY TABLE
# ─────────────────────────────

print("\n")
print("=" * 80)
print("SUMMARY")
print("=" * 80)

print(
    f"{'類別':<35}"
    f"{'有效數量':>10}"
    f"{'損毀數量':>10}"
    f"{'準確率':>12}"
    f"{'平均Fake分數':>15}"
)

print("-" * 90)

for r in results:
    print(
        f"{r['name']:<35}"
        f"{r['total']:>10}"
        f"{r['skipped']:>10}"
        f"{r['acc']:>12.2%}"
        f"{r['avg_fake_score']:>15.4f}"
    )

print("\n✅ evaluate 完成")
print("模型位置：", MODEL_PATH)