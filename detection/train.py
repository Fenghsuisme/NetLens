import torch
import torch.nn as nn
import timm
from torchvision import transforms
from torch.utils.data import DataLoader, Dataset
from PIL import Image, UnidentifiedImageError
from tqdm import tqdm
import os
import random

# ─────────────────────────────
# CONFIG
# ─────────────────────────────
DATASET_DIR = "dataset_v3"
MODEL_SAVE_PATH = "detection/models/netlens_detector_v5.pth"

EPOCHS = 10
BATCH_SIZE = 64
LEARNING_RATE = 1e-4

DEVICE = torch.device(
    "cuda" if torch.cuda.is_available() else "cpu"
)

# ⚠ 不要在這裡 print(device)
# Windows DataLoader 會重複 import，
# 造成 device 被印很多次


# ─────────────────────────────
# TRANSFORMS
# ─────────────────────────────
train_transform = transforms.Compose([
    transforms.Resize((380, 380)),
    transforms.RandomHorizontalFlip(),
    transforms.RandomRotation(10),
    transforms.ColorJitter(
        brightness=0.2,
        contrast=0.2
    ),
    transforms.ToTensor(),
    transforms.Normalize(
        [0.485, 0.456, 0.406],
        [0.229, 0.224, 0.225]
    )
])

val_transform = transforms.Compose([
    transforms.Resize((380, 380)),
    transforms.ToTensor(),
    transforms.Normalize(
        [0.485, 0.456, 0.406],
        [0.229, 0.224, 0.225]
    )
])


# ─────────────────────────────
# SAFE DATASET
# 壞圖自動跳過
# ─────────────────────────────
class SafeImageFolder(Dataset):
    def __init__(self, root, transform=None):
        self.samples = []
        self.transform = transform
        self.bad_count = 0

        classes = sorted([
            c for c in os.listdir(root)
            if os.path.isdir(os.path.join(root, c))
        ])

        self.class_to_idx = {
            c: i for i, c in enumerate(classes)
        }

        for c in classes:
            class_dir = os.path.join(root, c)

            for f in os.listdir(class_dir):
                path = os.path.join(class_dir, f)

                if f.lower().endswith(
                    (".jpg", ".jpeg", ".png", ".webp")
                ):
                    self.samples.append(
                        (path, self.class_to_idx[c])
                    )

        print(f"{root} samples: {len(self.samples)}")

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):

        # 最多嘗試 5 次避免 infinite loop
        for _ in range(5):
            path, label = self.samples[idx]

            try:
                img = Image.open(path).convert("RGB")
                break

            except (
                UnidentifiedImageError,
                OSError,
                ValueError
            ):
                self.bad_count += 1

                # 壞圖直接隨機跳過
                idx = random.randint(
                    0,
                    len(self.samples) - 1
                )
                continue

        else:
            # 如果連續 5 次都壞
            # 用黑圖替代避免 crash
            img = Image.new(
                "RGB",
                (380, 380),
                (0, 0, 0)
            )
            label = 0

        if self.transform:
            img = self.transform(img)

        return img, label


# ─────────────────────────────
# MAIN
# ─────────────────────────────
def main():
    print("device:", DEVICE)

    # ─────────────────────────
    # Dataset
    # ─────────────────────────
    train_dataset = SafeImageFolder(
        os.path.join(DATASET_DIR, "train"),
        transform=train_transform
    )

    val_dataset = SafeImageFolder(
        os.path.join(DATASET_DIR, "val"),
        transform=val_transform
    )

    train_loader = DataLoader(
        train_dataset,
        batch_size=BATCH_SIZE,
        shuffle=True,
        num_workers=0,
        pin_memory=False   # ← Windows 建議 False
    )

    val_loader = DataLoader(
        val_dataset,
        batch_size=BATCH_SIZE,
        shuffle=False,
        num_workers=0,
        pin_memory=False
    )

    print()
    print("train:", len(train_dataset))
    print("val:", len(val_dataset))
    print("mapping:", train_dataset.class_to_idx)
    print()

    # fake -> 0
    # real -> 1

    # ─────────────────────────
    # Model
    # ─────────────────────────
    model = timm.create_model(
        "efficientnet_b4",
        pretrained=True,
        num_classes=2
    ).to(DEVICE)

    # freeze strategy
    for name, param in model.named_parameters():
        if (
            "blocks.5" in name
            or "blocks.6" in name
            or "conv_head" in name
            or "classifier" in name
        ):
            param.requires_grad = True
        else:
            param.requires_grad = False

    trainable_params = sum(
        p.numel()
        for p in model.parameters()
        if p.requires_grad
    )

    print(
        f"trainable params: "
        f"{trainable_params:,}"
    )
    print()

    # ─────────────────────────
    # Loss / Optimizer
    # ─────────────────────────
    criterion = nn.CrossEntropyLoss()

    optimizer = torch.optim.AdamW(
        filter(
            lambda p: p.requires_grad,
            model.parameters()
        ),
        lr=LEARNING_RATE,
        weight_decay=1e-4
    )

    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(
        optimizer,
        T_max=EPOCHS
    )

    # ─────────────────────────
    # Training
    # ─────────────────────────
    best_val_acc = 0.0

    for epoch in range(EPOCHS):
        print(
            f"========== "
            f"Epoch {epoch+1}/{EPOCHS} "
            f"=========="
        )

        # ───── train ─────
        model.train()
        train_correct = 0

        for images, labels in tqdm(
            train_loader,
            desc=f"Epoch {epoch+1} Train"
        ):
            images = images.to(DEVICE)
            labels = labels.to(DEVICE)

            optimizer.zero_grad()

            outputs = model(images)

            loss = criterion(
                outputs,
                labels
            )

            loss.backward()
            optimizer.step()

            train_correct += (
                outputs.argmax(1) == labels
            ).sum().item()

        scheduler.step()

        # ───── validation ─────
        model.eval()
        val_correct = 0

        with torch.no_grad():
            for images, labels in tqdm(
                val_loader,
                desc=f"Epoch {epoch+1} Val"
            ):
                images = images.to(DEVICE)
                labels = labels.to(DEVICE)

                outputs = model(images)

                val_correct += (
                    outputs.argmax(1) == labels
                ).sum().item()

        train_acc = (
            train_correct / len(train_dataset)
        )

        val_acc = (
            val_correct / len(val_dataset)
        )

        print()
        print(
            f"Train Acc: {train_acc:.4f}"
        )
        print(
            f"Val Acc:   {val_acc:.4f}"
        )

        # ─────────────────────
        # Save best model
        # ─────────────────────
        os.makedirs(
            os.path.dirname(MODEL_SAVE_PATH),
            exist_ok=True
        )

        if val_acc > best_val_acc:
            best_val_acc = val_acc

            torch.save(
                model.state_dict(),
                MODEL_SAVE_PATH
            )

            print("✅ saved best model")

        print()

    # ─────────────────────────
    # Final Report
    # ─────────────────────────
    print("🎉 TRAINING DONE")
    print(
        f"Best Val Acc: "
        f"{best_val_acc:.4f}"
    )

    print(
        f"Bad images skipped: "
        f"{train_dataset.bad_count + val_dataset.bad_count}"
    )

    print()
    print("模型已儲存：")
    print(MODEL_SAVE_PATH)


# ─────────────────────────────
if __name__ == "__main__":
    main()