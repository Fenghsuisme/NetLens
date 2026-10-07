import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

# 設定中文字體
plt.rcParams['font.family'] = 'Microsoft JhengHei'
plt.rcParams['axes.unicode_minus'] = False

# ── 數據 ──────────────────────────────────────────
categories = [
    "Kaggle\n真實照片\n（訓練內）",
    "Kaggle AI生成\n（SD/MJ風格）\n（訓練內）",
    "StyleGAN\n140k test\n（訓練內）",
    "StyleGAN\nthisperson\n（訓練外）",
    "自拍照片\n（訓練外）",
]
accuracies = [99.81, 99.87, 100.0, 40.0, 100.0]
avg_scores = [0.0201, 0.9908, 0.9999, 0.4057, 0.0000]
colors = ["#2563EB", "#059669", "#059669", "#DC2626", "#7C3AED"]

fig, axes = plt.subplots(1, 2, figsize=(14, 6))
fig.suptitle("NetLens 跨生成器評估報告", fontsize=16, fontweight="bold", y=1.02)

# ── 圖一：準確率長條圖 ────────────────────────────
ax1 = axes[0]
bars = ax1.bar(categories, accuracies, color=colors, width=0.5, edgecolor="white", linewidth=1.5)
ax1.set_title("各類別偵測準確率", fontsize=13, fontweight="bold", pad=12)
ax1.set_ylabel("準確率 (%)", fontsize=11)
ax1.set_ylim(0, 115)
ax1.axhline(y=80, color="gray", linestyle="--", linewidth=1, alpha=0.5, label="80% 基準線")
ax1.legend(fontsize=10)
ax1.spines["top"].set_visible(False)
ax1.spines["right"].set_visible(False)

for bar, acc in zip(bars, accuracies):
    label = f"{acc:.1f}%"
    color = "white" if acc > 20 else "#DC2626"
    ax1.text(bar.get_x() + bar.get_width()/2, 
             bar.get_height() + 1.5,
             label, ha="center", va="bottom",
             fontsize=12, fontweight="bold", color="#111827")

# ── 圖二：平均 AI 分數 ────────────────────────────
ax2 = axes[1]
bars2 = ax2.bar(categories, avg_scores, color=colors, width=0.5, edgecolor="white", linewidth=1.5)
ax2.set_title("平均 AI 分數（越高代表模型越確定是AI生成）", fontsize=13, fontweight="bold", pad=12)
ax2.set_ylabel("平均 AI 分數", fontsize=11)
ax2.set_ylim(0, 1.15)
ax2.axhline(y=0.5, color="gray", linestyle="--", linewidth=1, alpha=0.5, label="判斷門檻 0.5")
ax2.legend(fontsize=10)
ax2.spines["top"].set_visible(False)
ax2.spines["right"].set_visible(False)

for bar, score in zip(bars2, avg_scores):
    ax2.text(bar.get_x() + bar.get_width()/2,
             bar.get_height() + 0.02,
             f"{score:.4f}", ha="center", va="bottom",
             fontsize=11, fontweight="bold", color="#111827")

# ── 標注重點發現 ──────────────────────────────────
fig.text(0.5, -0.08,
         "★ v3 模型：訓練內 StyleGAN 達到 100% 辨識率（AI分數 0.9999）\n"
         "→ thispersondoesnotexist.com 因高品質後處理消除 GAN artifact，屬於訓練外困難案例（40%）",
         ha="center", fontsize=11, color="#059669",
         bbox=dict(boxstyle="round,pad=0.5", facecolor="#F0FDF4", edgecolor="#059669")) 

plt.tight_layout()
plt.savefig("detection/outputs/evaluation_report_v3.png",
            dpi=150, bbox_inches="tight", facecolor="white")
print("圖表已儲存至：detection/outputs/evaluation_report_v3.png")