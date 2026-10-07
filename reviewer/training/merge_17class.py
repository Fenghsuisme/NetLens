# -*- coding: utf-8 -*-

"""
merge_17class.py — 合併訓練資料，產出 17 類訓練/驗證集（v7v8 + safe）

本版資料來源：

1. dataset/dataset_aligned.csv
   原本的合成漏洞資料

2. dataset/cvefixes/cvefixes_aligned_web.csv
   CVEfixes 真實漏洞資料

3. dataset/teammate_aligned.csv
   組員產生的漏洞資料

4. dataset/safe_aligned.csv
   組員產生的「安全程式碼」
   → 全部標記為 label 0「正常程式碼」

主要處理：

1. 剝除註解
   避免模型從 "# VULNERABILITY: XXX" 等註解作弊。

2. IDOR(15) → 權限控制缺陷(17)
   合併後重新編號成 17 類（label 0-16）。

3. safe dataset
   safe_dataset 中的程式碼全部視為正常程式碼：
       label = 0
       category = normal
       category_zh = 正常程式碼

4. 防止測試集資料洩漏

5. 去除重複程式碼

6. 各類別平衡

7. 80/20 stratified train / validation split

輸出：

dataset/train_17_v7v8.csv
dataset/val_17_v7v8.csv
dataset/merge_17_report_v7v8.txt

執行：

python .\training\merge_17class.py
"""

import os
import sys
import re
import hashlib

import pandas as pd
from sklearn.model_selection import train_test_split


# ============================================================
# Import reviewer/core
# ============================================================

# merge_17class.py 位於：
# reviewer/training/merge_17class.py
#
# core 位於：
# reviewer/core/
#
# 所以要往上一層到 reviewer/
sys.path.insert(
    0,
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)

from core.config_loader import get_category, label_to_category


# ============================================================
# 設定
# ============================================================

# 原本三批漏洞資料
SOURCES = [
    "dataset/dataset_aligned.csv",
    "dataset/cvefixes/cvefixes_aligned_web.csv",
    "dataset/teammate_aligned.csv",
]

# ============================================================
# 新增：安全資料獨立來源
# ============================================================

SAFE_SOURCE = "dataset/safe_aligned.csv"


# ============================================================
# 測試集
# ============================================================

TEST_FILES = [
    "test_code/real_test/security_training_dataset_v1.txt",
    # "test_code/real_test/golden_raw.txt",
]


# ============================================================
# 輸出
# ============================================================

OUT_TRAIN = "dataset/train_17_v7v8.csv"
OUT_VAL = "dataset/val_17_v7v8.csv"
REPORT = "dataset/merge_17_report_v7v8.txt"


# ============================================================
# 資料設定
# ============================================================

KEEP_LABELS = set(range(18))

# 漏洞類別最多 2500
MAX_PER_CLASS = 2500

# 正常程式碼最多 5000
MAX_CLEAN = 5000

VAL_RATIO = 0.2

SEED = 42

# 剝除註解後至少保留 30 字元
MIN_CODE_LEN_AFTER_STRIP = 30

STRIP_COMMENTS = True


# ============================================================
# IDOR → 權限控制缺陷
# ============================================================

MERGE_LABELS = {
    15: 17
}


# ============================================================
# 重新編號成 17 類
# ============================================================

RELABEL_MAP = {
    0: 0,
    1: 1,
    2: 2,
    3: 3,
    4: 4,
    5: 5,
    6: 6,
    7: 7,
    8: 8,
    9: 9,
    10: 10,
    11: 11,
    12: 12,
    13: 13,
    14: 14,
    16: 15,
    17: 16,
}


# ============================================================
# 17 類名稱
# ============================================================

NEW_LABEL_NAMES = {
    0: "正常程式碼",
    1: "指令注入",
    2: "SQL 注入",
    3: "程式碼執行",
    4: "資料外洩",
    5: "後門",
    6: "弱加密",
    7: "硬編碼密碼",
    8: "路徑遊走",
    9: "不安全反序列化",
    10: "跨站腳本",
    11: "原型污染",
    12: "惡意套件",
    13: "跨站請求偽造",
    14: "伺服器端請求偽造",
    15: "不受限檔案上傳",
    16: "權限控制缺陷",
}


# ============================================================
# 剝除註解
# ============================================================

def _strip_comments(code):
    """
    剝除常見程式語言註解。

    注意：
    這是原本的簡易版本，維持你的既有流程。
    """

    s = str(code)

    # Python / JS / Java / C / C++ / PHP 等
    s = re.sub(r'"""(.*?)"""', "", s, flags=re.DOTALL)
    s = re.sub(r"'''(.*?)'''", "", s, flags=re.DOTALL)

    # /* ... */
    s = re.sub(r"/\*.*?\*/", "", s, flags=re.DOTALL)

    # // ...
    s = re.sub(r"//.*", "", s)

    # # ...
    s = re.sub(r"#.*", "", s)

    # 清除連續空白行
    s = re.sub(r"\n\s*\n+", "\n", s)

    return s.strip()


# ============================================================
# Fingerprint
# ============================================================

def _fingerprint(code):
    s = re.sub(r"\s+", "", str(code)).lower()
    return hashlib.md5(
        s.encode("utf-8")
    ).hexdigest()


# ============================================================
# 載入測試集 fingerprint
# ============================================================

def _load_test_fingerprints():

    fps = set()
    n = 0

    for path in TEST_FILES:

        if not os.path.exists(path):
            print(f"  （測試檔不存在，跳過：{path}）")
            continue

        with open(
            path,
            encoding="utf-8",
            errors="ignore"
        ) as f:
            content = f.read()

        for block in content.split("---SPLIT---"):

            # Markdown code block
            m = re.search(
                r"```\w*\n(.*?)```",
                block,
                re.DOTALL
            )

            if m:
                code = m.group(1).strip()

            else:

                pos = block.find("###DESC:")

                if pos == -1:
                    continue

                nl = block.find("\n", pos)

                if nl != -1:
                    code = block[nl:].strip()
                else:
                    code = ""

            if len(code) >= 30:

                if STRIP_COMMENTS:
                    code_for_fp = _strip_comments(code)
                else:
                    code_for_fp = code

                fps.add(_fingerprint(code_for_fp))
                n += 1

    print(f"  載入測試集 {n} 筆指紋")

    return fps


# ============================================================
# 主程式
# ============================================================

def main():

    # ========================================================
    # 載入原本三批漏洞資料
    # ========================================================

    dfs = []

    src_stat = {}

    print("=" * 70)
    print("開始載入漏洞訓練資料")
    print("=" * 70)

    for path in SOURCES:

        if not os.path.exists(path):

            print(f"⚠️ 找不到 {path}，跳過")
            continue

        try:
            df = pd.read_csv(path)
        except Exception as e:
            print(f"❌ 讀取失敗：{path}")
            print(f"   {e}")
            continue

        src_stat[os.path.basename(path)] = len(df)

        print(
            f"載入 {path}：{len(df)} 筆"
        )

        dfs.append(df)

    # ========================================================
    # 載入安全資料
    # ========================================================

    safe_df = None
    safe_count = 0

    print("\n" + "=" * 70)
    print("載入安全程式碼資料")
    print("=" * 70)

    if os.path.exists(SAFE_SOURCE):

        try:

            safe_df = pd.read_csv(SAFE_SOURCE)

            safe_count = len(safe_df)

            print(
                f"載入 {SAFE_SOURCE}：{safe_count} 筆"
            )

            # ------------------------------------------------
            # 安全資料強制設定為正常程式碼
            # ------------------------------------------------

            safe_df["label"] = 0
            safe_df["category"] = "normal"
            safe_df["category_zh"] = NEW_LABEL_NAMES[0]

            # 如果沒有 cwe 欄位就補
            if "cwe" not in safe_df.columns:
                safe_df["cwe"] = "SAFE"

            # 如果沒有 source 欄位就補
            safe_df["source"] = "safe_dataset"

            # 確保有 code
            if "code" not in safe_df.columns:
                raise ValueError(
                    "safe_aligned.csv 缺少 code 欄位"
                )

            # 確保有 language
            if "language" not in safe_df.columns:
                raise ValueError(
                    "safe_aligned.csv 缺少 language 欄位"
                )

            print(
                f"  → 全部標記為 label 0：正常程式碼"
            )

            # ------------------------------------------------
            # 安全資料獨立加入
            # ------------------------------------------------

            dfs.append(safe_df)

            src_stat["safe_aligned.csv"] = safe_count

        except Exception as e:

            print(
                f"❌ 讀取 safe dataset 失敗：{e}"
            )
            return

    else:

        print(
            f"⚠️ 找不到安全資料：{SAFE_SOURCE}"
        )

        print(
            "   將不加入 safe dataset。"
        )

    # ========================================================
    # 確認有資料
    # ========================================================

    if not dfs:

        print("❌ 沒有任何資料源")
        return

    # ========================================================
    # 合併
    # ========================================================

    combined = pd.concat(
        dfs,
        ignore_index=True
    )

    print(
        f"\n全部資料合併總計：{len(combined)} 筆"
    )

    # ========================================================
    # 只保留原本 18 類
    #
    # 注意：
    # safe data 已經 label=0，所以也會被保留
    # ========================================================

    before = len(combined)

    combined = combined[
        combined["label"].isin(KEEP_LABELS)
    ].reset_index(drop=True)

    removed_other = before - len(combined)

    print(
        f"排除非 18 類資料：{removed_other} 筆"
    )

    # ========================================================
    # 剝除註解
    # ========================================================

    stripped_short = 0

    if STRIP_COMMENTS:

        print(
            "\n剝除註解中（防止模型讀漏洞名稱作弊）..."
        )

        len_before = (
            combined["code"]
            .astype(str)
            .str.len()
            .mean()
        )

        combined["code"] = combined[
            "code"
        ].apply(_strip_comments)

        len_after = (
            combined["code"]
            .astype(str)
            .str.len()
            .mean()
        )

        # 剝除後太短
        mask = (
            combined["code"]
            .astype(str)
            .str.len()
            >= MIN_CODE_LEN_AFTER_STRIP
        )

        stripped_short = int((~mask).sum())

        combined = combined[
            mask
        ].reset_index(drop=True)

        print(
            f"  平均長度："
            f"{len_before:.0f} → "
            f"{len_after:.0f} 字元"
        )

        print(
            f"  剝除後過短而丟棄："
            f"{stripped_short} 筆"
        )

    # ========================================================
    # 合併 IDOR → 權限控制缺陷
    # ========================================================

    print("\n合併類別：")

    for old, new in MERGE_LABELS.items():

        n = int(
            (combined["label"] == old).sum()
        )

        old_cat = label_to_category(old)
        new_cat = label_to_category(new)

        old_info = (
            get_category(old_cat)
            if old_cat
            else None
        )

        new_info = (
            get_category(new_cat)
            if new_cat
            else None
        )

        old_zh = (
            old_info.get("name_zh", str(old))
            if old_info
            else str(old)
        )

        new_zh = (
            new_info.get("name_zh", str(new))
            if new_info
            else str(new)
        )

        print(
            f"  {old_zh}({old}) "
            f"→ {new_zh}({new})："
            f"{n} 筆"
        )

        combined.loc[
            combined["label"] == old,
            "label"
        ] = new

        if new_cat is not None:

            combined.loc[
                combined["label"] == new,
                "category"
            ] = new_cat

            combined.loc[
                combined["label"] == new,
                "category_zh"
            ] = new_zh

    # ========================================================
    # 重新編號
    # ========================================================

    combined["label"] = combined[
        "label"
    ].map(RELABEL_MAP)

    combined = combined.dropna(
        subset=["label"]
    ).reset_index(drop=True)

    combined["label"] = combined[
        "label"
    ].astype(int)

    combined["category_zh"] = combined[
        "label"
    ].map(NEW_LABEL_NAMES)

    # ========================================================
    # 防資料洩漏
    # ========================================================

    print("\n防資料洩漏檢查：")

    test_fps = _load_test_fingerprints()

    combined["_fp"] = combined[
        "code"
    ].apply(_fingerprint)

    leak_mask = combined[
        "_fp"
    ].isin(test_fps)

    leaked = int(
        leak_mask.sum()
    )

    combined = combined[
        ~leak_mask
    ].reset_index(drop=True)

    print(
        f"  剔除與測試集重疊："
        f"{leaked} 筆"
    )

    # ========================================================
    # 去重
    # ========================================================

    before_dedup = len(combined)

    combined = combined.drop_duplicates(
        subset=["_fp"]
    ).reset_index(drop=True)

    dedup = (
        before_dedup
        - len(combined)
    )

    combined = combined.drop(
        columns=["_fp"]
    )

    print(
        f"  去重移除：{dedup} 筆"
    )

    # ========================================================
    # 平衡
    # ========================================================

    print("\n平衡各類數量...")

    balanced = []

    balance_stat = {}

    for label in sorted(
        combined["label"].unique()
    ):

        sub = combined[
            combined["label"] == label
        ]

        # label 0 正常程式碼
        # 包含原本 normal + safe dataset
        if label == 0:
            cap = MAX_CLEAN
        else:
            cap = MAX_PER_CLASS

        original = len(sub)

        if len(sub) > cap:

            sub = sub.sample(
                n=cap,
                random_state=SEED
            )

        balanced.append(sub)

        balance_stat[label] = {
            "before": original,
            "after": len(sub),
        }

    combined = pd.concat(
        balanced,
        ignore_index=True
    )

    # 打亂
    combined = combined.sample(
        frac=1,
        random_state=SEED
    ).reset_index(drop=True)

    # ========================================================
    # 切分 train / validation
    # ========================================================

    counts = combined[
        "label"
    ].value_counts()

    if counts.min() >= 2:

        train_df, val_df = train_test_split(
            combined,
            test_size=VAL_RATIO,
            random_state=SEED,
            stratify=combined["label"],
        )

    else:

        train_df, val_df = train_test_split(
            combined,
            test_size=VAL_RATIO,
            random_state=SEED,
        )

    # ========================================================
    # 輸出
    # ========================================================

    os.makedirs(
        "dataset",
        exist_ok=True
    )

    train_df.to_csv(
        OUT_TRAIN,
        index=False,
        encoding="utf-8"
    )

    val_df.to_csv(
        OUT_VAL,
        index=False,
        encoding="utf-8"
    )

    # ========================================================
    # 報告
    # ========================================================

    lines = []

    lines.append("=" * 68)
    lines.append(
        "17 類訓練資料合併報告"
    )
    lines.append(
        "v7v8 + safe dataset"
    )
    lines.append("=" * 68)

    lines.append(
        "\n本版資料處理："
    )

    lines.append(
        "  1. 原本三批漏洞資料維持不變"
    )

    lines.append(
        "  2. 額外加入 safe_aligned.csv"
    )

    lines.append(
        "  3. safe dataset 全部標記為 "
        "label 0「正常程式碼」"
    )

    lines.append(
        "  4. 剝除註解，避免模型讀漏洞名稱作弊"
    )

    lines.append(
        "  5. IDOR(15) 併入權限控制缺陷(17)"
    )

    lines.append(
        "\n資料來源："
    )

    for name, n in src_stat.items():

        lines.append(
            f"  {name:<40} {n:>7}"
        )

    lines.append(
        f"\nSafe dataset 原始筆數："
        f"{safe_count}"
    )

    lines.append(
        f"排除非18類範圍："
        f"{removed_other}"
    )

    lines.append(
        f"剝除註解後過短丟棄："
        f"{stripped_short}"
    )

    lines.append(
        f"防洩漏剔除："
        f"{leaked}"
    )

    lines.append(
        f"去重移除："
        f"{dedup}"
    )

    lines.append(
        f"\n最終總筆數："
        f"{len(combined)}"
    )

    lines.append(
        f"  訓練集："
        f"{len(train_df)}"
    )

    lines.append(
        f"  驗證集："
        f"{len(val_df)}"
    )

    # ========================================================
    # 各類別數量
    # ========================================================

    lines.append(
        "\n各類別數量（17類，label 0-16）："
    )

    lines.append(
        f"  {'label':<6} "
        f"{'類別':<22} "
        f"{'平衡前':>7} "
        f"{'平衡後':>7}"
    )

    lines.append(
        "  " + "-" * 48
    )

    for label in sorted(
        balance_stat.keys()
    ):

        zh = NEW_LABEL_NAMES.get(
            label,
            str(label)
        )

        s = balance_stat[label]

        if label == 0:
            tag = "  ★含 safe dataset"
        elif label == 16:
            tag = "  ★含原IDOR"
        else:
            tag = ""

        lines.append(
            f"  {label:<6} "
            f"{zh:<22} "
            f"{s['before']:>7} "
            f"{s['after']:>7}"
            f"{tag}"
        )

    # ========================================================
    # 最終來源分布
    # ========================================================

    lines.append(
        "\n資料來源分布（最終）："
    )

    for src, cnt in combined[
        "source"
    ].value_counts().items():

        lines.append(
            f"  {src:<30} {cnt:>7}"
        )

    # ========================================================
    # 語言分布
    # ========================================================

    lines.append(
        "\n語言分布："
    )

    for lang, cnt in combined[
        "language"
    ].value_counts().items():

        lines.append(
            f"  {lang:<14} {cnt:>7}"
        )

    lines.append(
        "\n※ 訓練腳本請維持 NUM_LABELS=17"
    )

    lines.append(
        "※ LABEL_NAMES 使用本報告的 17 類對照"
    )

    lines.append(
        "※ safe dataset 的安全程式碼全部屬於 label 0"
    )

    # ========================================================
    # 寫報告
    # ========================================================

    report = "\n".join(lines)

    with open(
        REPORT,
        "w",
        encoding="utf-8"
    ) as f:

        f.write(report)

    print("\n" + report)

    print(
        f"\n✅ 訓練集：{OUT_TRAIN}"
    )

    print(
        f"✅ 驗證集：{OUT_VAL}"
    )


# ============================================================
# Entry point
# ============================================================

if __name__ == "__main__":
    main()