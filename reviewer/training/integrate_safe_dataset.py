# -*- coding: utf-8 -*-

"""
integrate_safe_dataset.py — 掃描 safe_dataset 的 CWE 資料夾，
轉成本專案格式並統計

重要：
safe_dataset 裡的程式碼都是「安全 / 已修補」版本，
因此無論原本屬於哪一個 CWE，
訓練 label 一律設定為：

    label = 0
    category = normal
    category_zh = 正常程式碼

但是原始 CWE 仍然保留在：
    cwe

方便之後分析不同 CWE 的安全程式碼。

資料結構：

<安全資料集根目錄>\\safe_dataset\\
    CWE-200/
        xxx_gpt.java
        xxx_gpt.py

    CWE-284/
        xxx_gpt.java

    CWE-352/
        xxx_gpt.php

    ...

執行：

    從 reviewer/ 執行：

    python .\\training\\integrate_safe_dataset.py

輸出：

    dataset/safe_aligned.csv
    dataset/safe_report.txt
"""

import os
import sys
import re
import hashlib
from collections import defaultdict, Counter

import pandas as pd


# ============================================================
# 路徑設定
# ============================================================

# 本檔案：
#
# reviewer/
# └── training/
#     └── integrate_safe_dataset.py
#
# core：
#
# reviewer/
# └── core/
#     └── config_loader.py
#
# 所以 training 的上一層就是 reviewer。

REVIEWER_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

sys.path.insert(0, REVIEWER_ROOT)


# ============================================================
# 匯入核心設定
# ============================================================

from core.config_loader import (
    cwe_to_category,
    get_category,
    get_cwe_info,
)


# ============================================================
# Safe Dataset 路徑
# ============================================================

# 請改成你本機 safe_dataset 的路徑
SAFE_DATASET_ROOT = os.environ.get(
    "SAFE_DATASET_ROOT",
    os.path.join(REVIEWER_ROOT, "dataset", "safe_dataset"),
)


# ============================================================
# 輸出
# ============================================================

OUT_CSV = "dataset/safe_aligned.csv"
REPORT = "dataset/safe_report.txt"

MIN_CODE_LEN = 30


# ============================================================
# 副檔名 → 語言
# ============================================================

EXT_LANG = {
    ".py": "python",

    ".js": "javascript",
    ".jsx": "javascript",

    ".ts": "typescript",
    ".tsx": "typescript",

    ".php": "php",

    ".java": "java",

    ".cs": "csharp",

    ".c": "c",
    ".h": "c",

    ".cpp": "cpp",
    ".cc": "cpp",
    ".hpp": "cpp",
}


# ============================================================
# Safe Dataset 統一標籤
# ============================================================

SAFE_LABEL = 0
SAFE_CATEGORY = "normal"
SAFE_CATEGORY_ZH = "正常程式碼"


# ============================================================
# 從檔名判斷生成模型
# ============================================================

def _detect_model(filename):
    """從檔名推測生成模型"""

    low = filename.lower()

    if "codellama" in low:
        return "codellama"

    if "qwen" in low:
        return "qwen"

    if "gemini" in low:
        return "gemini"

    if "gpt" in low:
        return "gpt"

    return "unknown"


# ============================================================
# CWE 名稱標準化
# ============================================================

def _norm_cwe(name):
    """
    資料夾名 → 標準 CWE 格式

    CWE-89
    cwe89
    89

    都會變成：

    CWE-89
    """

    m = re.search(
        r"(\d+)",
        str(name)
    )

    if m:
        return f"CWE-{m.group(1)}"

    return None


# ============================================================
# Main
# ============================================================

def main():

    # ========================================================
    # 檢查 Safe Dataset
    # ========================================================

    if not os.path.isdir(SAFE_DATASET_ROOT):

        print(
            "❌ 找不到 safe_dataset："
        )

        print(
            SAFE_DATASET_ROOT
        )

        return


    print("=" * 68)
    print("Safe Dataset 整合")
    print("=" * 68)

    print(
        f"\nSafe Dataset：{SAFE_DATASET_ROOT}"
    )

    print(
        "\n注意："
    )

    print(
        "  safe_dataset 所有程式碼皆視為安全程式碼"
    )

    print(
        "  所有資料將設定為 label 0：正常程式碼"
    )

    print(
        "  原始 CWE 仍保留在 cwe 欄位"
    )


    # ========================================================
    # 統計容器
    # ========================================================

    rows = []

    # cwe -> language -> count
    per_cwe = defaultdict(
        lambda: defaultdict(int)
    )

    # model -> count
    model_counter = Counter()

    # 無法解析 / 統計用
    invalid_cwe = []

    # 跳過統計
    skipped_short = 0
    skipped_ext = 0
    skipped_read = 0
    skipped_non_cwe_dir = 0

    # 去重
    seen_fp = set()
    dup = 0


    # ========================================================
    # 遍歷 Safe Dataset
    # ========================================================

    for entry in sorted(
        os.listdir(SAFE_DATASET_ROOT)
    ):

        cwe_dir = os.path.join(
            SAFE_DATASET_ROOT,
            entry
        )

        # ----------------------------------------------------
        # 只處理資料夾
        # ----------------------------------------------------

        if not os.path.isdir(cwe_dir):
            continue


        # ----------------------------------------------------
        # 第一層資料夾名稱 → CWE
        # ----------------------------------------------------

        cwe = _norm_cwe(entry)

        if cwe is None:

            skipped_non_cwe_dir += 1

            continue


        # ----------------------------------------------------
        # 確認 CWE 是否存在於 config
        #
        # 注意：
        # 即使 CWE 沒有對應到漏洞 category，
        # safe dataset 仍然可以是正常程式碼。
        #
        # 因此這裡「不會」因此丟掉資料。
        # ----------------------------------------------------

        mapped_category = cwe_to_category(cwe)


        # ----------------------------------------------------
        # 遞迴掃描
        # ----------------------------------------------------

        for dirpath, _, filenames in os.walk(
            cwe_dir
        ):

            for fn in filenames:

                # =================================================
                # 副檔名 → Language
                # =================================================

                ext = os.path.splitext(
                    fn
                )[1].lower()

                lang = EXT_LANG.get(ext)

                if lang is None:

                    skipped_ext += 1

                    continue


                # =================================================
                # 完整路徑
                # =================================================

                full = os.path.join(
                    dirpath,
                    fn
                )


                # =================================================
                # 讀取程式碼
                # =================================================

                try:

                    with open(
                        full,
                        "r",
                        encoding="utf-8",
                        errors="ignore"
                    ) as f:

                        code = f.read().strip()

                except Exception:

                    skipped_read += 1

                    continue


                # =================================================
                # 過短資料
                # =================================================

                if len(code) < MIN_CODE_LEN:

                    skipped_short += 1

                    continue


                # =================================================
                # 去重
                # =================================================

                normalized_code = re.sub(
                    r"\s+",
                    "",
                    code
                ).lower()

                fp = hashlib.md5(
                    normalized_code.encode(
                        "utf-8"
                    )
                ).hexdigest()


                if fp in seen_fp:

                    dup += 1

                    continue


                seen_fp.add(fp)


                # =================================================
                # 生成模型
                # =================================================

                model = _detect_model(fn)

                model_counter[model] += 1


                # =================================================
                # CWE 統計
                # =================================================

                per_cwe[cwe][lang] += 1


                # =================================================
                # 如果 CWE 沒有在 config 裡
                #
                # 仍然保留。
                #
                # 因為這是安全資料，
                # label 一律都是正常程式碼。
                # =================================================

                if mapped_category is None:

                    invalid_cwe.append(cwe)


                # =================================================
                # 加入資料
                #
                # 重要：
                #
                # 不管 CWE 是：
                #
                # CWE-200
                # CWE-284
                # CWE-352
                # CWE-434
                # CWE-639
                # CWE-912
                # CWE-918
                #
                # 都是：
                #
                # label = 0
                # =================================================

                rows.append({

                    "code": code,

                    "language": lang,

                    "label": SAFE_LABEL,

                    "category": SAFE_CATEGORY,

                    "category_zh": SAFE_CATEGORY_ZH,

                    "cwe": cwe,

                    "source": f"safe_{model}",

                })


    # ========================================================
    # 沒有資料
    # ========================================================

    if not rows:

        print(
            "\n❌ 沒有成功讀取任何安全程式碼"
        )

        return


    # ========================================================
    # 建立 dataset 資料夾
    # ========================================================

    os.makedirs(
        "dataset",
        exist_ok=True
    )


    # ========================================================
    # 輸出 CSV
    # ========================================================

    df = pd.DataFrame(rows)

    df.to_csv(
        OUT_CSV,
        index=False,
        encoding="utf-8"
    )


    # ========================================================
    # 報告
    # ========================================================

    lines = []

    lines.append(
        "=" * 68
    )

    lines.append(
        "Safe Dataset 整合報告"
    )

    lines.append(
        "=" * 68
    )


    # --------------------------------------------------------
    # 基本資訊
    # --------------------------------------------------------

    lines.append(
        f"\n來源資料夾：{SAFE_DATASET_ROOT}"
    )

    lines.append(
        f"成功轉換：{len(rows)} 筆"
    )

    lines.append(
        f"去重移除：{dup}"
    )

    lines.append(
        f"過短跳過：{skipped_short}"
    )

    lines.append(
        f"非程式檔跳過：{skipped_ext}"
    )

    lines.append(
        f"讀取失敗：{skipped_read}"
    )

    lines.append(
        f"非 CWE 資料夾跳過：{skipped_non_cwe_dir}"
    )


    # --------------------------------------------------------
    # Label 說明
    # --------------------------------------------------------

    lines.append(
        "\n【Label 設定】"
    )

    lines.append(
        "  所有 safe_dataset 程式碼皆視為安全程式碼"
    )

    lines.append(
        "  label：0"
    )

    lines.append(
        "  category：normal"
    )

    lines.append(
        "  category_zh：正常程式碼"
    )

    lines.append(
        "  原始 CWE 保留於 cwe 欄位"
    )


    # --------------------------------------------------------
    # 模型分布
    # --------------------------------------------------------

    lines.append(
        "\n【生成模型分布】"
    )

    for model, count in model_counter.most_common():

        lines.append(
            f"  {model:<14} {count:>7}"
        )


    # --------------------------------------------------------
    # CWE 分布
    # --------------------------------------------------------

    lines.append(
        "\n【各 CWE 資料量】"
    )

    lines.append(
        f"  {'CWE':<10} "
        f"{'訓練Label':<10} "
        f"{'類別':<22} "
        f"{'總數':>7}  "
        f"語言分布"
    )

    lines.append(
        "  " + "-" * 76
    )


    for cwe in sorted(
        per_cwe.keys(),
        key=lambda x: int(
            re.search(
                r"\d+",
                x
            ).group()
        )
    ):

        total = sum(
            per_cwe[cwe].values()
        )


        langs = ", ".join(
            f"{lang}:{count}"
            for lang, count
            in sorted(
                per_cwe[cwe].items()
            )
        )


        # ----------------------------------------------------
        # 原始 CWE 對應的漏洞名稱
        #
        # 這裡只用來「報告」，
        # 不會改變 label。
        # ----------------------------------------------------

        mapped_category = cwe_to_category(
            cwe
        )

        info = (
            get_category(mapped_category)
            if mapped_category
            else None
        )


        if info:

            original_name = info.get(
                "name_zh",
                mapped_category
            )

        else:

            original_name = "(未對應)"


        lines.append(
            f"  {cwe:<10} "
            f"{SAFE_LABEL:<10} "
            f"{SAFE_CATEGORY_ZH:<22} "
            f"{total:>7}  "
            f"{langs}"
        )

        # 額外註明原始 CWE 對應類別
        lines.append(
            f"      原始 CWE 類別：{original_name}"
        )


    # --------------------------------------------------------
    # 無法對應 CWE
    # --------------------------------------------------------

    if invalid_cwe:

        uniq = sorted(
            set(invalid_cwe),
            key=lambda x: int(
                re.search(
                    r"\d+",
                    x
                ).group()
            )
        )

        lines.append(
            "\n⚠️ 以下 CWE 在 config 中沒有對應類別，"
            "但資料仍保留並標為正常程式碼："
        )

        lines.append(
            f"  {uniq}"
        )


    # --------------------------------------------------------
    # 最終資料統計
    # --------------------------------------------------------

    lines.append(
        "\n【最終 Label 分布】"
    )

    label_counts = df["label"].value_counts().sort_index()

    for label, count in label_counts.items():

        lines.append(
            f"  label {label}: "
            f"{count} 筆"
        )


    # --------------------------------------------------------
    # 語言分布
    # --------------------------------------------------------

    lines.append(
        "\n【語言分布】"
    )

    for lang, count in (
        df["language"]
        .value_counts()
        .items()
    ):

        lines.append(
            f"  {lang:<14} {count:>7}"
        )


    # ========================================================
    # 寫入報告
    # ========================================================

    report = "\n".join(lines)

    with open(
        REPORT,
        "w",
        encoding="utf-8"
    ) as f:

        f.write(report)


    # ========================================================
    # 顯示結果
    # ========================================================

    print(
        "\n" + report
    )

    print(
        f"\n✅ 轉換結果：{OUT_CSV}"
    )

    print(
        f"✅ 報告：{REPORT}"
    )


# ============================================================
# Entry Point
# ============================================================

if __name__ == "__main__":
    main()