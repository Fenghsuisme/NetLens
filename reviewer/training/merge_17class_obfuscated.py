# -*- coding: utf-8 -*-

"""
merge_17class_obfuscated.py — 合併三批資料，產出 17 類訓練/驗證集（v7）

v7 相對 v6 的主要改動：

1. 剝除註解
   訓練資料中部分註解直接寫出漏洞名稱，
   例如 "# VULNERABILITY: SSRF"，
   避免模型直接從註解作弊。

2. 合併 IDOR(15) → 權限控制缺陷(17)
   CWE-639（IDOR）併入 CWE-284（權限控制缺陷），
   最終維持 17 類。

3. Function 名稱去語意化
   將程式碼中的 function / method 名稱改成沒有語意的隨機名稱，
   例如：

       def execute_sql_query():
           ...

   改成：

       def f_a83k2m():
           ...

   同一個 function 的呼叫名稱也會同步修改。

   目的：
   避免 CodeBERT 直接從 function 名稱中的
   "sql", "upload", "password", "execute", "request" 等語意
   猜測漏洞類型。

輸出：
    dataset/train_17_v7_obfuscated.csv
    dataset/val_17_v7_obfuscated.csv
    dataset/merge_17_report_v7_obfuscated.txt

執行：
    python merge_17class_obfuscated.py
"""

import os
import sys
import re
import hashlib

import pandas as pd
from sklearn.model_selection import train_test_split

# 已移入子目錄，需往上一層才能 import 到 reviewer/ 下的模組
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.config_loader import get_category, label_to_category


# ============================================================
# 設定
# ============================================================

SOURCES = [
    "dataset/dataset_aligned.csv",
    "dataset/cvefixes/cvefixes_aligned_web.csv",
    "dataset/teammate_aligned.csv",
]

TEST_FILES = [
    "test_code/real_test/security_training_dataset_v1.txt",
    # "test_code/real_test/golden_raw.txt",
]

OUT_TRAIN = "dataset/train_17_v7_obfuscated.csv"
OUT_VAL = "dataset/val_17_v7_obfuscated.csv"
REPORT = "dataset/merge_17_report_v7_obfuscated.txt"

KEEP_LABELS = set(range(18))

MAX_PER_CLASS = 2500
MAX_CLEAN = 5000

VAL_RATIO = 0.2
SEED = 42

MIN_CODE_LEN_AFTER_STRIP = 30

STRIP_COMMENTS = True

# IDOR(15) → 權限控制缺陷(17)
MERGE_LABELS = {
    15: 17
}

# 合併後重新編號
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
    剝除常見語言的註解。
    """

    s = str(code)

    # Python / 部分語言的三引號區塊
    s = re.sub(
        r'"""(.*?)"""',
        "",
        s,
        flags=re.DOTALL
    )

    s = re.sub(
        r"'''(.*?)'''",
        "",
        s,
        flags=re.DOTALL
    )

    # /* ... */
    s = re.sub(
        r"/\*.*?\*/",
        "",
        s,
        flags=re.DOTALL
    )

    # // ...
    s = re.sub(
        r"//.*",
        "",
        s
    )

    # # ...
    s = re.sub(
        r"#.*",
        "",
        s
    )

    # 清理多餘空行
    s = re.sub(
        r"\n\s*\n+",
        "\n",
        s
    )

    return s.strip()


# ============================================================
# Function 名稱去語意化
# ============================================================

def _random_function_name(original_name, code):
    """
    根據原始 function 名稱 + 該筆 code 產生固定的無語意名稱。

    例如：

        execute_query
        upload_file
        check_password

    可能變成：

        f_a83k2m
        f_71qpx4
        f_c91mz7

    不直接使用 random，避免每次 merge 後結果不同。
    """

    seed_text = f"{code}::{original_name}"

    digest = hashlib.sha256(
        seed_text.encode("utf-8")
    ).hexdigest()

    return "f_" + digest[:8]


def _rename_functions(code):
    """
    將常見語言中的 function / method 名稱去語意化。

    支援主要語言：

        Python
        JavaScript
        TypeScript
        Java
        C
        C++
        C#
        PHP

    主要處理：

        def function_name(...)
        function function_name(...)
        public void function_name(...)
        private int function_name(...)
        static function_name(...)
        function_name(...) { ... }

    同一段 code 中，function 的定義與呼叫名稱會同步替換。
    """

    code = str(code)

    replacements = {}

    # --------------------------------------------------------
    # 1. Python
    #
    # def execute_query(...):
    # --------------------------------------------------------

    python_defs = re.findall(
        r"\bdef\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
        code
    )

    for name in python_defs:
        if name not in replacements:
            replacements[name] = _random_function_name(
                name,
                code
            )

    # --------------------------------------------------------
    # 2. JavaScript / TypeScript
    #
    # function executeQuery(...)
    # async function executeQuery(...)
    # --------------------------------------------------------

    js_defs = re.findall(
        r"\b(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(",
        code
    )

    for name in js_defs:
        if name not in replacements:
            replacements[name] = _random_function_name(
                name,
                code
            )

    # --------------------------------------------------------
    # 3. JavaScript / TypeScript arrow function
    #
    # const executeQuery = (...) =>
    # let executeQuery = (...) =>
    # var executeQuery = (...) =>
    # --------------------------------------------------------

    arrow_defs = re.findall(
        r"\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)"
        r"\s*=\s*(?:async\s*)?"
        r"(?:\([^)]*\)|[A-Za-z_$][A-Za-z0-9_$]*)"
        r"\s*=>",
        code
    )

    for name in arrow_defs:
        if name not in replacements:
            replacements[name] = _random_function_name(
                name,
                code
            )

    # --------------------------------------------------------
    # 4. PHP
    #
    # function execute_query(...)
    # --------------------------------------------------------

    php_defs = re.findall(
        r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
        code
    )

    for name in php_defs:
        if name not in replacements:
            replacements[name] = _random_function_name(
                name,
                code
            )

    # --------------------------------------------------------
    # 5. C / C++ / Java / C# / PHP
    #
    # void executeQuery(...)
    # public int executeQuery(...)
    # private static String executeQuery(...)
    #
    # 這裡只抓「看起來像 function declaration」的情況。
    # --------------------------------------------------------

    typed_defs = re.findall(
        r"""
        (?:
            public\s+|
            private\s+|
            protected\s+|
            internal\s+|
            static\s+|
            virtual\s+|
            override\s+|
            async\s+|
            extern\s+|
            inline\s+|
            constexpr\s+|
            unsigned\s+|
            signed\s+|
            const\s+|
            volatile\s+
        )*
        (?:
            void|
            int|
            long|
            short|
            float|
            double|
            bool|
            boolean|
            char|
            byte|
            string|
            String|
            Object|
            auto|
            var|
            Task|
            Action|
            Result|
            Response|
            [A-Za-z_][A-Za-z0-9_:<>\[\]]*
        )
        \s+
        ([A-Za-z_][A-Za-z0-9_]*)
        \s*
        \(
        """,
        code,
        flags=re.VERBOSE
    )

    for name in typed_defs:
        # 排除一些常見語言 keyword / 控制結構
        if name in {
            "if",
            "for",
            "while",
            "switch",
            "catch",
            "return",
            "sizeof",
            "typeof",
            "main",
        }:
            continue

        if name not in replacements:
            replacements[name] = _random_function_name(
                name,
                code
            )

    # --------------------------------------------------------
    # 如果完全沒有抓到 function definition
    # 就直接返回原始 code
    # --------------------------------------------------------

    if not replacements:
        return code, 0

    # --------------------------------------------------------
    # 替換 function 名稱
    #
    # 使用 word boundary，
    # 避免：
    #
    # query
    #
    # 誤傷：
    #
    # query_result
    # queryData
    # --------------------------------------------------------

    renamed = code

    # 先按照名稱長度由長到短
    # 避免短名稱影響長名稱
    names = sorted(
        replacements.keys(),
        key=len,
        reverse=True
    )

    for old_name in names:
        new_name = replacements[old_name]

        renamed = re.sub(
            rf"\b{re.escape(old_name)}\b",
            new_name,
            renamed
        )

    return renamed, len(replacements)


# ============================================================
# Fingerprint
# ============================================================

def _fingerprint(code):
    s = re.sub(
        r"\s+",
        "",
        str(code)
    ).lower()

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
            print(
                f"  （測試檔不存在，跳過：{path}）"
            )
            continue

        content = open(
            path,
            encoding="utf-8"
        ).read()

        for block in content.split("---SPLIT---"):

            block = block.strip()

            if not block:
                continue

            # Markdown code block
            m = re.search(
                r"```(?:\w*)\n(.*?)```",
                block,
                re.DOTALL
            )

            if m:
                code = m.group(1).strip()

            else:

                pos = block.find("###DESC:")

                if pos == -1:
                    continue

                nl = block.find(
                    "\n",
                    pos
                )

                code = (
                    block[nl:].strip()
                    if nl != -1
                    else ""
                )

            if len(code) >= 30:

                # 測試集也剝註解後比對
                clean_code = (
                    _strip_comments(code)
                    if STRIP_COMMENTS
                    else code
                )

                fps.add(
                    _fingerprint(clean_code)
                )

                n += 1

    print(
        f"  載入測試集 {n} 筆指紋"
    )

    return fps


# ============================================================
# Main
# ============================================================

def main():

    # --------------------------------------------------------
    # 載入資料
    # --------------------------------------------------------

    dfs = []
    src_stat = {}

    for path in SOURCES:

        if not os.path.exists(path):

            print(
                f"⚠️ 找不到 {path}，跳過"
            )

            continue

        df = pd.read_csv(path)

        src_stat[
            os.path.basename(path)
        ] = len(df)

        print(
            f"載入 {path}：{len(df)} 筆"
        )

        dfs.append(df)

    if not dfs:

        print("❌ 沒有任何資料源")
        return

    combined = pd.concat(
        dfs,
        ignore_index=True
    )

    print(
        f"\n合併總計：{len(combined)} 筆"
    )

    # --------------------------------------------------------
    # 只保留 18 類
    # --------------------------------------------------------

    before = len(combined)

    combined = combined[
        combined["label"].isin(KEEP_LABELS)
    ].reset_index(drop=True)

    removed_other = before - len(combined)

    # --------------------------------------------------------
    # 剝除註解
    # --------------------------------------------------------

    stripped_short = 0

    if STRIP_COMMENTS:

        print(
            "\n剝除註解中（防止模型讀註解作弊）..."
        )

        len_before = (
            combined["code"]
            .astype(str)
            .str.len()
            .mean()
        )

        combined["code"] = (
            combined["code"]
            .apply(_strip_comments)
        )

        len_after = (
            combined["code"]
            .str.len()
            .mean()
        )

        mask = (
            combined["code"].str.len()
            >= MIN_CODE_LEN_AFTER_STRIP
        )

        stripped_short = int(
            (~mask).sum()
        )

        combined = (
            combined[mask]
            .reset_index(drop=True)
        )

        print(
            f"  平均長度："
            f"{len_before:.0f} → "
            f"{len_after:.0f} 字元"
        )

        print(
            f"  剝除後過短而丟棄："
            f"{stripped_short} 筆"
        )

    # --------------------------------------------------------
    # Function 名稱去語意化
    # --------------------------------------------------------

    print(
        "\nFunction 名稱去語意化中..."
    )

    total_renamed = 0
    rows_with_function = 0

    renamed_codes = []

    for code in combined["code"]:

        new_code, count = _rename_functions(code)

        renamed_codes.append(new_code)

        if count > 0:
            rows_with_function += 1
            total_renamed += count

    combined["code"] = renamed_codes

    print(
        f"  有 function/method 被處理的資料："
        f"{rows_with_function} 筆"
    )

    print(
        f"  總共重新命名 function："
        f"{total_renamed} 個"
    )

    # --------------------------------------------------------
    # 合併類別
    # --------------------------------------------------------

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
            else {}
        )

        new_info = (
            get_category(new_cat)
            if new_cat
            else {}
        )

        old_zh = old_info.get(
            "name_zh",
            str(old)
        )

        new_zh = new_info.get(
            "name_zh",
            str(new)
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

        combined.loc[
            combined["label"] == new,
            "category"
        ] = new_cat

        combined.loc[
            combined["label"] == new,
            "category_zh"
        ] = new_zh

    # --------------------------------------------------------
    # 重新編號
    # --------------------------------------------------------

    combined["label"] = (
        combined["label"]
        .map(RELABEL_MAP)
    )

    combined = (
        combined
        .dropna(subset=["label"])
        .reset_index(drop=True)
    )

    combined["label"] = (
        combined["label"]
        .astype(int)
    )

    combined["category_zh"] = (
        combined["label"]
        .map(NEW_LABEL_NAMES)
    )

    # --------------------------------------------------------
    # 防資料洩漏
    # --------------------------------------------------------

    print(
        "\n防資料洩漏檢查："
    )

    test_fps = (
        _load_test_fingerprints()
    )

    combined["_fp"] = (
        combined["code"]
        .apply(_fingerprint)
    )

    leak_mask = (
        combined["_fp"]
        .isin(test_fps)
    )

    leaked = int(
        leak_mask.sum()
    )

    combined = (
        combined[~leak_mask]
        .reset_index(drop=True)
    )

    print(
        f"  剔除與測試集重疊："
        f"{leaked} 筆"
    )

    # --------------------------------------------------------
    # 去重
    # --------------------------------------------------------

    before_dedup = len(combined)

    combined = (
        combined
        .drop_duplicates(
            subset=["_fp"]
        )
        .reset_index(drop=True)
    )

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

    # --------------------------------------------------------
    # 平衡
    # --------------------------------------------------------

    print(
        "\n平衡各類數量..."
    )

    balanced = []
    balance_stat = {}

    for label in sorted(
        combined["label"].unique()
    ):

        sub = combined[
            combined["label"] == label
        ]

        cap = (
            MAX_CLEAN
            if label == 0
            else MAX_PER_CLASS
        )

        original = len(sub)

        if len(sub) > cap:

            sub = sub.sample(
                n=cap,
                random_state=SEED
            )

        balanced.append(sub)

        balance_stat[label] = {
            "before": original,
            "after": len(sub)
        }

    combined = pd.concat(
        balanced,
        ignore_index=True
    )

    combined = (
        combined
        .sample(
            frac=1,
            random_state=SEED
        )
        .reset_index(drop=True)
    )

    # --------------------------------------------------------
    # Train / Validation split
    # --------------------------------------------------------

    counts = (
        combined["label"]
        .value_counts()
    )

    if counts.min() >= 2:

        train_df, val_df = train_test_split(
            combined,
            test_size=VAL_RATIO,
            random_state=SEED,
            stratify=combined["label"]
        )

    else:

        train_df, val_df = train_test_split(
            combined,
            test_size=VAL_RATIO,
            random_state=SEED
        )

    # --------------------------------------------------------
    # 輸出
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # 報告
    # --------------------------------------------------------

    lines = []

    lines.append(
        "=" * 68
    )

    lines.append(
        "17 類訓練資料合併報告（v7）"
    )

    lines.append(
        "=" * 68
    )

    lines.append(
        "\n本版主要改動："
    )

    lines.append(
        "  1. 剝除所有註解"
    )

    lines.append(
        "     防止模型直接讀取 "
        "'# VULNERABILITY: XXX' "
        "等漏洞提示。"
    )

    lines.append(
        "  2. IDOR 併入權限控制缺陷"
    )

    lines.append(
        "     CWE-639 → CWE-284"
    )

    lines.append(
        "  3. Function 名稱去語意化"
    )

    lines.append(
        "     將 function / method 名稱"
        "改成固定、無語意的亂碼名稱。"
    )

    lines.append(
        "     例如 execute_query → f_a83k2m"
    )

    lines.append(
        "     upload_file → f_91bc72"
    )

    lines.append(
        "\nFunction 去語意化統計："
    )

    lines.append(
        f"  有 function 被處理的資料："
        f"{rows_with_function}"
    )

    lines.append(
        f"  總重新命名 function 數量："
        f"{total_renamed}"
    )

    lines.append(
        "\n資料來源："
    )

    for name, n in src_stat.items():

        lines.append(
            f"  {name:<34} {n:>7}"
        )

    lines.append(
        f"\n排除非18類範圍："
        f"{removed_other}"
    )

    lines.append(
        f"剝除註解後過短丟棄："
        f"{stripped_short}"
    )

    lines.append(
        f"防洩漏剔除：{leaked}"
    )

    lines.append(
        f"去重移除：{dedup}"
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

        tag = (
            "  ★含原IDOR"
            if label == 16
            else ""
        )

        lines.append(
            f"  {label:<6} "
            f"{zh:<22} "
            f"{s['before']:>7} "
            f"{s['after']:>7}"
            f"{tag}"
        )

    lines.append(
        "\n資料來源分布（最終）："
    )

    for src, cnt in (
        combined["source"]
        .value_counts()
        .items()
    ):

        lines.append(
            f"  {src:<24} {cnt:>7}"
        )

    lines.append(
        "\n語言分布："
    )

    for lang, cnt in (
        combined["language"]
        .value_counts()
        .items()
    ):

        lines.append(
            f"  {lang:<14} {cnt:>7}"
        )

    lines.append(
        "\n※ 訓練腳本請設 "
        "NUM_LABELS=17"
    )

    lines.append(
        "※ LABEL_NAMES 使用本報告的 "
        "17 類對照"
    )

    lines.append(
        "※ Function 名稱已去語意化，"
        "模型無法直接依 function 名稱判斷漏洞類別"
    )

    report = "\n".join(lines)

    open(
        REPORT,
        "w",
        encoding="utf-8"
    ).write(report)

    print(
        "\n" + report
    )

    print(
        f"\n✅ 訓練集：{OUT_TRAIN}"
    )

    print(
        f"✅ 驗證集：{OUT_VAL}"
    )


if __name__ == "__main__":
    main()