# -*- coding: utf-8 -*-

"""
test_v7_full_real.py — CodeBERT 17 類完整測試集評估（v7）

本版修改：
    1. 完整讀取 testset_merged.txt
    2. 不再限制每種類別只抽 15 筆
    3. testset_merged.txt 中所有可解析的測試資料全部進行測試
    4. 剝除註解，與 v7 訓練條件一致
    5. IDOR 已併入「權限控制缺陷」
    6. 只測 CodeBERT，不含 Semgrep

執行：
    python test_v7_full_real.py
"""

import os
import re
import sys
from collections import defaultdict

import torch
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
)

# 已移入子目錄，需往上一層才能 import 到 reviewer/ 下的模組
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.config_loader import normalize_label, get_category


# ============================================================
# 設定
# ============================================================

# v7 模型
MODEL_DIR = "models/codebert_v7_obfuscated"

# 完整測試集
TEST_FILE = "test_code/real_test/testset_merged.txt"

# 測試報告
REPORT = "dataset/v7_obfuscated_real_test_report.txt"

# 必須與 v7 訓練條件一致
STRIP_COMMENTS = True


# ============================================================
# v7 的 17 類
# ============================================================

LABEL_NAMES = {
    0:  "正常程式碼",
    1:  "指令注入",
    2:  "SQL 注入",
    3:  "程式碼執行",
    4:  "資料外洩",
    5:  "後門",
    6:  "弱加密",
    7:  "硬編碼密碼",
    8:  "路徑遊走",
    9:  "不安全反序列化",
    10: "跨站腳本",
    11: "原型污染",
    12: "惡意套件",
    13: "跨站請求偽造",
    14: "伺服器端請求偽造",
    15: "不受限檔案上傳",
    16: "權限控制缺陷",
}


# ============================================================
# 舊 config 的 18 類 label → v7 的 17 類 label
#
# 原本：
#   15 = IDOR
#   16 = 不受限檔案上傳
#   17 = 權限控制缺陷
#
# v7：
#   IDOR(15) → 權限控制缺陷(16)
#   檔案上傳(16) → 15
#   權限控制缺陷(17) → 16
# ============================================================

OLD_TO_NEW = {
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

    15: 16,   # IDOR → 權限控制缺陷
    16: 15,   # 不受限檔案上傳
    17: 16,   # 權限控制缺陷
}


# ============================================================
# 剝除註解
# ============================================================

def strip_comments(code):
    """
    剝除常見程式碼註解。

    與訓練資料 merge_17class.py 的處理方式保持一致。
    """

    s = str(code)

    # Python / 多行字串型註解
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

    # C / C++ / Java / JavaScript / PHP 等
    s = re.sub(
        r"/\*.*?\*/",
        "",
        s,
        flags=re.DOTALL
    )

    # //
    s = re.sub(
        r"//.*",
        "",
        s
    )

    # #
    s = re.sub(
        r"#.*",
        "",
        s
    )

    # 移除多餘空行
    s = re.sub(
        r"\n\s*\n+",
        "\n",
        s
    )

    return s.strip()


# ============================================================
# 解析完整 testset_merged.txt
# ============================================================

def parse_test_file(path):
    """
    完整解析 testset_merged.txt。

    不再：
        每種類別抽 15 筆

    而是：
        所有可解析的測試資料全部加入 items。

    回傳：
        [(label_new, lang, code), ...]
    """

    if not os.path.exists(path):
        print(f"❌ 找不到測試檔案：{path}")
        return []

    print(f"讀取完整測試集：{path}")

    content = open(
        path,
        encoding="utf-8"
    ).read()

    items = []
    skipped = []

    # testset_merged.txt 使用 ---SPLIT--- 分隔不同測試案例
    blocks = content.split("---SPLIT---")

    print(f"原始區塊數量：{len(blocks)}")

    for block in blocks:

        block = block.strip()

        if not block:
            continue

        # ----------------------------------------------------
        # LABEL
        # ----------------------------------------------------

        lm = re.search(
            r"###LABEL:(\S+)",
            block
        )

        if not lm:
            skipped.append("缺少LABEL")
            continue

        raw_label = lm.group(1).strip()

        # ----------------------------------------------------
        # CODE
        # ----------------------------------------------------

        # 支援：
        #
        # ```python
        # code
        # ```
        #
        # ```javascript
        # code
        # ```
        #
        # ```java
        # code
        # ```
        #
        # 等格式
        cm = re.search(
            r"```[\w+#.-]*\s*\n(.*?)```",
            block,
            re.DOTALL
        )

        if cm:

            code = cm.group(1).strip()

        else:

            # 如果沒有 Markdown code block，
            # 嘗試從 ###DESC: 後面取得內容
            pos = block.find("###DESC:")

            if pos == -1:
                skipped.append(
                    f"{raw_label}:找不到CODE"
                )
                continue

            nl = block.find(
                "\n",
                pos
            )

            if nl != -1:
                code = block[nl:].strip()
            else:
                code = ""

        # 太短的程式碼不測
        if len(code) < 30:
            skipped.append(
                f"{raw_label}:程式碼過短"
            )
            continue

        # ----------------------------------------------------
        # LANGUAGE
        # ----------------------------------------------------

        langm = re.search(
            r"###LANG:(\S+)",
            block
        )

        if langm:
            lang = langm.group(1).strip().lower()
        else:
            lang = "unknown"

        # ----------------------------------------------------
        # LABEL NORMALIZE
        # ----------------------------------------------------

        canon = normalize_label(raw_label)

        if not canon:
            skipped.append(
                f"{raw_label}:無法normalize"
            )
            continue

        info = get_category(canon)

        if not info:
            skipped.append(
                f"{raw_label}:找不到category"
            )
            continue

        old_label = info["label"]

        # ----------------------------------------------------
        # 18 類 → 17 類
        # ----------------------------------------------------

        new_label = OLD_TO_NEW.get(old_label)

        if new_label is None:
            skipped.append(
                f"{raw_label}(label{old_label}超出17類)"
            )
            continue

        # ----------------------------------------------------
        # 加入完整測試集
        #
        # 注意：
        # 這裡沒有任何「每類15筆」限制。
        # 所有資料都會加入。
        # ----------------------------------------------------

        items.append(
            (
                new_label,
                lang,
                code
            )
        )

    # ========================================================
    # 顯示解析結果
    # ========================================================

    print(f"\n完整解析：{len(items)} 筆")

    if skipped:

        print(
            f"跳過：{len(skipped)} 筆"
        )

        # 不一次印出全部，避免終端機爆量
        if len(skipped) <= 30:

            for item in skipped:
                print(f"  - {item}")

        else:

            print("  前 30 筆：")

            for item in skipped[:30]:
                print(f"  - {item}")

    # ========================================================
    # 各類別數量
    # ========================================================

    class_count = defaultdict(int)

    for label, lang, code in items:
        class_count[label] += 1

    print("\n完整測試集各類別數量：")
    print("-" * 55)

    for label in range(17):

        count = class_count.get(
            label,
            0
        )

        print(
            f"  {label:2d} "
            f"{LABEL_NAMES[label]:<14}："
            f"{count:>6} 筆"
        )

    print("-" * 55)
    print(
        f"  {'總計':<18}："
        f"{len(items):>6} 筆"
    )

    return items


# ============================================================
# 主程式
# ============================================================

def main():

    # ========================================================
    # 檢查模型
    # ========================================================

    if not os.path.exists(MODEL_DIR):

        print(
            f"❌ 找不到模型：{MODEL_DIR}"
        )

        print(
            "請先確認 v7 模型已經訓練完成。"
        )

        return

    # ========================================================
    # 讀取完整測試資料
    # ========================================================

    items = parse_test_file(
        TEST_FILE
    )

    if not items:

        print(
            "\n❌ 沒有解析到任何測試資料"
        )

        return

    print(
        f"\n準備測試 {len(items)} 筆資料"
    )

    # ========================================================
    # Device
    # ========================================================

    device = torch.device(
        "cuda"
        if torch.cuda.is_available()
        else "cpu"
    )

    print(
        f"使用裝置：{device}"
    )

    # ========================================================
    # Tokenizer
    # ========================================================

    print(
        f"\n載入模型：{MODEL_DIR}"
    )

    tok = AutoTokenizer.from_pretrained(
        MODEL_DIR
    )

    # ========================================================
    # Model
    # ========================================================

    model = AutoModelForSequenceClassification.from_pretrained(
        MODEL_DIR
    ).to(device)

    model.eval()

    print(
        "模型載入完成。"
    )

    # ========================================================
    # 報告
    # ========================================================

    lines = []

    def log(s=""):

        print(s)
        lines.append(s)

    # ========================================================
    # 報告標題
    # ========================================================

    log("=" * 80)
    log("v7 完整真實測試報告（17 類）")
    log("=" * 80)

    log(
        f"\n模型：{MODEL_DIR}"
    )

    log(
        f"測試資料：{TEST_FILE}"
    )

    log(
        f"測試資料總數：{len(items)}"
    )

    log(
        f"剝除註解："
        f"{'是（與訓練條件一致）' if STRIP_COMMENTS else '否'}"
    )

    log(
        "\n本次測試："
    )

    log(
        "  完整讀取 testset_merged.txt"
    )

    log(
        "  不限制每種類別 15 筆"
    )

    # ========================================================
    # 測試表頭
    # ========================================================

    log(
        "\n"
        + "=" * 100
    )

    log(
        f"{'#':<6}"
        f"{'語言':<14}"
        f"{'預期':<16}"
        f"{'預測':<16}"
        f"{'信心':<8}"
        f"{'結果'}"
    )

    log(
        "-" * 100
    )

    # ========================================================
    # 統計
    # ========================================================

    correct = 0

    total = len(items)

    # 每種類別
    per_class = defaultdict(
        lambda: {
            "total": 0,
            "hit": 0
        }
    )

    # 每種語言
    per_language = defaultdict(
        lambda: {
            "total": 0,
            "hit": 0
        }
    )

    # 誤判
    errors = []

    # ========================================================
    # 開始測試
    # ========================================================

    for idx, (
        true_label,
        lang,
        code
    ) in enumerate(
        items,
        1
    ):

        # ----------------------------------------------------
        # 剝除註解
        # ----------------------------------------------------

        if STRIP_COMMENTS:

            test_code = strip_comments(
                code
            )

        else:

            test_code = code

        # 如果剝除後太短
        # 就使用原始 code
        if len(test_code) < 20:

            test_code = code

        # ----------------------------------------------------
        # Tokenize
        # ----------------------------------------------------

        enc = tok(
            test_code[:2000],
            max_length=512,
            padding="max_length",
            truncation=True,
            return_tensors="pt"
        ).to(device)

        # ----------------------------------------------------
        # Prediction
        # ----------------------------------------------------

        with torch.no_grad():

            logits = model(
                **enc
            ).logits

            probs = torch.softmax(
                logits,
                dim=1
            )

            pred = int(
                torch.argmax(
                    probs,
                    dim=1
                ).item()
            )

            conf = float(
                probs[0][pred].item()
            )

        # ----------------------------------------------------
        # 正確與否
        # ----------------------------------------------------

        ok = (
            pred == true_label
        )

        if ok:
            correct += 1

        # ----------------------------------------------------
        # 類別統計
        # ----------------------------------------------------

        per_class[
            true_label
        ]["total"] += 1

        if ok:

            per_class[
                true_label
            ]["hit"] += 1

        # ----------------------------------------------------
        # 語言統計
        # ----------------------------------------------------

        per_language[
            lang
        ]["total"] += 1

        if ok:

            per_language[
                lang
            ]["hit"] += 1

        # ----------------------------------------------------
        # 誤判紀錄
        # ----------------------------------------------------

        if not ok:

            errors.append(
                (
                    idx,
                    lang,
                    true_label,
                    pred,
                    conf
                )
            )

        # ----------------------------------------------------
        # 輸出
        # ----------------------------------------------------

        result_symbol = (
            "✓"
            if ok
            else "✗"
        )

        log(
            f"{idx:<6}"
            f"{lang:<14}"
            f"{LABEL_NAMES[true_label]:<16}"
            f"{LABEL_NAMES[pred]:<16}"
            f"{conf:>6.1%}   "
            f"{result_symbol}"
        )

    # ========================================================
    # 總命中率
    # ========================================================

    accuracy = (
        correct / total
        if total > 0
        else 0
    )

    log(
        "\n"
        + "=" * 80
    )

    log(
        "【完整測試集結果】"
    )

    log(
        f"總測試數：{total}"
    )

    log(
        f"正確數：{correct}"
    )

    log(
        f"錯誤數：{total - correct}"
    )

    log(
        f"總命中率："
        f"{correct}/{total}"
        f" = {accuracy:.2%}"
    )

    log(
        "=" * 80
    )

    # ========================================================
    # 各類別命中率
    # ========================================================

    log(
        "\n【各類別命中率】"
    )

    log(
        "-" * 80
    )

    for label in range(17):

        s = per_class[label]

        class_total = s["total"]
        class_hit = s["hit"]

        if class_total > 0:

            rate = (
                class_hit
                / class_total
            )

        else:

            rate = 0.0

        bar = (
            "█"
            * int(rate * 20)
        )

        log(
            f"  {label:2d} "
            f"{LABEL_NAMES[label]:<16} "
            f"{class_hit:>4}/"
            f"{class_total:<4} "
            f"{rate:>6.2%}  "
            f"{bar}"
        )

    log(
        "-" * 80
    )

    # ========================================================
    # 各語言命中率
    # ========================================================

    log(
        "\n【各語言命中率】"
    )

    log(
        "-" * 80
    )

    for lang in sorted(
        per_language.keys()
    ):

        s = per_language[lang]

        lang_total = s["total"]
        lang_hit = s["hit"]

        rate = (
            lang_hit / lang_total
            if lang_total > 0
            else 0
        )

        log(
            f"  {lang:<14}"
            f"{lang_hit:>5}/"
            f"{lang_total:<5} "
            f"{rate:>6.2%}"
        )

    log(
        "-" * 80
    )

    # ========================================================
    # 誤判明細
    # ========================================================

    if errors:

        log(
            "\n【誤判明細】"
        )

        log(
            "-" * 100
        )

        for (
            idx,
            lang,
            true_label,
            pred,
            conf
        ) in errors:

            log(
                f"  #{idx:<5}"
                f"{lang:<12}"
                f"{LABEL_NAMES[true_label]:<16}"
                f"→ "
                f"{LABEL_NAMES[pred]:<16}"
                f"(信心 {conf:.1%})"
            )

        log(
            "-" * 100
        )

    else:

        log(
            "\n【誤判明細】"
        )

        log(
            "沒有誤判。"
        )

    # ========================================================
    # 儲存報告
    # ========================================================

    os.makedirs(
        os.path.dirname(REPORT),
        exist_ok=True
    )

    with open(
        REPORT,
        "w",
        encoding="utf-8"
    ) as f:

        f.write(
            "\n".join(lines)
        )

    print(
        f"\n✅ 測試完成"
    )

    print(
        f"✅ 測試總數：{total} 筆"
    )

    print(
        f"✅ 正確：{correct} 筆"
    )

    print(
        f"❌ 錯誤：{total - correct} 筆"
    )

    print(
        f"📊 總命中率：{accuracy:.2%}"
    )

    print(
        f"📄 報告：{REPORT}"
    )


# ============================================================
# Entry Point
# ============================================================

if __name__ == "__main__":
    main()