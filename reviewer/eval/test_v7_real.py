# -*- coding: utf-8 -*-

"""
test_v7_real.py — CodeBERT v7 真實測試（17 類）

v7 設計：
  1. 使用 models/codebert_v7
  2. 測試資料使用 testset_merged.txt
  3. 17 類，每類隨機抽取 15 筆
  4. 最多測試 17 × 15 = 255 筆
  5. 固定 SEED=42，確保每次抽到相同資料
  6. 測試時剝除註解，與 v7 訓練條件一致
  7. IDOR(15) → 權限控制缺陷(16)
  8. 檔案上傳(16) → 不受限檔案上傳(15)

執行：

    python test_v7_real.py

如果要指定測試檔：

    python test_v7_real.py testset_merged.txt
"""

import os
import re
import sys
import random
from collections import defaultdict

import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

# 已移入子目錄，需往上一層才能 import 到 reviewer/ 下的模組
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.config_loader import normalize_label, get_category


# ============================================================
# 設定
# ============================================================

MODEL_DIR = "models/codebert_v7"

# 預設測試資料
TEST_FILE = "test_code/real_test/testset_merged.txt"

# 報告
REPORT = "dataset/v7_real_test_report.txt"

# 每一類抽幾筆
SAMPLES_PER_CLASS = 15

# 固定亂數種子
SEED = 42

# 是否剝除註解
# 必須與 v7 訓練資料一致
STRIP_COMMENTS = True


# ============================================================
# 17 類標籤
# ============================================================

LABEL_NAMES = {
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
    14: "SSRF",
    15: "不受限檔案上傳",
    16: "權限控制缺陷",
}


# ============================================================
# 舊 18 類 → 新 17 類
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

    # IDOR → 權限控制缺陷
    15: 16,

    # 檔案上傳 → 不受限檔案上傳
    16: 15,

    # 原本的權限控制缺陷
    17: 16,
}


# ============================================================
# 剝除註解
# ============================================================

def strip_comments(code):
    """
    剝除常見程式碼註解。

    注意：
    這裡沿用你 v6 / v7 merge_17class.py 的處理方式，
    讓測試條件與訓練資料保持一致。
    """

    s = str(code)

    # Python / 多行字串註解
    s = re.sub(r'"""(.*?)"""', "", s, flags=re.DOTALL)
    s = re.sub(r"'''(.*?)'''", "", s, flags=re.DOTALL)

    # C / C++ / Java / JS / PHP 等
    s = re.sub(r"/\*.*?\*/", "", s, flags=re.DOTALL)
    s = re.sub(r"//.*", "", s)

    # Python / Shell
    s = re.sub(r"#.*", "", s)

    # 移除連續空白行
    s = re.sub(r"\n\s*\n+", "\n", s)

    return s.strip()


# ============================================================
# 解析 testset_merged.txt
# ============================================================

def parse_test_file(path):
    """
    解析：

    ###LABEL:xxx
    ###LANG:xxx
    ###DESC:xxx
    ###VERIFY:xxx

    ```python
    code
    ```

    回傳：

        [
            {
                "label": new_label,
                "lang": lang,
                "code": code,
            },
            ...
        ]
    """

    if not os.path.exists(path):
        print(f"❌ 找不到測試檔：{path}")
        return []

    print(f"讀取測試資料：{path}")

    with open(path, encoding="utf-8") as f:
        content = f.read()

    items = []
    skipped = []

    blocks = content.split("---SPLIT---")

    print(f"原始區塊數：{len(blocks)}")

    for block in blocks:

        block = block.strip()

        if not block:
            continue

        # ----------------------------------------------------
        # LABEL
        # ----------------------------------------------------

        lm = re.search(r"###LABEL:(\S+)", block)

        if not lm:
            continue

        raw_label = lm.group(1).strip()

        # ----------------------------------------------------
        # LANGUAGE
        # ----------------------------------------------------

        langm = re.search(r"###LANG:(\S+)", block)

        if langm:
            lang = langm.group(1).strip().lower()
        else:
            lang = "unknown"

        # ----------------------------------------------------
        # CODE
        # ----------------------------------------------------

        # 支援：
        # ```python
        # ...
        # ```

        cm = re.search(
            r"```[^\n]*\n(.*?)```",
            block,
            re.DOTALL
        )

        if cm:
            code = cm.group(1).strip()

        else:
            skipped.append(
                f"{raw_label}: 找不到程式碼區塊"
            )
            continue

        if len(code) < 30:
            skipped.append(
                f"{raw_label}: 程式碼過短"
            )
            continue

        # ----------------------------------------------------
        # Label normalize
        # ----------------------------------------------------

        canon = normalize_label(raw_label)

        if not canon:
            skipped.append(
                f"{raw_label}: normalize_label 失敗"
            )
            continue

        info = get_category(canon)

        if not info:
            skipped.append(
                f"{raw_label}: get_category 失敗"
            )
            continue

        old_label = info["label"]

        new_label = OLD_TO_NEW.get(old_label)

        if new_label is None:
            skipped.append(
                f"{raw_label}: label {old_label} 無法轉成 17 類"
            )
            continue

        items.append({
            "label": new_label,
            "lang": lang,
            "code": code,
        })

    # --------------------------------------------------------
    # 顯示解析結果
    # --------------------------------------------------------

    print(f"成功解析：{len(items)} 筆")

    if skipped:
        print(f"跳過：{len(skipped)} 筆")

        if len(skipped) <= 20:
            for x in skipped:
                print(f"  - {x}")

    return items


# ============================================================
# 每類抽 15 筆
# ============================================================

def sample_each_class(items):
    """
    每個 label 最多抽 SAMPLES_PER_CLASS 筆。

    例如：

    label 0 → 15
    label 1 → 15
    ...
    label 16 → 15

    如果某類只有 8 筆：
        → 就全部取 8 筆
    """

    random.seed(SEED)

    grouped = defaultdict(list)

    for item in items:
        grouped[item["label"]].append(item)

    selected = []

    print("\n" + "=" * 72)
    print(
        f"各類抽樣：每類最多 {SAMPLES_PER_CLASS} 筆"
    )
    print("=" * 72)

    for label in range(17):

        data = grouped.get(label, [])

        total = len(data)

        if total >= SAMPLES_PER_CLASS:

            chosen = random.sample(
                data,
                SAMPLES_PER_CLASS
            )

            print(
                f"{label:2d} "
                f"{LABEL_NAMES[label]:<14} "
                f"原始 {total:>4} → 抽取 {len(chosen):>2}"
            )

        else:

            chosen = data.copy()

            print(
                f"{label:2d} "
                f"{LABEL_NAMES[label]:<14} "
                f"原始 {total:>4} → "
                f"⚠ 只有 {len(chosen)} 筆"
            )

        selected.extend(chosen)

    # --------------------------------------------------------
    # 再打亂一次
    # --------------------------------------------------------

    random.shuffle(selected)

    print("-" * 72)
    print(f"實際測試總筆數：{len(selected)}")
    print(
        f"理論最大筆數：{17 * SAMPLES_PER_CLASS}"
    )

    return selected


# ============================================================
# 主程式
# ============================================================

def main():

    # --------------------------------------------------------
    # 命令列可以指定測試檔
    # --------------------------------------------------------

    global TEST_FILE

    if len(sys.argv) >= 2:
        TEST_FILE = sys.argv[1]

    # --------------------------------------------------------
    # 檢查模型
    # --------------------------------------------------------

    if not os.path.exists(MODEL_DIR):

        print(
            f"❌ 找不到 v7 模型：{MODEL_DIR}"
        )

        print(
            "請先執行 train_model_v7.py"
        )

        return

    # --------------------------------------------------------
    # 解析測試資料
    # --------------------------------------------------------

    items = parse_test_file(TEST_FILE)

    if not items:

        print("❌ 沒有解析到任何測試資料")

        return

    # --------------------------------------------------------
    # 每類抽 15
    # --------------------------------------------------------

    items = sample_each_class(items)

    if not items:

        print("❌ 抽樣後沒有資料")

        return

    # --------------------------------------------------------
    # 載入模型
    # --------------------------------------------------------

    device = torch.device(
        "cuda"
        if torch.cuda.is_available()
        else "cpu"
    )

    print("\n" + "=" * 72)
    print("載入 v7 CodeBERT")
    print("=" * 72)

    print(f"模型：{MODEL_DIR}")
    print(f"裝置：{device}")

    tok = AutoTokenizer.from_pretrained(
        MODEL_DIR
    )

    model = AutoModelForSequenceClassification.from_pretrained(
        MODEL_DIR
    ).to(device)

    model.eval()

    # --------------------------------------------------------
    # 報告
    # --------------------------------------------------------

    lines = []

    def log(s=""):
        print(s)
        lines.append(s)

    log("=" * 72)
    log("v7 真實測試報告")
    log("=" * 72)

    log(f"模型：{MODEL_DIR}")
    log(f"測試資料：{TEST_FILE}")
    log(f"每類抽取：{SAMPLES_PER_CLASS} 筆")
    log(f"亂數種子：{SEED}")

    log(
        f"剝除註解："
        f"{'是（與 v7 訓練條件一致）' if STRIP_COMMENTS else '否'}"
    )

    log(
        f"實際測試筆數：{len(items)}"
    )

    log(
        f"理論最大筆數：{17 * SAMPLES_PER_CLASS}"
    )

    # --------------------------------------------------------
    # 測試
    # --------------------------------------------------------

    log("\n" + "=" * 72)
    log("逐筆測試結果")
    log("=" * 72)

    log(
        f"{'#':<4} "
        f"{'語言':<12} "
        f"{'預期':<14} "
        f"{'預測':<14} "
        f"{'信心':<7} "
        f"結果"
    )

    log("-" * 72)

    correct = 0

    per_class = defaultdict(
        lambda: {
            "total": 0,
            "hit": 0
        }
    )

    errors = []

    for idx, item in enumerate(items, 1):

        true_label = item["label"]
        lang = item["lang"]
        code = item["code"]

        # ----------------------------------------------------
        # 測試時剝除註解
        # ----------------------------------------------------

        if STRIP_COMMENTS:

            test_code = strip_comments(code)

            # 如果剝除後過短，退回原始碼
            if len(test_code) < 20:
                test_code = code

        else:

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
        )

        enc = {
            k: v.to(device)
            for k, v in enc.items()
        }

        # ----------------------------------------------------
        # 預測
        # ----------------------------------------------------

        with torch.no_grad():

            logits = model(**enc).logits

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
        # 統計
        # ----------------------------------------------------

        ok = pred == true_label

        if ok:
            correct += 1

        per_class[true_label]["total"] += 1

        if ok:
            per_class[true_label]["hit"] += 1

        # ----------------------------------------------------
        # 錯誤
        # ----------------------------------------------------

        if not ok:

            errors.append({
                "idx": idx,
                "lang": lang,
                "true": true_label,
                "pred": pred,
                "conf": conf,
                "code": code,
            })

        log(
            f"{idx:<4} "
            f"{lang:<12} "
            f"{LABEL_NAMES[true_label]:<14} "
            f"{LABEL_NAMES[pred]:<14} "
            f"{conf:>5.0%}   "
            f"{'✓' if ok else '✗'}"
        )

    # ========================================================
    # 總結果
    # ========================================================

    total = len(items)

    accuracy = (
        correct / total
        if total > 0
        else 0
    )

    log("\n" + "=" * 72)
    log("總結果")
    log("=" * 72)

    log(
        f"總命中率："
        f"{correct}/{total} = {accuracy:.2%}"
    )

    # ========================================================
    # 各類別
    # ========================================================

    log("\n【各類別命中率】")

    for label in range(17):

        s = per_class[label]

        if s["total"] == 0:

            log(
                f"  {label:2d} "
                f"{LABEL_NAMES[label]:<14} "
                f"0/0   無測試資料"
            )

            continue

        rate = (
            s["hit"] /
            s["total"]
        )

        bar = "█" * int(rate * 20)

        log(
            f"  {label:2d} "
            f"{LABEL_NAMES[label]:<14} "
            f"{s['hit']:>2}/{s['total']:<2} "
            f"{rate:>6.1%}  "
            f"{bar}"
        )

    # ========================================================
    # 誤判明細
    # ========================================================

    if errors:

        log("\n【誤判明細】")

        for err in errors:

            log(
                f"  #{err['idx']:<3} "
                f"{err['lang']:<10} "
                f"{LABEL_NAMES[err['true']]:<14} "
                f"→ "
                f"{LABEL_NAMES[err['pred']]:<14} "
                f"(信心 {err['conf']:.0%})"
            )

    # ========================================================
    # 混淆統計
    # ========================================================

    confusion = defaultdict(int)

    for err in errors:

        confusion[
            (
                err["true"],
                err["pred"]
            )
        ] += 1

    if confusion:

        log("\n【主要誤判方向】")

        sorted_confusion = sorted(
            confusion.items(),
            key=lambda x: x[1],
            reverse=True
        )

        for (true_label, pred_label), count in sorted_confusion:

            log(
                f"  "
                f"{LABEL_NAMES[true_label]:<14} "
                f"→ "
                f"{LABEL_NAMES[pred_label]:<14} "
                f"{count:>2} 筆"
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
        f"✅ 測試筆數：{total}"
    )

    print(
        f"✅ 正確筆數：{correct}"
    )

    print(
        f"✅ 準確率：{accuracy:.2%}"
    )

    print(
        f"✅ 報告：{REPORT}"
    )


# ============================================================
# Entry
# ============================================================

if __name__ == "__main__":
    main()