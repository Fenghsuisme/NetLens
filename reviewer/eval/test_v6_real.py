# -*- coding: utf-8 -*-
"""
test_v6_real.py — 用 Gemini 94 筆真實測試資料評估 v6 模型（17類）

重要設計：
  1. 剝除註解 — v6 是用剝註解的資料訓練的，測試時也必須剝，條件才一致
  2. 17 類標籤對應 — IDOR 已併入權限控制缺陷
  3. 只測 CodeBERT（不含 Semgrep），純粹看模型實力

執行：python test_v6_real.py
"""
import os
import re
import sys
from collections import defaultdict

import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

# 已移入子目錄，需往上一層才能 import 到 reviewer/ 下的模組
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.config_loader import normalize_label, get_category

MODEL_DIR = "models/codebert_v6"
TEST_FILE = "test_code/real_test/testset_merged.txt"
REPORT = "dataset/v6_real_test_report.txt"

STRIP_COMMENTS = True   # 必須與訓練時一致

# v6 的 17 類（label 0-16）
LABEL_NAMES = {
    0: "正常程式碼", 1: "指令注入", 2: "SQL 注入", 3: "程式碼執行",
    4: "資料外洩", 5: "後門", 6: "弱加密", 7: "硬編碼密碼",
    8: "路徑遊走", 9: "不安全反序列化", 10: "跨站腳本", 11: "原型污染",
    12: "惡意套件", 13: "跨站請求偽造", 14: "SSRF",
    15: "不受限檔案上傳", 16: "權限控制缺陷",
}

# 舊 config 的 18 類 label → v6 的 17 類 label
# （IDOR 15 → 16；檔案上傳 16 → 15；權限 17 → 16）
OLD_TO_NEW = {
    0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 6: 6, 7: 7, 8: 8,
    9: 9, 10: 10, 11: 11, 12: 12, 13: 13, 14: 14,
    15: 16,   # IDOR → 權限控制缺陷
    16: 15,   # 檔案上傳
    17: 16,   # 權限控制缺陷
}


def strip_comments(code):
    s = str(code)
    s = re.sub(r'"""(.*?)"""', "", s, flags=re.DOTALL)
    s = re.sub(r"'''(.*?)'''", "", s, flags=re.DOTALL)
    s = re.sub(r"/\*.*?\*/", "", s, flags=re.DOTALL)
    s = re.sub(r"//.*", "", s)
    s = re.sub(r"#.*", "", s)
    s = re.sub(r"\n\s*\n+", "\n", s)
    return s.strip()


def parse_test_file(path):
    """解析 Gemini 測試檔，回傳 [(label_new, lang, code)]"""
    if not os.path.exists(path):
        print(f"❌ 找不到 {path}")
        return []
    content = open(path, encoding="utf-8").read()
    items = []
    skipped = []
    for block in content.split("---SPLIT---"):
        block = block.strip()
        if not block:
            continue
        lm = re.search(r"###LABEL:(\S+)", block)
        if not lm:
            continue
        raw_label = lm.group(1).strip()

        cm = re.search(r"```\w*\n(.*?)```", block, re.DOTALL)
        if cm:
            code = cm.group(1).strip()
        else:
            pos = block.find("###DESC:")
            if pos == -1:
                continue
            nl = block.find("\n", pos)
            code = block[nl:].strip() if nl != -1 else ""
        if len(code) < 30:
            continue

        langm = re.search(r"###LANG:(\S+)", block)
        lang = langm.group(1).strip().lower() if langm else "unknown"

        canon = normalize_label(raw_label)
        if not canon:
            skipped.append(raw_label)
            continue
        info = get_category(canon)
        old_label = info["label"]
        new_label = OLD_TO_NEW.get(old_label)
        if new_label is None:
            skipped.append(f"{raw_label}(label{old_label}超出17類)")
            continue
        items.append((new_label, lang, code))
    if skipped:
        print(f"  （跳過無法對應的標籤：{set(skipped)}）")
    return items


def main():
    if not os.path.exists(MODEL_DIR):
        print(f"❌ 找不到模型 {MODEL_DIR}")
        return

    items = parse_test_file(TEST_FILE)
    if not items:
        print("❌ 沒有解析到測試資料")
        return
    print(f"解析到 {len(items)} 筆測試資料\n")

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    tok = AutoTokenizer.from_pretrained(MODEL_DIR)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_DIR).to(device)
    model.eval()

    lines = []

    def log(s=""):
        print(s)
        lines.append(s)

    log("=" * 72)
    log("v6 真實測試報告（Gemini 94 筆，17 類）")
    log("=" * 72)
    log(f"\n模型：{MODEL_DIR}")
    log(f"測試資料：{TEST_FILE}")
    log(f"剝除註解：{'是（與訓練條件一致）' if STRIP_COMMENTS else '否'}")
    log(f"\n{'#':<4} {'語言':<12} {'預期':<14} {'預測':<14} {'信心':<7} {'結果'}")
    log("-" * 72)

    correct = 0
    per_class = defaultdict(lambda: {"total": 0, "hit": 0})
    errors = []

    for idx, (true_label, lang, code) in enumerate(items, 1):
        test_code = strip_comments(code) if STRIP_COMMENTS else code
        if len(test_code) < 20:
            test_code = code   # 剝完太短就用原始

        enc = tok(test_code[:2000], max_length=512, padding="max_length",
                  truncation=True, return_tensors="pt").to(device)
        with torch.no_grad():
            logits = model(**enc).logits
            probs = torch.softmax(logits, dim=1)
            pred = int(torch.argmax(probs, dim=1).item())
            conf = float(probs[0][pred].item())

        ok = pred == true_label
        correct += ok
        per_class[true_label]["total"] += 1
        per_class[true_label]["hit"] += ok
        if not ok:
            errors.append((idx, lang, true_label, pred, conf))

        log(f"{idx:<4} {lang:<12} {LABEL_NAMES[true_label]:<14} "
            f"{LABEL_NAMES[pred]:<14} {conf:>5.0%}   {'✓' if ok else '✗'}")

    total = len(items)
    log("\n" + "=" * 72)
    log(f"總命中率：{correct}/{total} = {correct/total:.1%}")
    log("=" * 72)

    log("\n【各類別命中率】")
    for label in sorted(per_class.keys()):
        s = per_class[label]
        rate = s["hit"] / s["total"]
        bar = "█" * int(rate * 20)
        log(f"  {LABEL_NAMES[label]:<14} {s['hit']:>2}/{s['total']:<2} "
            f"{rate:>5.0%}  {bar}")

    if errors:
        log("\n【誤判明細】")
        for idx, lang, t, p, c in errors:
            log(f"  #{idx:<3} {lang:<10} {LABEL_NAMES[t]:<14} → "
                f"誤判為 {LABEL_NAMES[p]:<14} (信心 {c:.0%})")

    with open(REPORT, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"\n✅ 報告：{REPORT}")


if __name__ == "__main__":
    main()