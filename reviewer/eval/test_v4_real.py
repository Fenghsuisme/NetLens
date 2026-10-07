# -*- coding: utf-8 -*-
"""
test_v4_real.py — 用 Gemini 94 筆真實測試資料評估 v4 模型（13類）

設計要點：
  1. 不剝除註解 — v4 是用含註解的資料訓練的，測試條件須與訓練一致
  2. 13 類標籤（label 0-12），用 config_loader 對應（非硬寫 LABEL_MAP）
     這點很重要：舊的 code_analyzer.py 有一份 v2/v3 時代硬寫的 LABEL_MAP，
     若與 v4 訓練時的標籤順序不符，會導致模型判對卻被算成錯。
  3. 只測 CodeBERT（不含 Semgrep），純粹看模型實力

注意：Gemini 94 筆只涵蓋 13 類中的 10 類。

執行：python test_v4_real.py
"""
import os
import re
import sys
import glob
from collections import defaultdict

import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

# 已移入子目錄，需往上一層才能 import 到 reviewer/ 下的模組
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.config_loader import normalize_label, get_category

MODEL_DIR = "models/codebert_v4"
BASE_MODEL = "microsoft/codebert-base"
TEST_FILE = "test_code/real_test/security_training_dataset_v1.txt"
REPORT = "dataset/v4_real_test_report.txt"

STRIP_COMMENTS = False   # v4 訓練時保留註解，測試也須保留

# v4 的 13 類（label 0-12），順序與 config/vuln_categories.json 一致
LABEL_NAMES = {
    0: "正常程式碼", 1: "指令注入", 2: "SQL 注入", 3: "程式碼執行",
    4: "資料外洩", 5: "後門", 6: "弱加密", 7: "硬編碼密碼",
    8: "路徑遊走", 9: "不安全反序列化", 10: "跨站腳本", 11: "原型污染",
    12: "惡意套件",
}
NUM_LABELS = 13


def _resolve_model_path(model_dir):
    if os.path.exists(os.path.join(model_dir, "model.safetensors")):
        return model_dir, "最終模型"
    ckpts = glob.glob(os.path.join(model_dir, "checkpoint-*"))
    ckpts = [c for c in ckpts if os.path.exists(os.path.join(c, "model.safetensors"))]
    if not ckpts:
        return None, None
    ckpts.sort(key=lambda p: int(p.split("-")[-1]))
    return ckpts[-1], f"checkpoint {os.path.basename(ckpts[-1])}"


def parse_test_file(path):
    if not os.path.exists(path):
        print(f"❌ 找不到 {path}")
        return []
    content = open(path, encoding="utf-8").read()
    items, skipped = [], []
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
        label = info["label"]
        if label >= NUM_LABELS:
            skipped.append(f"{raw_label}(label{label}超出13類)")
            continue
        items.append((label, lang, code))
    if skipped:
        print(f"  （跳過無法對應的標籤：{set(skipped)}）")
    return items


def main():
    model_path, kind = _resolve_model_path(MODEL_DIR)
    if model_path is None:
        print(f"❌ 在 {MODEL_DIR} 找不到模型權重")
        return

    items = parse_test_file(TEST_FILE)
    if not items:
        print("❌ 沒有解析到測試資料")
        return
    print(f"解析到 {len(items)} 筆測試資料")
    print(f"模型：{model_path}（{kind}）\n")

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    tok = AutoTokenizer.from_pretrained(BASE_MODEL)
    model = AutoModelForSequenceClassification.from_pretrained(model_path).to(device)
    model.eval()

    lines = []

    def log(s=""):
        print(s)
        lines.append(s)

    log("=" * 74)
    log("v4 真實測試報告（Gemini 94 筆，13 類）")
    log("=" * 74)
    log(f"\n模型：{model_path}")
    log(f"測試資料：{TEST_FILE}")
    log(f"剝除註解：{'是' if STRIP_COMMENTS else '否（與 v4 訓練條件一致）'}")
    log(f"\n{'#':<4} {'語言':<12} {'預期':<14} {'預測':<14} {'信心':<7} {'結果'}")
    log("-" * 74)

    correct = 0
    per_class = defaultdict(lambda: {"total": 0, "hit": 0})
    errors = []

    for idx, (true_label, lang, code) in enumerate(items, 1):
        enc = tok(code[:2000], max_length=512, padding="max_length",
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
    log("\n" + "=" * 74)
    log(f"總命中率：{correct}/{total} = {correct/total:.1%}")
    log("=" * 74)

    log("\n【各類別命中率】")
    for label in sorted(per_class.keys()):
        s = per_class[label]
        rate = s["hit"] / s["total"]
        bar = "█" * int(rate * 20)
        log(f"  {LABEL_NAMES[label]:<14} {s['hit']:>2}/{s['total']:<2} "
            f"{rate:>5.0%}  {bar}")

    covered = set(per_class.keys())
    missing = [LABEL_NAMES[i] for i in range(NUM_LABELS) if i not in covered]
    if missing:
        log(f"\n【測試集未涵蓋的類別】（無法評估）")
        log(f"  {', '.join(missing)}")

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