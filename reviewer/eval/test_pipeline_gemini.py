# -*- coding: utf-8 -*-
"""
test_pipeline_gemini.py — 用 Gemini 測試集評估「新架構」（傳輸層→CodeBERT）

與舊測試（test_v6_real.py）的差別：
  舊：整段程式碼 → CodeBERT（整檔輸入）
  新：整段程式碼 → Semgrep命中 → 抽片段 → CodeBERT（片段輸入）★這才是新架構

會同時報告三個關鍵數字：
  1. Semgrep 召回率：94筆裡Semgrep能命中幾筆（架構天花板）
  2. 片段管道準確率：Semgrep命中的，抽片段後CodeBERT判對幾筆
  3. 對比：同樣的資料，整檔輸入 vs 片段輸入 哪個好

只評估 A 類 10 種（新架構的範圍）。後門、資料外洩等B類會標記跳過。

執行：python test_pipeline_gemini.py
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
from transport_layer import process, extract_enclosing_function, run_semgrep, LANG_EXT
from core.config_loader import normalize_label, get_category, label_to_category

MODEL_DIR = "models/codebert_v6"
BASE_MODEL = "microsoft/codebert-base"
TEST_FILE = "test_code/real_test/security_training_dataset_v1.txt"
REPORT = "dataset/pipeline_gemini_report.txt"
STRIP_COMMENTS = True

LABEL_NAMES = {
    0: "正常程式碼", 1: "指令注入", 2: "SQL 注入", 3: "程式碼執行",
    4: "資料外洩", 5: "後門", 6: "弱加密", 7: "硬編碼密碼",
    8: "路徑遊走", 9: "不安全反序列化", 10: "跨站腳本", 11: "原型污染",
    12: "惡意套件", 13: "跨站請求偽造", 14: "SSRF",
    15: "不受限檔案上傳", 16: "權限控制缺陷",
}

# A 類 10 種的 label（新架構處理範圍）
A_CLASS_LABELS = {1, 2, 3, 6, 7, 8, 9, 10, 11, 12}
# 註：1指令注入 2SQL 3程式碼執行 6弱加密 7硬編碼 8路徑遊走
#     9反序列化 10XSS 11原型污染 12惡意套件

LANG_EXT_REV = {"python": ".py", "javascript": ".js", "php": ".php",
                "java": ".java", "typescript": ".ts"}


def _strip(code):
    s = str(code)
    s = re.sub(r'"""(.*?)"""', "", s, flags=re.DOTALL)
    s = re.sub(r"'''(.*?)'''", "", s, flags=re.DOTALL)
    s = re.sub(r"/\*.*?\*/", "", s, flags=re.DOTALL)
    s = re.sub(r"//.*", "", s)
    s = re.sub(r"#.*", "", s)
    return re.sub(r"\n\s*\n+", "\n", s).strip()


def _resolve(model_dir):
    if os.path.exists(os.path.join(model_dir, "model.safetensors")):
        return model_dir
    ckpts = [c for c in glob.glob(os.path.join(model_dir, "checkpoint-*"))
             if os.path.exists(os.path.join(c, "model.safetensors"))]
    ckpts.sort(key=lambda p: int(p.split("-")[-1]))
    return ckpts[-1] if ckpts else None


def parse_gemini():
    content = open(TEST_FILE, encoding="utf-8").read()
    items = []
    for block in content.split("---SPLIT---"):
        block = block.strip()
        if not block:
            continue
        lm = re.search(r"###LABEL:(\S+)", block)
        if not lm:
            continue
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
        canon = normalize_label(lm.group(1).strip())
        if not canon:
            continue
        label = get_category(canon)["label"]
        items.append((label, lang, code))
    return items


def main():
    model_path = _resolve(MODEL_DIR)
    if not model_path:
        print(f"❌ 找不到模型 {MODEL_DIR}")
        return

    items = parse_gemini()
    print(f"Gemini 測試集：{len(items)} 筆")

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    tok = AutoTokenizer.from_pretrained(BASE_MODEL)
    model = AutoModelForSequenceClassification.from_pretrained(model_path).to(device)
    model.eval()

    def classify(code):
        c = _strip(code) if STRIP_COMMENTS else code
        if len(c) < 10:
            c = code
        enc = tok(c[:2000], max_length=512, padding="max_length",
                  truncation=True, return_tensors="pt").to(device)
        with torch.no_grad():
            probs = torch.softmax(model(**enc).logits, dim=1)
            label = int(torch.argmax(probs, dim=1).item())
            conf = float(probs[0][label].item())
        return label, conf

    lines = []

    def log(s=""):
        print(s)
        lines.append(s)

    log("=" * 76)
    log("新架構評估：傳輸層(Semgrep抽片段) → CodeBERT")
    log("=" * 76)
    log(f"\n模型：{model_path}")
    log(f"只評估 A 類 10 種（新架構範圍），B類樣本標記跳過\n")

    # 統計
    total_a = 0              # A類樣本總數
    semgrep_hit = 0         # Semgrep命中數
    pipeline_correct = 0    # 片段管道判對數
    wholefile_correct = 0   # 整檔輸入判對數（對比用）
    skipped_b = 0           # B類跳過

    per_class = defaultdict(lambda: {"total": 0, "sg_hit": 0,
                                     "pipe_ok": 0, "whole_ok": 0})
    details = []

    for idx, (true_label, lang, code) in enumerate(items, 1):
        # B 類跳過
        if true_label not in A_CLASS_LABELS:
            skipped_b += 1
            continue
        if lang not in LANG_EXT_REV:
            continue

        total_a += 1
        per_class[true_label]["total"] += 1

        # ── 整檔輸入（舊架構，對比用）──
        whole_label, whole_conf = classify(code)
        whole_ok = whole_label == true_label
        wholefile_correct += whole_ok
        per_class[true_label]["whole_ok"] += whole_ok

        # ── 新架構：先跑 Semgrep ──
        findings = run_semgrep(code, lang)
        # 找出命中對應此類別的 finding
        matched_finding = None
        for f in findings:
            cwe = f["cwe"]
            if isinstance(cwe, list):
                cwe = cwe[0] if cwe else None
            if not cwe:
                continue
            fcat = None
            from core.config_loader import cwe_to_category
            fcat = cwe_to_category(cwe)
            if fcat and get_category(fcat)["label"] == true_label:
                matched_finding = f
                break

        sg_ok = matched_finding is not None
        semgrep_hit += sg_ok
        per_class[true_label]["sg_hit"] += sg_ok

        pipe_label, pipe_conf = None, None
        pipe_ok = False
        if sg_ok:
            # 抽片段 → CodeBERT
            snippet, _, _ = extract_enclosing_function(
                code, matched_finding["start_line"], lang)
            pipe_label, pipe_conf = classify(snippet)
            pipe_ok = pipe_label == true_label
            pipeline_correct += pipe_ok
            per_class[true_label]["pipe_ok"] += pipe_ok

        details.append({
            "idx": idx, "lang": lang, "true": true_label,
            "sg_ok": sg_ok,
            "whole_label": whole_label, "whole_ok": whole_ok,
            "pipe_label": pipe_label, "pipe_ok": pipe_ok,
        })

    # ── 報告 ──
    log("─" * 76)
    log("逐筆結果")
    log("─" * 76)
    log(f"  {'#':<4} {'語言':<11} {'預期':<12} "
        f"{'Semgrep':<8} {'整檔判定':<12} {'片段判定':<12}")
    for d in details:
        whole = LABEL_NAMES[d["whole_label"]]
        pipe = LABEL_NAMES[d["pipe_label"]] if d["pipe_label"] is not None else "(未命中)"
        log(f"  {d['idx']:<4} {d['lang']:<11} {LABEL_NAMES[d['true']]:<12} "
            f"{'✓' if d['sg_ok'] else '✗':<8} "
            f"{whole:<10}{'✓' if d['whole_ok'] else '✗':<2} "
            f"{pipe:<10}{'✓' if d['pipe_ok'] else '✗' if d['sg_ok'] else '—'}")

    log("\n" + "=" * 76)
    log("關鍵數字")
    log("=" * 76)
    log(f"\nA 類樣本總數：{total_a}（另有 {skipped_b} 筆 B 類跳過）")
    log(f"\n① Semgrep 召回率：{semgrep_hit}/{total_a} = "
        f"{semgrep_hit/max(1,total_a):.1%}")
    log(f"   （Semgrep 命中不到的，新架構直接漏掉，這是架構天花板）")
    log(f"\n② 片段管道準確率（Semgrep命中的樣本中）：")
    log(f"   {pipeline_correct}/{semgrep_hit} = "
        f"{pipeline_correct/max(1,semgrep_hit):.1%}")
    log(f"\n③ 新架構端到端：{pipeline_correct}/{total_a} = "
        f"{pipeline_correct/max(1,total_a):.1%}")
    log(f"   （= 召回率 × 片段準確率，這是實際偵測率）")
    log(f"\n對比：整檔輸入（舊架構）：{wholefile_correct}/{total_a} = "
        f"{wholefile_correct/max(1,total_a):.1%}")

    log("\n【各類別對比】")
    log(f"  {'類別':<14} {'樣本':>4} {'Semgrep':>8} {'整檔':>6} {'片段':>6}")
    log("  " + "-" * 46)
    for label in sorted(per_class.keys()):
        s = per_class[label]
        n = s["total"]
        log(f"  {LABEL_NAMES[label]:<14} {n:>4} "
            f"{s['sg_hit']:>3}/{n:<3} "
            f"{s['whole_ok']:>2}/{n:<2} "
            f"{s['pipe_ok']:>2}/{n:<2}")

    log("\n【解讀提示】")
    log("  ② 片段準確率 > 整檔準確率 → 片段輸入有效，值得走路線B")
    log("  ① Semgrep 召回率低       → 要先補規則，否則架構天花板受限")
    log("  片段和整檔差不多         → v6沒學過片段格式，需重訓才能發揮片段優勢")

    with open(REPORT, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"\n✅ 報告：{REPORT}")


if __name__ == "__main__":
    main()