# -*- coding: utf-8 -*-
"""
error_by_source.py — 逐來源錯誤分析

目的：分辨「模型學不好」與「資料標籤有問題」。

原理：
  用訓練好的模型跑驗證集，把答錯的樣本依「資料來源」分組統計。
  - 若某來源的錯誤率遠高於其他來源 → 該來源的標籤品質有問題
  - 若各來源錯誤率相近 → 問題在類別定義或模型本身，不是資料

這比關鍵字稽核可靠，因為它用的是模型的實際判斷，
不是啟發式的關鍵字比對（後者在長程式碼上會誤判）。

執行：python error_by_source.py
"""
import os
import sys
import glob
import json
from collections import defaultdict, Counter

import numpy as np
import pandas as pd
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

# 已移入子目錄，需往上一層才能 import 到 reviewer/ 下的模組
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

MODEL_DIR = "models/codebert_v6"
BASE_MODEL = "microsoft/codebert-base"
VAL_CSV = "dataset/val_17.csv"
REPORT = "dataset/error_by_source_report.txt"
BATCH = 32

LABEL_NAMES = {
    0: "正常程式碼", 1: "指令注入", 2: "SQL 注入", 3: "程式碼執行",
    4: "資料外洩", 5: "後門", 6: "弱加密", 7: "硬編碼密碼",
    8: "路徑遊走", 9: "不安全反序列化", 10: "跨站腳本", 11: "原型污染",
    12: "惡意套件", 13: "跨站請求偽造", 14: "SSRF",
    15: "不受限檔案上傳", 16: "權限控制缺陷",
}
N = len(LABEL_NAMES)


def _resolve_model(model_dir):
    if os.path.exists(os.path.join(model_dir, "model.safetensors")):
        return model_dir
    ckpts = [c for c in glob.glob(os.path.join(model_dir, "checkpoint-*"))
             if os.path.exists(os.path.join(c, "model.safetensors"))]
    if not ckpts:
        return None
    ckpts.sort(key=lambda p: int(p.split("-")[-1]))
    return ckpts[-1]


def main():
    model_path = _resolve_model(MODEL_DIR)
    if model_path is None:
        print(f"❌ 找不到模型：{MODEL_DIR}")
        return
    if not os.path.exists(VAL_CSV):
        print(f"❌ 找不到 {VAL_CSV}")
        return

    df = pd.read_csv(VAL_CSV).dropna(subset=["code", "label"])
    df["code"] = df["code"].astype(str).str[:2000]
    df["label"] = df["label"].astype(int)
    if "source" not in df.columns:
        print("❌ 驗證集沒有 source 欄位，無法做來源分析")
        return

    print(f"模型：{model_path}")
    print(f"驗證集：{len(df)} 筆\n")

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    tok = AutoTokenizer.from_pretrained(BASE_MODEL)
    model = AutoModelForSequenceClassification.from_pretrained(model_path).to(device)
    model.eval()

    codes = df["code"].tolist()
    preds, confs = [], []
    with torch.no_grad():
        for i in range(0, len(codes), BATCH):
            enc = tok(codes[i:i + BATCH], max_length=512, padding="max_length",
                      truncation=True, return_tensors="pt").to(device)
            probs = torch.softmax(model(**enc).logits, dim=1)
            p = torch.argmax(probs, dim=1)
            preds.extend(p.cpu().numpy().tolist())
            confs.extend(probs.max(dim=1).values.cpu().numpy().tolist())
            if (i // BATCH) % 30 == 0:
                print(f"  {i}/{len(codes)}")

    df["_pred"] = preds
    df["_conf"] = confs
    df["_correct"] = df["_pred"] == df["label"]

    lines = []

    def log(s=""):
        print(s)
        lines.append(s)

    log("=" * 78)
    log("逐來源錯誤分析報告")
    log("=" * 78)
    log("\n目的：分辨「模型學不好」與「資料標籤有問題」")
    log("  某來源錯誤率遠高於其他 → 該來源標籤品質有問題")
    log("  各來源錯誤率相近       → 問題在類別定義或模型，非資料")

    overall_acc = df["_correct"].mean()
    log(f"\n整體正確率：{overall_acc:.1%}（{int(df['_correct'].sum())}/{len(df)}）")

    # ── 各來源整體表現 ──
    log("\n【各來源正確率】")
    log(f"  {'來源':<24} {'筆數':>6} {'正確':>6} {'正確率':>8} {'平均信心':>9}")
    log("  " + "-" * 58)
    src_stat = []
    for src in df["source"].value_counts().index:
        sub = df[df["source"] == src]
        src_stat.append((src, len(sub), int(sub["_correct"].sum()),
                         sub["_correct"].mean(), sub["_conf"].mean()))
    # 依正確率排序（低的在前，最可疑）
    for src, n, n_ok, acc, conf in sorted(src_stat, key=lambda x: x[3]):
        gap = acc - overall_acc
        flag = ""
        if gap < -0.10:
            flag = "  ⚠️ 明顯偏低"
        elif gap < -0.05:
            flag = "  ⚠️"
        elif gap > 0.05:
            flag = "  ✓ 偏高"
        log(f"  {src:<24} {n:>6} {n_ok:>6} {acc:>7.1%} {conf:>8.1%}{flag}")

    # ── 來源 × 類別 交叉表 ──
    log("\n【來源 × 類別 正確率】（找出特定來源在特定類別的問題）")
    sources = list(df["source"].value_counts().index)
    # 只列樣本數夠的來源
    sources = [s for s in sources if (df["source"] == s).sum() >= 100]

    header = f"  {'類別':<16}"
    for s in sources:
        short = s.replace("teammate_", "T-").replace("/dataset_raw", "").replace("cvefixes_", "CVE-")
        header += f" {short[:11]:>11}"
    log(header)
    log("  " + "-" * (16 + 12 * len(sources)))

    problem_cells = []
    for label in range(N):
        row = f"  {LABEL_NAMES[label]:<16}"
        for s in sources:
            sub = df[(df["label"] == label) & (df["source"] == s)]
            if len(sub) < 10:
                row += f" {'—':>11}"
                continue
            acc = sub["_correct"].mean()
            mark = ""
            if acc < 0.5:
                mark = "!"
                problem_cells.append((LABEL_NAMES[label], s, len(sub), acc))
            row += f" {acc:>10.0%}{mark}"
        log(row)

    if problem_cells:
        log("\n  ! 標記處（正確率 < 50%）：")
        for cat, src, n, acc in sorted(problem_cells, key=lambda x: x[3]):
            log(f"     {cat:<16} × {src:<22} n={n:<5} {acc:.0%}")

    # ── 高信心錯誤（最可疑的標籤問題）──
    log("\n【高信心錯誤】（模型很確定，卻與標籤不符 → 標籤可能是錯的）")
    high_conf_err = df[(~df["_correct"]) & (df["_conf"] > 0.90)]
    log(f"  總數：{len(high_conf_err)} 筆"
        f"（佔所有錯誤的 {len(high_conf_err)/max(1,(~df['_correct']).sum()):.0%}）")
    log(f"\n  {'來源':<24} {'高信心錯誤數':>12} {'佔該來源比例':>12}")
    log("  " + "-" * 50)
    for src in df["source"].value_counts().index:
        sub = df[df["source"] == src]
        hce = high_conf_err[high_conf_err["source"] == src]
        if len(sub) < 50:
            continue
        ratio = len(hce) / len(sub)
        flag = "  ⚠️" if ratio > 0.15 else ""
        log(f"  {src:<24} {len(hce):>12} {ratio:>11.1%}{flag}")

    log("\n  高信心錯誤的流向 TOP 12（標籤說 A，模型很確定是 B）：")
    flow = Counter()
    for _, r in high_conf_err.iterrows():
        flow[(LABEL_NAMES[r["label"]], LABEL_NAMES[r["_pred"]])] += 1
    for (a, b), c in flow.most_common(12):
        log(f"     標籤:{a:<14} → 模型:{b:<14} {c:>4} 筆")

    # ── 判讀 ──
    log("\n【判讀】")
    worst = sorted(src_stat, key=lambda x: x[3])[0]
    best = sorted(src_stat, key=lambda x: -x[3])[0]
    spread = best[3] - worst[3]
    log(f"  最低正確率來源：{worst[0]}（{worst[3]:.1%}）")
    log(f"  最高正確率來源：{best[0]}（{best[3]:.1%}）")
    log(f"  差距：{spread:.1%}")
    if spread > 0.20:
        log("  → 來源間差距大，低分來源的標籤品質有問題，建議重新生成")
    elif spread > 0.10:
        log("  → 來源間有中度差距，可針對低分來源的特定類別檢視")
    else:
        log("  → 各來源品質相近，問題不在特定資料來源，")
        log("     而在類別定義重疊或模型能力，應優先調整分類體系")

    with open(REPORT, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"\n✅ 報告：{REPORT}")


if __name__ == "__main__":
    main()