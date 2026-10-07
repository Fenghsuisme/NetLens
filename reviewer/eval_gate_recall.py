# -*- coding: utf-8 -*-
"""
eval_gate_recall.py — 量測硬閘門的召回代價

背景：
    scan.py 的融合判定把結果分成三類
        confirmed  模型預測 == Semgrep 類別      ✅ 呈現
        disputed   兩者不同                      🔍 呈現（並列兩者）
        filtered   模型判為正常                  ⚪ 不呈現

    「硬閘門」= 不呈現 disputed。在 clean 樣本上這能把殘留誤報
    從 19.3% 降到 7.3%，但代價未知——因為 disputed 之中，
    可能有「Semgrep 類別猜錯、模型判對」的正確偵測。

    eval_e2e.py 量不到這個代價：它的 matched 一開始就要求
    Semgrep 類別等於真實標籤，disputed 的情況根本不會進入統計。

本腳本量測：
    現行召回   存在任一 finding，其模型預測 == 真實標籤
               （不論 Semgrep 類別是否相符；disputed 也算偵測到）
    硬閘門召回 存在任一 finding，Semgrep 類別 == 模型預測 == 真實標籤

    兩者之差，就是關閉 disputed 會失去的偵測。

用法：
    python eval_gate_recall.py -n 30      每類 30 筆（約 20 分鐘，足以決策）
    python eval_gate_recall.py            全量 1497 筆（約 90 分鐘）
    python eval_gate_recall.py --analyze-only
"""
import argparse
import json
import os
import sys
import time
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "eval"))

from testset_parser import parse_testset
from transport_layer import extract_enclosing_function, SemgrepExecutionError
from core.config_loader import get_category
from label_map import config_to_model, MODEL_LABEL_NAMES

from eval_e2e import (collect_findings, finding_categories,
                      model_labels_to_config, A_CLASS_LABELS,
                      _strip, _resolve_model, MODEL_DIR, BASE_MODEL,
                      STRIP_COMMENTS, OBFUSCATE_FUNCS,
                      HAS_OBFUSCATE, obfuscate_functions)

CACHE = "dataset/gate_recall_cache.json"
A_PRED = {1, 2, 3, 6, 7, 8, 9, 10, 11, 12}


def semgrep_model_label(f):
    for cat in finding_categories(f):
        info = get_category(cat)
        if info:
            ml = config_to_model(info["label"])
            if ml is not None:
                return ml
    return None


def build_cache(per_cat=None):
    cfg_labels = model_labels_to_config(set(A_CLASS_LABELS))
    items = parse_testset(labels=cfg_labels)
    if not items:
        print("❌ 取不到 A 類樣本")
        return None

    if per_cat:
        seen = defaultdict(int)
        kept = []
        for it in items:
            c = it["category"]
            if seen[c] < per_cat:
                kept.append(it)
                seen[c] += 1
        items = kept

    path = _resolve_model(MODEL_DIR)
    if path is None:
        print(f"❌ 找不到模型：{MODEL_DIR}")
        return None
    import torch
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    tok = AutoTokenizer.from_pretrained(BASE_MODEL)
    model = AutoModelForSequenceClassification.from_pretrained(path).to(device)
    model.eval()

    def classify(code, language=None):
        c = _strip(code) if STRIP_COMMENTS else code
        if OBFUSCATE_FUNCS and HAS_OBFUSCATE and language:
            c = obfuscate_functions(c, language)
        if len(c) < 10:
            c = code
        enc = tok(c[:2000], max_length=512, padding="max_length",
                  truncation=True, return_tensors="pt").to(device)
        with torch.no_grad():
            p = torch.softmax(model(**enc).logits, dim=1)
            lb = int(torch.argmax(p, dim=1).item())
            return lb, float(p[0][lb].item())

    print(f"模型：{path}　裝置：{device}")
    print(f"A 類樣本：{len(items)} 筆\n")

    records = []
    t0 = time.time()
    for i, it in enumerate(items, 1):
        lang, code = it["lang"], it["code"]
        true_lb = config_to_model(it["label"])
        try:
            findings = collect_findings(code, lang)
        except SemgrepExecutionError as e:
            print(f"❌ Semgrep 失敗：{e}")
            return None

        rec = {"lang": lang, "cat": it["category"], "true": true_lb,
               "findings": []}
        for f in findings:
            line = f.get("start_line")
            if not line:
                continue
            snip, _, _ = extract_enclosing_function(code, line, lang)
            pl, conf = classify(snip, lang)
            rec["findings"].append({
                "rule": f.get("rule_id", "?"),
                "sg": semgrep_model_label(f),
                "pred": pl,
                "conf": round(conf, 4),
            })
        records.append(rec)

        if i % 50 == 0:
            el = time.time() - t0
            print(f"  {i}/{len(items)}　（{el:.0f}s，預估總計 "
                  f"{el/i*len(items):.0f}s）")

    os.makedirs(os.path.dirname(CACHE), exist_ok=True)
    json.dump(records, open(CACHE, "w", encoding="utf-8"), ensure_ascii=False)
    print(f"\n✅ 快取：{CACHE}　（耗時 {time.time()-t0:.0f}s）")
    return records


def analyze(records):
    name = lambda l: MODEL_LABEL_NAMES.get(l, str(l))
    stat = defaultdict(lambda: {"n": 0, "cur": 0, "soft": 0, "hard": 0,
                                "sg_only": 0})
    lost_detail = Counter()

    for rec in records:
        t = rec["true"]
        s = stat[rec["cat"]]
        s["n"] += 1
        fs = rec["findings"]

        # Semgrep 有沒有抓到（類別正確）——召回上限
        if any(f["sg"] == t for f in fs):
            s["sg_only"] += 1

        cur = any(f["pred"] == t for f in fs)
        soft = any(f["pred"] == t and f["pred"] in A_PRED for f in fs)
        hard = any(f["sg"] == t and f["pred"] == t for f in fs)

        s["cur"] += cur
        s["soft"] += soft
        s["hard"] += hard

        if cur and not hard:
            for f in fs:
                if f["pred"] == t and f["sg"] != t:
                    lost_detail[(name(f["sg"]) if f["sg"] is not None else "?",
                                 name(t), f["rule"])] += 1
                    break

    W = 78
    print("\n" + "=" * W)
    print("硬閘門的召回代價（A 類樣本）")
    print("=" * W)
    print(f"{'類別':<24}{'樣本':>6}{'Semgrep':>9}{'現行':>8}{'軟閘門':>8}{'硬閘門':>8}{'代價':>7}")
    print("-" * W)

    T = defaultdict(int)
    for cat in sorted(stat):
        s = stat[cat]
        cost = s["cur"] - s["hard"]
        for k in ("n", "cur", "soft", "hard", "sg_only"):
            T[k] += s[k]
        T["cost"] += cost
        mark = "  ⚠️" if cost > s["n"] * 0.02 else ""
        print(f"{cat:<24}{s['n']:>6}{s['sg_only']/s['n']:>8.1%}"
              f"{s['cur']/s['n']:>8.1%}{s['soft']/s['n']:>8.1%}"
              f"{s['hard']/s['n']:>8.1%}{cost:>7}{mark}")

    print("-" * W)
    n = T["n"]
    print(f"{'總計':<24}{n:>6}{T['sg_only']/n:>8.1%}{T['cur']/n:>8.1%}"
          f"{T['soft']/n:>8.1%}{T['hard']/n:>8.1%}{T['cost']:>7}")

    print(f"\n  現行 → 軟閘門　召回 {T['cur']/n:.1%} → {T['soft']/n:.1%}"
          f"　（損失 {T['cur']-T['soft']} 筆）")
    print(f"  現行 → 硬閘門　召回 {T['cur']/n:.1%} → {T['hard']/n:.1%}"
          f"　（損失 {T['cost']} 筆，{T['cost']/n:.1%}）")

    if lost_detail:
        print("\n" + "-" * W)
        print("【硬閘門會失去的偵測：Semgrep 類別猜錯、模型判對】")
        print("-" * W)
        print(f"  {'Semgrep說':<16}{'真實=模型說':<16}規則")
        for (sg, tr, rule), c in lost_detail.most_common(20):
            print(f"  {sg:<16}{tr:<16}{rule}　×{c}")

    print("\n" + "=" * W)
    print("決策參考")
    print("=" * W)
    print(f"  在 clean 樣本上：現行殘留誤報 19.3%，軟閘門 12.7%，硬閘門 7.3%")
    print(f"  在 A 類樣本上：現行召回 {T['cur']/n:.1%}，"
          f"軟閘門 {T['soft']/n:.1%}，硬閘門 {T['hard']/n:.1%}")
    d_fp_soft, d_fp_hard = 19.3 - 12.7, 19.3 - 7.3
    d_rc_soft = (T["cur"] - T["soft"]) / n * 100
    d_rc_hard = T["cost"] / n * 100
    print(f"\n  軟閘門：誤報 −{d_fp_soft:.1f}pp，召回 −{d_rc_soft:.1f}pp"
          f"　→ {'划算' if d_fp_soft > d_rc_soft else '不划算'}")
    print(f"  硬閘門：誤報 −{d_fp_hard:.1f}pp，召回 −{d_rc_hard:.1f}pp"
          f"　→ {'划算' if d_fp_hard > d_rc_hard else '不划算'}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", "--per-cat", type=int, help="每類最多幾筆")
    ap.add_argument("--analyze-only", action="store_true")
    args = ap.parse_args()

    if args.analyze_only:
        if not os.path.exists(CACHE):
            print(f"❌ 找不到快取 {CACHE}")
            return 1
        records = json.load(open(CACHE, encoding="utf-8"))
        print(f"讀取快取：{CACHE}（{len(records)} 筆）")
    else:
        records = build_cache(args.per_cat)
        if records is None:
            return 1

    analyze(records)
    return 0


if __name__ == "__main__":
    sys.exit(main())