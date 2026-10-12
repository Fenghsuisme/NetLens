# -*- coding: utf-8 -*-
"""
ov_eval_accuracy.py — PyTorch vs OpenVINO（FP32 / INT8 / INT8-WO）準確率對照

測試集：test_code/real_test/testset_merged.txt（2742 筆，17 類，與 test_v7v8_full_real.py 同解析器）
前處理與 scan.py 完全一致。輸出 macro-F1、accuracy、逐類別召回、
與 PyTorch 的 top-1 一致率，以及「過濾決策（label==0）」一致率。

執行（reviewer/ 下）：
  python scripts/ov/ov_eval_accuracy.py [--device CPU] [--limit N]
結果：docs/ov_results/accuracy_<device>.json
"""
import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ov_common as C

import numpy as np
import openvino as ov
from sklearn.metrics import f1_score, recall_score, accuracy_score
from transformers import AutoTokenizer

BATCH = 8
OUT_DIR = os.path.join(C.REVIEWER_ROOT, "docs", "ov_results")
VARIANTS = {
    "ov_fp32": C.OV_FP32_DIR,
    "ov_int8": C.OV_INT8_DIR,
    "ov_int8wo": os.path.join(C.REVIEWER_ROOT, "models", "codebert_ov_int8wo"),
}


def batched(enc, n):
    for i in range(0, len(enc["input_ids"]), BATCH):
        yield i, {k: enc[k][i:i + BATCH] for k in ("input_ids", "attention_mask")}


def run_pytorch(enc):
    import torch
    from transformers import AutoModelForSequenceClassification
    m = AutoModelForSequenceClassification.from_pretrained(C.SRC_MODEL_DIR).eval()
    out = []
    with torch.no_grad():
        for _, b in batched(enc, BATCH):
            out.append(m(**{k: torch.from_numpy(v) for k, v in b.items()}).logits.numpy())
    return np.concatenate(out)


def run_ov(model_dir, enc, device):
    core = ov.Core()
    cm = core.compile_model(os.path.join(model_dir, "openvino_model.xml"), device)
    req = cm.create_infer_request()
    out = []
    for _, b in batched(enc, BATCH):
        out.append(req.infer(b)[cm.output(0)].copy())
    return np.concatenate(out)


def metrics(y, logits, ref_pred=None):
    p = logits.argmax(1)
    r = {
        "accuracy": float(accuracy_score(y, p)),
        "macro_f1": float(f1_score(y, p, average="macro", labels=list(range(17)))),
        "per_class_recall": [float(x) for x in
                             recall_score(y, p, average=None, labels=list(range(17)), zero_division=0)],
    }
    if ref_pred is not None:
        r["top1_agreement_vs_pytorch"] = float((p == ref_pred).mean())
        r["filter_decision_agreement"] = float(((p == 0) == (ref_pred == 0)).mean())
    return r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--device", default="CPU")
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    items, names = C.load_testset()
    if args.limit:
        items = items[::max(1, len(items) // args.limit)][:args.limit]
    y = np.array([it["label"] for it in items])
    tok = AutoTokenizer.from_pretrained(C.BASE_MODEL)
    enc = C.tokenize(tok, [it["code"] for it in items])
    print(f"樣本數：{len(y)}")

    results, logits = {}, {}
    t = time.time()
    logits["pytorch"] = run_pytorch(enc)
    print(f"pytorch 完成 {time.time() - t:.0f}s")
    ref = logits["pytorch"].argmax(1)
    results["pytorch"] = metrics(y, logits["pytorch"])
    for name, d in VARIANTS.items():
        t = time.time()
        logits[name] = run_ov(d, enc, args.device)
        results[name] = metrics(y, logits[name], ref)
        print(f"{name} 完成 {time.time() - t:.0f}s")

    os.makedirs(OUT_DIR, exist_ok=True)
    out = {"device": args.device, "n": int(len(y)), "label_names": names, "results": results}
    path = os.path.join(OUT_DIR, f"accuracy_{args.device.lower().replace('.', '')}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)

    print(f"\n{'variant':<11}{'acc':>8}{'macroF1':>9}{'agree':>8}{'filter':>8}")
    for k, r in results.items():
        print(f"{k:<11}{r['accuracy']:8.4f}{r['macro_f1']:9.4f}"
              f"{r.get('top1_agreement_vs_pytorch', 1):8.4f}{r.get('filter_decision_agreement', 1):8.4f}")
    print("\n逐類別召回（pytorch / ov_int8 / Δpp）")
    for i in range(17):
        a, b = results["pytorch"]["per_class_recall"][i], results["ov_int8"]["per_class_recall"][i]
        print(f"  {i:2d} {names[i]:<10} {a:6.3f} {b:6.3f} {100 * (b - a):+6.1f}")
    print(f"\n→ {path}")


if __name__ == "__main__":
    main()
