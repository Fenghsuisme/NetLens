# -*- coding: utf-8 -*-
"""
ov_eval_device.py — 在任意 OpenVINO 裝置（如 Intel iGPU）上驗證準確率，只需 openvino + numpy

輸入為 WSL/Linux 端預先 tokenize 的 subset.npz（input_ids, attention_mask, y, pt=PyTorch 預測），
用於確認 GPU 上的 FP16 推論精度不影響判定。
  python ov_eval_device.py --npz subset.npz --device GPU.0 --models codebert_ov_fp32 codebert_ov_int8
"""
import argparse
import json
import os

import numpy as np
import openvino as ov


def macro_f1(y, p, n=17):
    f = []
    for c in range(n):
        tp = ((p == c) & (y == c)).sum(); fp = ((p == c) & (y != c)).sum(); fn = ((p != c) & (y == c)).sum()
        f.append(0.0 if tp == 0 else 2 * tp / (2 * tp + fp + fn))
    return float(np.mean(f))


ap = argparse.ArgumentParser()
ap.add_argument("--npz", default="subset.npz")
ap.add_argument("--device", default="GPU.0")
ap.add_argument("--models", nargs="+", required=True)
a = ap.parse_args()
d = np.load(a.npz)
core = ov.Core()
out = {"device": a.device, "device_name": core.get_property(a.device, "FULL_DEVICE_NAME"), "n": int(len(d["y"])),
       "pytorch": {"accuracy": float((d["pt"] == d["y"]).mean()), "macro_f1": macro_f1(d["y"], d["pt"])}}
for m in a.models:
    cm = core.compile_model(os.path.join(m, "openvino_model.xml"), a.device)
    req = cm.create_infer_request()
    preds = []
    for i in range(0, len(d["y"]), 8):
        r = req.infer({"input_ids": d["input_ids"][i:i + 8], "attention_mask": d["attention_mask"][i:i + 8]})
        preds.append(r[cm.output(0)].argmax(1))
    p = np.concatenate(preds)
    out[m] = {"accuracy": float((p == d["y"]).mean()), "macro_f1": macro_f1(d["y"], p),
              "top1_agreement_vs_pytorch": float((p == d["pt"]).mean())}
print(json.dumps(out, ensure_ascii=False, indent=1))
