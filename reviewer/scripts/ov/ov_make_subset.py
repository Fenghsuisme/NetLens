# -*- coding: utf-8 -*-
"""
ov_make_subset.py — 產生 ov_eval_device.py 用的 subset.npz（測試集每 N 筆取 1，含 PyTorch 預測）

  python scripts/ov/ov_make_subset.py [--step 5] [--out subset.npz]
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ov_common as C
import ov_eval_accuracy as E

import numpy as np
from transformers import AutoTokenizer

ap = argparse.ArgumentParser()
ap.add_argument("--step", type=int, default=5)
ap.add_argument("--out", default="subset.npz")
a = ap.parse_args()

items, _ = C.load_testset()
items = items[::a.step]
enc = C.tokenize(AutoTokenizer.from_pretrained(C.BASE_MODEL), [i["code"] for i in items])
y = np.array([i["label"] for i in items])
pt = E.run_pytorch(enc).argmax(1)
np.savez(a.out, input_ids=enc["input_ids"], attention_mask=enc["attention_mask"], y=y, pt=pt)
print(f"{len(y)} 筆 → {a.out}")
