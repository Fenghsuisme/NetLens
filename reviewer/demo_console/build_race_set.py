# -*- coding: utf-8 -*-
"""
build_race_set.py — 產生賽跑場景用的 data/race_set.json（測試集分層抽樣 152 筆：正常 24 + 16 類 × 8）

race_set.json 含測試集原始碼，未納入公開版控；需在有 test_code/real_test/testset_merged.txt 的機器上產生。
用法（reviewer/ 下）：python demo_console/build_race_set.py
"""
import json
import os
import random
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "scripts", "ov"))
sys.path.insert(0, HERE)
import ov_common as C
from build_funnel_data import LABEL_EN


def preview(code):
    """賽道下方跑馬燈顯示的一行：跳過 import / 括號等雜訊行"""
    for line in C.strip_comments(code).splitlines():
        s = line.strip()
        if s and not re.match(r"(import|from|#include|using|package|require|const .*require|<\?php|\}|\{)", s):
            return s[:90]
    return code.strip().splitlines()[0][:90]


def main():
    items, _ = C.load_testset()
    random.seed(42)
    by = {}
    for it in items:
        by.setdefault(it["label"], []).append(it)
    sel = []
    for lab in range(17):
        sel += random.sample(by[lab], 24 if lab == 0 else 8)
    random.shuffle(sel)
    out = [{"code": it["code"], "label": it["label"], "label_en": LABEL_EN[it["label"]],
            "lang": it["lang"], "preview": preview(it["code"])} for it in sel]
    path = os.path.join(HERE, "data", "race_set.json")
    json.dump({"source": "test_code/real_test/testset_merged.txt (stratified, seed 42)", "items": out},
              open(path, "w", encoding="utf-8"), ensure_ascii=False)
    print(f"{len(out)} 筆 → {path}")


if __name__ == "__main__":
    main()
