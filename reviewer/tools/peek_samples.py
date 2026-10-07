# -*- coding: utf-8 -*-
"""印出指定類別的樣本程式碼，供設計規則參考"""
import os, sys
# 已移入子目錄，需往上一層才能 import 到 reviewer/ 下的模組
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from testset_parser import parse_testset
from core.config_loader import get_category

target = sys.argv[1] if len(sys.argv) > 1 else "prototype_pollution"
n_per_lang = int(sys.argv[2]) if len(sys.argv) > 2 else 1

info = get_category(target)
items = parse_testset(labels={info["label"]})

by_lang = {}
for it in items:
    by_lang.setdefault(it["lang"], []).append(it)

for lang in sorted(by_lang):
    for it in by_lang[lang][:n_per_lang]:
        print("=" * 74)
        print(f"【{lang}】{it['desc'][:90]}")
        print("=" * 74)
        print(it["code"][:1400])
        print()