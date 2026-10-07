# -*- coding: utf-8 -*-
"""列出 Gemini 測試集的完整組成：類別 × 語言 分布"""
import os, re, sys
from collections import defaultdict, Counter
# 已移入子目錄，需往上一層才能 import 到 reviewer/ 下的模組
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.config_loader import normalize_label, get_category

TEST_FILE = "test_code/real_test/security_training_dataset_v1.txt"

content = open(TEST_FILE, encoding="utf-8").read()
grid = defaultdict(Counter)      # category -> lang -> count
unparsed = []
total = 0

for block in content.split("---SPLIT---"):
    block = block.strip()
    if not block:
        continue
    lm = re.search(r"###LABEL:(\S+)", block)
    langm = re.search(r"###LANG:(\S+)", block)
    if not lm:
        continue
    raw_label = lm.group(1).strip()
    lang = langm.group(1).strip().lower() if langm else "unknown"
    cm = re.search(r"```\w*\n(.*?)```", block, re.DOTALL)
    if not cm or len(cm.group(1).strip()) < 30:
        continue
    total += 1
    canon = normalize_label(raw_label)
    if not canon:
        unparsed.append(raw_label)
        continue
    info = get_category(canon)
    grid[(info["label"], info.get("name_zh", canon))][lang] += 1

langs = sorted({l for c in grid.values() for l in c})

print(f"Gemini 測試集總筆數：{total}\n")
print(f"{'label':<6} {'類別':<20} " + "".join(f"{l[:10]:>11}" for l in langs) + f"{'合計':>7}")
print("-" * (27 + 11 * len(langs) + 7))
for (label, zh) in sorted(grid.keys()):
    row = grid[(label, zh)]
    line = f"{label:<6} {zh:<20} "
    for l in langs:
        line += f"{row.get(l, 0):>11}"
    line += f"{sum(row.values()):>7}"
    print(line)

print("-" * (27 + 11 * len(langs) + 7))
tot_line = f"{'':6} {'合計':<20} "
for l in langs:
    tot_line += f"{sum(c.get(l,0) for c in grid.values()):>11}"
tot_line += f"{sum(sum(c.values()) for c in grid.values()):>7}"
print(tot_line)

if unparsed:
    print(f"\n無法對應的標籤：{Counter(unparsed)}")

# A 類 10 種的涵蓋狀況
A_CLASS = {1:"指令注入",2:"SQL注入",3:"程式碼執行",6:"弱加密",7:"硬編碼密碼",
           8:"路徑遊走",9:"不安全反序列化",10:"跨站腳本",11:"原型污染",12:"惡意套件"}
print(f"\n【A 類 10 種的測試樣本涵蓋】")
for label, name in A_CLASS.items():
    cnt = 0
    for (l, z), c in grid.items():
        if l == label:
            cnt = sum(c.values())
    mark = "✓" if cnt > 0 else "✗ 無樣本"
    print(f"  {label:>2} {name:<14} {cnt:>3} 筆  {mark}")