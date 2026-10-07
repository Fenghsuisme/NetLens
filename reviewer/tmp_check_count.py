# tmp_check_count.py
from testset_parser import parse_testset

samples = parse_testset(verbose=True)
print("總筆數：", len(samples))

from collections import Counter
print("\n依類別：")
for cat, n in Counter(s["category"] for s in samples).most_common():
    print(f"  {cat:30s} {n}")

print("\n依語言：")
for lang, n in Counter(s["lang"] for s in samples).most_common():
    print(f"  {lang:15s} {n}")