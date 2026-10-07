# tmp_check_crypto.py
from testset_parser import parse_testset
from transport_layer import process
from collections import Counter

s = [x for x in parse_testset() if x["category"] == "weak_cryptography"][:50]
c = Counter()
for x in s:
    r = process(x["code"], x["lang"], rules_path="rules")
    for f in r["to_codebert"]:
        c[("A類→模型", f.get("semgrep_cwe"))] += 1
    for f in r["semgrep_only"]:
        c[("B類→丟棄", f.get("cwe"))] += 1

for k, v in c.most_common():
    print(f"{v:>4}  {k[0]:<12} {k[1]}")