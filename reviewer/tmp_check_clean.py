# tmp_check_clean.py
from testset_parser import parse_testset
from transport_layer import process
from collections import Counter

s = [x for x in parse_testset() if x["category"] == "clean"]
print(f"clean 樣本 {len(s)} 筆\n")

fired = 0
rule_c, cwe_c = Counter(), Counter()
for x in s:
    r = process(x["code"], x["lang"], rules_path="rules")
    fs = r["to_codebert"] + r["semgrep_only"]
    if fs:
        fired += 1
    for f in r["to_codebert"]:
        rule_c[f.get("semgrep_rule", "?")] += 1
        cwe_c[f.get("semgrep_cwe")] += 1

print(f"觸發率(Semgrep 誤報率): {fired}/{len(s)} = {fired/len(s)*100:.1f}%\n")
print("誤報最多的規則:")
for k, v in rule_c.most_common(15):
    print(f"  {v:>4}  {k}")
print("\n依 CWE:")
for k, v in cwe_c.most_common():
    print(f"  {v:>4}  {k}")