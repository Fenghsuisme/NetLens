# tools/check_cwe_coverage.py
import glob, re, json, sys
from transport_layer import A_CLASS_CWES

catalog = set(json.load(open("config/cwe_catalog.json")))   # 依實際結構調整

used = {}
for path in glob.glob("rules/*.yml"):
    txt = open(path, encoding="utf-8").read()
    for m in re.finditer(r"CWE-\d+", txt):
        used.setdefault(m.group(), set()).add(path)

print(f"{'CWE':<12}{'在A類':<8}{'在catalog':<10}來源")
for cwe in sorted(used, key=lambda x: int(x.split("-")[1])):
    a = "✓" if cwe in A_CLASS_CWES else "✗"
    c = "✓" if cwe in catalog else "✗"
    flag = "" if (a == "✓" and c == "✓") else "  ⚠️"
    src = ", ".join(sorted(p.split("/")[-1] for p in used[cwe]))
    print(f"{cwe:<12}{a:<8}{c:<10}{src}{flag}")