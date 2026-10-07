from testset_parser import parse_testset
from transport_layer import process

s = [x for x in parse_testset() if x["category"] == "weak_cryptography"][:20]
for x in s:
    r = process(x["code"], x["lang"], rules_path="rules")
    for f in r["to_codebert"]:
        if f.get("semgrep_cwe") == "CWE-89":
            print("=== rule:", f.get("semgrep_rule"))
            print(f.get("snippet", "")[:300])
            print()
            break