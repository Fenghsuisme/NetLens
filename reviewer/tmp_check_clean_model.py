# tmp_check_clean_model.py —— 把模型接上去,量真正的殘留誤報
from testset_parser import parse_testset
from transport_layer import process
from collections import Counter
from model_runner import classify_snippet

s = [x for x in parse_testset() if x["category"] == "clean"]

fired = filtered = residual = 0
surv = Counter()

for x in s:
    r = process(x["code"], x["lang"], rules_path="rules")
    fs = r["to_codebert"]
    if not fs:
        continue
    fired += 1
    alive = []
    for f in fs:
        pred = classify_snippet(f["snippet"], f.get("semgrep_category"))
        if pred != "clean":
            alive.append(f)
    if alive:
        residual += 1
        for f in alive:
            surv[f.get("semgrep_rule", "?")] += 1
    else:
        filtered += 1

print(f"① Semgrep 誤報率 : {fired}/150 = {fired/150*100:.1f}%")
print(f"② 模型過濾率     : {filtered}/{fired} = {filtered/fired*100:.1f}%")
print(f"③ 殘留誤報率     : {residual}/150 = {residual/150*100:.1f}%")
print("\n模型濾不掉的規則:")
for k, v in surv.most_common(15):
    print(f"  {v:>4}  {k}")