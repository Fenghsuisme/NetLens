# -*- coding: utf-8 -*-
"""
針對命中率異常的類別，印出 Semgrep 實際回報的 CWE，用來校準對應表。
只抽每類 5 筆，快速看實際回報什麼。
"""
import subprocess, json, os, tempfile
from collections import Counter
import pandas as pd

os.environ["PYTHONUTF8"] = "1"

RULES_DIR = "rules"
DATASET_PATH = "dataset/dataset_v3.csv"

LANG_CONFIG = {
    "python":     {"rule": "python.yml",     "ext": ".py"},
    "javascript": {"rule": "javascript.yml", "ext": ".js"},
    "java":       {"rule": "java.yml",       "ext": ".java"},
    "php":        {"rule": "php.yml",         "ext": ".php"},
}

# 只針對這幾個「偵測率高但命中率低」的類別除錯
TARGET_CATEGORIES = [
    "prototype_pollution", "weak_cryptography", "xss",
    "hardcoded_secret", "malicious_import", "backdoor",
]

def extract_cwes(metadata):
    cwes = []
    if not isinstance(metadata, dict):
        return cwes
    if "cwe" in metadata:
        c = metadata["cwe"]
        cwes.extend(c if isinstance(c, list) else [c])
    return cwes

def run_semgrep(code, lang):
    cfg = LANG_CONFIG.get(lang)
    if not cfg:
        return []
    rule_path = os.path.join(RULES_DIR, cfg["rule"])
    if not os.path.exists(rule_path):
        return []
    tmp_path = out_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=cfg["ext"], delete=False, encoding="utf-8") as tmp:
            tmp.write(code); tmp_path = tmp.name
        out_path = tmp_path + ".json"
        subprocess.run(["semgrep","--config",rule_path,"--no-git-ignore","--json","--quiet","--output",out_path,tmp_path],
                       capture_output=True, timeout=30)
        if not os.path.exists(out_path): return []
        with open(out_path, encoding="utf-8") as f:
            data = json.load(f)
        cwes = []
        for r in data.get("results", []):
            meta = r.get("extra", {}).get("metadata", {})
            cwes.extend(str(c) for c in extract_cwes(meta))
        return cwes
    except Exception:
        return []
    finally:
        for p in (tmp_path, out_path):
            if p and os.path.exists(p): os.unlink(p)

df = pd.read_csv(DATASET_PATH)
df = df[df["language"].isin(LANG_CONFIG.keys())]

for cat in TARGET_CATEGORIES:
    sub = df[df["category"] == cat]
    if len(sub) == 0:
        print(f"\n【{cat}】資料集中沒有這個類別")
        continue
    sample = sub.sample(n=min(5, len(sub)), random_state=1)
    counter = Counter()
    for _, row in sample.iterrows():
        cwes = run_semgrep(str(row["code"]), row["language"])
        counter.update(cwes)
    print(f"\n【{cat}】(抽5筆) Semgrep 實際回報的 CWE：")
    if counter:
        for cwe, cnt in counter.most_common():
            print(f"    {cwe}: {cnt} 次")
    else:
        print("    （沒抓到任何東西）")

print("\n完成")