# -*- coding: utf-8 -*-
"""
用 dataset_v3.csv 的真實資料測試 Semgrep 自訂規則的分類命中率（選項B：測分類正確）
每類抽樣 100 筆。改用 CWE 編號比對（最穩定，不受規則命名風格影響）。
"""
import subprocess
import json
import os
import tempfile
from collections import defaultdict

import pandas as pd

os.environ["PYTHONUTF8"] = "1"

# ── 設定 ──────────────────────────────────────────
RULES_DIR = "rules"
DATASET_PATH = "dataset/dataset_v3.csv"
SAMPLES_PER_CLASS = 100
RANDOM_SEED = 42

LANG_CONFIG = {
    "python":     {"rule": "python.yml",     "ext": ".py"},
    "javascript": {"rule": "javascript.yml", "ext": ".js"},
    "java":       {"rule": "java.yml",       "ext": ".java"},
    "php":        {"rule": "php.yml",         "ext": ".php"},
}

# 內部類別 → 對應的 CWE 編號（可接受多個，命中任一即算對）
# 依據你們的規則檔 metadata 中的 cwe 欄位
CATEGORY_CWE = {
    "command_injection":        ["CWE-78", "CWE-77"],
    "sql_injection":            ["CWE-89"],
    "code_execution":           ["CWE-94"],
    "data_exfiltration":        ["CWE-200", "CWE-918"],   # 資料外洩 ≈ 資訊暴露 / SSRF
    "backdoor":                 ["CWE-798", "CWE-306", "CWE-284", "CWE-863", "CWE-862"],
    "weak_cryptography":        ["CWE-328", "CWE-295"],
    "hardcoded_secret":         ["CWE-798"],
    "path_traversal":           ["CWE-22"],
    "insecure_deserialization": ["CWE-502"],
    "xss":                      ["CWE-79"],
    "prototype_pollution":      ["CWE-1321"],
    "malicious_import":         ["CWE-829", "CWE-94"],    # 惡意套件（規則若無對應會偏低）
}


def extract_cwes(metadata):
    """從一個 finding 的 metadata 取出 CWE 清單，容錯多種結構"""
    cwes = []
    if not isinstance(metadata, dict):
        return cwes
    if "cwe" in metadata:
        c = metadata["cwe"]
        cwes.extend(c if isinstance(c, list) else [c])
    if "semgrep.dev" in metadata:
        rule_meta = metadata.get("semgrep.dev", {}).get("rule", {}).get("metadata", {})
        if "cwe" in rule_meta:
            c = rule_meta["cwe"]
            cwes.extend(c if isinstance(c, list) else [c])
    return cwes


def normalize_cwe(cwe_str):
    """把 'CWE-89: SQL Injection' 這種格式正規化成 'CWE-89'"""
    s = str(cwe_str).upper().replace(" ", "")
    if s.startswith("CWE-"):
        # 取 CWE- 後的數字
        num = ""
        for ch in s[4:]:
            if ch.isdigit():
                num += ch
            else:
                break
        return f"CWE-{num}" if num else s
    return s


def run_semgrep_on_code(code, lang):
    cfg = LANG_CONFIG.get(lang)
    if not cfg:
        return None
    rule_path = os.path.join(RULES_DIR, cfg["rule"])
    if not os.path.exists(rule_path):
        return None

    tmp_path = out_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=cfg["ext"],
                                         delete=False, encoding="utf-8") as tmp:
            tmp.write(code)
            tmp_path = tmp.name
        out_path = tmp_path + ".json"

        cmd = ["semgrep", "--config", rule_path, "--no-git-ignore",
               "--json", "--quiet", "--output", out_path, tmp_path]
        subprocess.run(cmd, capture_output=True, timeout=30)

        if not os.path.exists(out_path):
            return []
        with open(out_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        found_cwes = []
        for r in data.get("results", []):
            meta = r.get("extra", {}).get("metadata", {})
            found_cwes.extend(normalize_cwe(c) for c in extract_cwes(meta))
        return found_cwes
    except Exception:
        return []
    finally:
        for p in (tmp_path, out_path):
            if p and os.path.exists(p):
                os.unlink(p)


def is_correct(category, found_cwes):
    targets = [normalize_cwe(c) for c in CATEGORY_CWE.get(category, [])]
    return any(c in targets for c in found_cwes)


def main():
    if not os.path.exists(DATASET_PATH):
        print(f"❌ 找不到資料集：{DATASET_PATH}")
        return

    df = pd.read_csv(DATASET_PATH)
    print(f"載入資料集：{len(df)} 筆")

    df = df[df["label"] != 0]
    df = df[df["language"].isin(LANG_CONFIG.keys())]

    sampled = []
    for cat, group in df.groupby("category"):
        n = min(SAMPLES_PER_CLASS, len(group))
        sampled.append(group.sample(n=n, random_state=RANDOM_SEED))
    sample_df = pd.concat(sampled).reset_index(drop=True)
    print(f"抽樣後：{len(sample_df)} 筆（每類最多 {SAMPLES_PER_CLASS} 筆）\n")

    stats = defaultdict(lambda: {"total": 0, "hit": 0, "detected": 0})

    for idx, row in sample_df.iterrows():
        code = str(row["code"])
        lang = row["language"]
        cat  = row["category"]

        found = run_semgrep_on_code(code, lang)
        if found is None:
            continue

        stats[cat]["total"] += 1
        if found:
            stats[cat]["detected"] += 1
        if is_correct(cat, found):
            stats[cat]["hit"] += 1

        if (idx + 1) % 100 == 0:
            print(f"  已處理 {idx + 1}/{len(sample_df)} ...")

    print("\n" + "=" * 70)
    print("Semgrep 分類命中率報告（選項B：抓對 CWE）")
    print("=" * 70)
    print(f"{'類別':<24} {'抓對':<6} {'有抓到':<8} {'總數':<6} {'分類命中率':<10} {'偵測率'}")
    print("-" * 70)

    total_all = hit_all = detected_all = 0
    for cat in sorted(stats.keys()):
        v = stats[cat]
        t, h, d = v["total"], v["hit"], v["detected"]
        total_all += t; hit_all += h; detected_all += d
        hr = h / t if t else 0
        dr = d / t if t else 0
        print(f"{cat:<24} {h:<6} {d:<8} {t:<6} {hr:<10.0%} {dr:.0%}")

    print("-" * 70)
    if total_all:
        print(f"{'總計':<24} {hit_all:<6} {detected_all:<8} {total_all:<6} "
              f"{hit_all/total_all:<10.0%} {detected_all/total_all:.0%}")
    print("=" * 70)
    print("\n說明：")
    print("  分類命中率（選項B）＝ Semgrep 抓到且 CWE 對應到正確類別")
    print("  偵測率（選項A參考）＝ Semgrep 有抓到任何漏洞（不論 CWE 對錯）")
    print("\n注意：data_exfiltration / malicious_import 若命中率偏低，")
    print("      多半是規則檔尚無對應 CWE，屬預期現象，可列入待補規則清單。")


if __name__ == "__main__":
    main()