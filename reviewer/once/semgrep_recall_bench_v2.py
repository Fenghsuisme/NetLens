# -*- coding: utf-8 -*-
"""
semgrep_recall_bench_v3.py — Semgrep 規則組召回率 / 誤報率基準比較

v3 修正：改用「以 ###LABEL 切分區塊」的解析方式，不再依賴 ``` 圍欄。
標頭之後的所有內容都視為程式碼，圍欄若存在則自動剝除。

用法：
    python semgrep_recall_bench_v3.py test_code/real_test/security_training_dataset_v1.txt
"""

import csv
import json
import os
import re
import subprocess
import sys
import tempfile
from collections import defaultdict, Counter

# ──────────────────────────────────────────────────────────────
# 設定區
# ──────────────────────────────────────────────────────────────
OWN_RULES = "rules/"

CONFIGS = {
    "自己的規則":        [f"--config={OWN_RULES}"],
    "官方 security":     ["--config=p/security-audit"],
    "官方 secrets":      ["--config=p/secrets"],
    "官方 owasp":        ["--config=p/owasp-top-ten"],
    "官方全部":          ["--config=p/security-audit",
                          "--config=p/secrets",
                          "--config=p/owasp-top-ten"],
    "自己的 + 官方全部": [f"--config={OWN_RULES}",
                          "--config=p/security-audit",
                          "--config=p/secrets",
                          "--config=p/owasp-top-ten"],
}

A_CLASS = {
    "sql_injection":            "SQL 注入",
    "sqli":                     "SQL 注入",
    "command_injection":        "指令注入",
    "cmd_injection":            "指令注入",
    "os_command_injection":     "指令注入",
    "code_execution":           "程式碼執行",
    "code_injection":           "程式碼執行",
    "unsafe_eval":              "程式碼執行",
    "eval_injection":           "程式碼執行",
    "xss":                      "跨站腳本",
    "cross_site_scripting":     "跨站腳本",
    "path_traversal":           "路徑遊走",
    "directory_traversal":      "路徑遊走",
    "weak_crypto":              "弱加密",
    "weak_cryptography":        "弱加密",
    "weak_hash":                "弱加密",
    "hardcoded_secret":         "硬編碼密碼",
    "hardcoded_credential":     "硬編碼密碼",
    "hardcoded_credentials":    "硬編碼密碼",
    "hardcoded_password":       "硬編碼密碼",
    "insecure_deserialization": "不安全反序列化",
    "deserialization":          "不安全反序列化",
    "unsafe_deserialization":   "不安全反序列化",
    "ssrf":                     "SSRF",
    "prototype_pollution":      "原型污染",
}

SAFE_LABELS = {"safe", "normal", "benign", "clean", "secure",
               "no_vuln", "none", "safe_code", "not_vulnerable"}

LANG_EXT = {
    "python": ".py", "py": ".py",
    "javascript": ".js", "js": ".js", "node": ".js", "nodejs": ".js",
    "typescript": ".ts", "ts": ".ts",
    "php": ".php",
    "java": ".java",
    "go": ".go", "golang": ".go",
    "ruby": ".rb", "rb": ".rb",
    "csharp": ".cs", "cs": ".cs", "c#": ".cs",
    "c": ".c", "cpp": ".cpp", "c++": ".cpp",
}

FENCE = re.compile(r"^\s*```")


def read_text(path):
    for enc in ("utf-8-sig", "utf-8", "cp950", "big5", "latin-1"):
        try:
            with open(path, encoding=enc) as f:
                return f.read()
        except UnicodeDecodeError:
            continue
    sys.exit(f"無法解碼檔案：{path}")


def parse_blocks(text):
    """以 ###LABEL 切分區塊。標頭後的其餘內容全視為程式碼，圍欄自動剝除。"""
    lines = text.splitlines()
    starts = [i for i, l in enumerate(lines) if l.strip().startswith("###LABEL:")]
    if not starts:
        return []

    samples = []
    for n, si in enumerate(starts):
        ei = starts[n + 1] if n + 1 < len(starts) else len(lines)
        block = lines[si:ei]

        label = block[0].strip()[len("###LABEL:"):].strip().lower()
        lang = desc = ""
        code_start = 1
        for j in range(1, len(block)):
            s = block[j].strip()
            if s.startswith("###LANG:"):
                lang = s[len("###LANG:"):].strip().lower()
                code_start = j + 1
            elif s.startswith("###DESC:"):
                desc = s[len("###DESC:"):].strip()
                code_start = j + 1
            elif s.startswith("###"):
                code_start = j + 1          # 其他未知標頭一併略過
            else:
                break

        body = [l for l in block[code_start:] if not FENCE.match(l)]
        code = "\n".join(body).strip()
        if not code:
            continue

        samples.append({"id": n + 1, "label": label, "lang": lang,
                        "desc": desc, "code": code})
    return samples


def materialise(samples, workdir):
    mapping = {}
    unsupported = Counter()
    for s in samples:
        ext = LANG_EXT.get(s["lang"])
        if ext is None:
            unsupported[s["lang"] or "(空白)"] += 1
            continue
        fname = f"s{s['id']:04d}{ext}"
        with open(os.path.join(workdir, fname), "w", encoding="utf-8") as f:
            f.write(s["code"])
        mapping[fname] = s
    return mapping, unsupported


def run_semgrep(config_args, workdir):
    cmd = ["semgrep", "--json", "--quiet", "--no-git-ignore",
           "--metrics=off", "--timeout=15", *config_args, workdir]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=2400)
    except FileNotFoundError:
        sys.exit("找不到 semgrep 指令。")
    except subprocess.TimeoutExpired:
        print("  ⚠ 逾時，這組跳過")
        return None

    if not proc.stdout.strip():
        print(f"  ⚠ 無輸出。stderr：{proc.stderr[:500]}")
        return None
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        print(f"  ⚠ JSON 解析失敗。stderr：{proc.stderr[:500]}")
        return None

    hits = defaultdict(list)
    for r in data.get("results", []):
        hits[os.path.basename(r.get("path", ""))].append(r.get("check_id", "?"))
    return dict(hits)


def summarise(hits, mapping):
    hit_n = n = fp_n = safe_n = 0
    lang_stat = defaultdict(lambda: [0, 0])
    type_stat = defaultdict(lambda: [0, 0])
    rule_hits = Counter()
    misses = []

    for fname, s in mapping.items():
        label = s["label"]
        found = hits.get(fname) or []
        got = bool(found)

        if label in SAFE_LABELS:
            safe_n += 1
            if got:
                fp_n += 1
            continue
        if label not in A_CLASS:
            continue

        vt = A_CLASS[label]
        n += 1
        lang_stat[s["lang"]][1] += 1
        type_stat[vt][1] += 1
        if got:
            hit_n += 1
            lang_stat[s["lang"]][0] += 1
            type_stat[vt][0] += 1
            for rid in set(found):
                rule_hits[rid] += 1
        else:
            misses.append(s)

    return {
        "recall": hit_n / n if n else 0.0,
        "hit": hit_n, "total": n,
        "fp_rate": fp_n / safe_n if safe_n else None,
        "fp": fp_n, "safe": safe_n,
        "lang": lang_stat, "type": type_stat,
        "rules": rule_hits, "misses": misses,
    }


def main():
    if len(sys.argv) < 2:
        sys.exit("用法：python semgrep_recall_bench_v3.py <測試集路徑>")
    path = sys.argv[1]
    if not os.path.exists(path):
        sys.exit(f"找不到檔案：{path}")

    samples = parse_blocks(read_text(path))
    if not samples:
        sys.exit("解析不到任何樣本。")

    print(f"解析到 {len(samples)} 筆樣本\n")

    print("─" * 62)
    print("標籤分布")
    print("─" * 62)
    unclassified = []
    for lb, c in Counter(s["label"] for s in samples).most_common():
        if lb in A_CLASS:
            tag = f"A 類 → {A_CLASS[lb]}"
        elif lb in SAFE_LABELS:
            tag = "正常樣本（算誤報率）"
        else:
            tag = "未歸類（不計入）"
            unclassified.append(lb)
        print(f"  {lb:<28}{c:>5}   {tag}")
    print()
    print("語言分布：", dict(Counter(s["lang"] for s in samples)))
    if unclassified:
        print(f"\n⚠ 未歸類標籤：{unclassified}")
        print("  若其中有 A 類，請加進腳本上方的 A_CLASS")
    print()

    workdir = tempfile.mkdtemp(prefix="semgrep_bench_")
    mapping, unsupported = materialise(samples, workdir)
    print(f"寫出 {len(mapping)} 個檔案 → {workdir}")
    if unsupported:
        print(f"跳過（語言不支援）：{dict(unsupported)}")
    a_n = sum(1 for s in mapping.values() if s["label"] in A_CLASS)
    sf_n = sum(1 for s in mapping.values() if s["label"] in SAFE_LABELS)
    print(f"A 類樣本 {a_n} 筆　正常樣本 {sf_n} 筆\n")

    if a_n == 0:
        sys.exit("A 類樣本 0 筆，請對照標籤分布調整 A_CLASS。")

    results = {}
    for name, args in CONFIGS.items():
        print(f"跑：{name}")
        hits = run_semgrep(args, workdir)
        if hits is None:
            continue
        r = summarise(hits, mapping)
        results[name] = r
        fp = f"　誤報 {r['fp']}/{r['safe']} = {r['fp_rate']:.1%}" if r["fp_rate"] is not None else ""
        print(f"  → 召回 {r['hit']}/{r['total']} = {r['recall']:.1%}{fp}\n")

    if not results:
        sys.exit("所有規則組都失敗了")

    lines = []

    def emit(s=""):
        print(s)
        lines.append(s)

    emit("=" * 74)
    emit("規則組比較")
    emit("=" * 74)
    emit(f"{'規則組':<22}{'命中':>7}{'總數':>7}{'召回率':>10}{'誤報率':>10}")
    emit("-" * 74)
    for name, r in results.items():
        fp = f"{r['fp_rate']:.1%}" if r["fp_rate"] is not None else "n/a"
        emit(f"{name:<22}{r['hit']:>7}{r['total']:>7}{r['recall']:>9.1%}{fp:>10}")
    emit()

    best = max(results, key=lambda k: results[k]["recall"])
    emit(f"召回最佳：{best}（{results[best]['recall']:.1%}）")
    emit()
    r = results[best]

    emit("=" * 74)
    emit(f"逐語言召回率 — {best}")
    emit("=" * 74)
    emit(f"{'語言':<16}{'命中':>8}{'總數':>8}{'召回率':>10}")
    emit("-" * 74)
    for lang, (h, t) in sorted(r["lang"].items(), key=lambda x: x[1][0] / max(x[1][1], 1)):
        emit(f"{lang:<16}{h:>8}{t:>8}{h/max(t,1):>9.1%}")
    emit()

    emit("=" * 74)
    emit(f"逐漏洞類型召回率 — {best}")
    emit("=" * 74)
    emit(f"{'類型':<22}{'命中':>8}{'總數':>8}{'召回率':>10}")
    emit("-" * 74)
    for vt, (h, t) in sorted(r["type"].items(), key=lambda x: x[1][0] / max(x[1][1], 1)):
        flag = "  ← 優先補" if h / max(t, 1) < 0.6 else ""
        emit(f"{vt:<22}{h:>8}{t:>8}{h/max(t,1):>9.1%}{flag}")
    emit()

    emit("=" * 74)
    emit(f"命中次數最多的規則 — {best}（前 15）")
    emit("=" * 74)
    for rid, c in r["rules"].most_common(15):
        emit(f"  {c:>4}  {rid}")
    emit()

    emit("=" * 74)
    emit(f"未命中清單 — {best}（{len(r['misses'])} 筆）")
    emit("=" * 74)
    for s in r["misses"]:
        emit(f"  #{s['id']:<5}{s['lang']:<12}{A_CLASS.get(s['label'], s['label'])}")
    emit()

    with open("bench_report.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    with open("bench_misses.csv", "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["id", "language", "label", "desc", "code"])
        for s in r["misses"]:
            w.writerow([s["id"], s["lang"], s["label"], s.get("desc", ""), s["code"]])

    print("✅ bench_report.txt")
    print("✅ bench_misses.csv")
    print(f"   樣本檔：{workdir}")


if __name__ == "__main__":
    main()