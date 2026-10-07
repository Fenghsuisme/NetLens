import sys
import os
import re
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# 已移入子目錄，需往上一層才能 import 到 reviewer/ 下的模組
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from code_analyzer import analyze_code

# ── 標籤對應中文 ──────────────────────────────────
LABEL_MAP = {
    "sql_injection":             "SQL 注入",
    "command_injection":         "指令注入",
    "xss":                       "XSS",
    "hardcoded_secret":          "硬編碼密碼",
    "hardcoded_credential":      "硬編碼密碼",
    "data_exfiltration":         "資料外洩",
    "data_leakage":              "資料外洩",
    "weak_cryptography":         "弱加密",
    "weak_crypto":               "弱加密",
    "path_traversal":            "路徑遊走",
    "backdoor":                  "後門",
    "backdoor_debug":            "後門",
    "debug_backdoor":            "後門",
    "code_execution":            "程式碼執行",
    "dynamic_code_exec":         "程式碼執行",
    "unsafe_eval":               "程式碼執行",
    "insecure_deserialization":  "不安全反序列化",
    "unsafe_deserialization":    "不安全反序列化",
    "prototype_pollution":       "原型污染",
    "malicious_import":          "惡意套件",
    "clean":                     "正常程式碼",
}

EXT_MAP = {
    "python":     ".py",
    "javascript": ".js",
    "php":        ".php",
    "java":       ".java",
    "typescript": ".ts",
}


# ── 解析單一檔案 ──────────────────────────────────
def parse_file(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    blocks = content.split("---SPLIT---")
    samples = []

    for block in blocks:
        block = block.strip()
        if not block:
            continue

        label_match = re.search(r"###LABEL:(\S+)", block)
        lang_match  = re.search(r"###LANG:(\S+)", block)
        desc_match  = re.search(r"###DESC:(.+)", block)
        code_match  = re.search(r"```\w*\n(.*?)```", block, re.DOTALL)

        if not (label_match and lang_match):
            continue

        label = label_match.group(1).strip().lower()
        lang  = lang_match.group(1).strip().lower()
        desc  = desc_match.group(1).strip() if desc_match else ""

        if code_match:
            code = code_match.group(1).strip()
        else:
            desc_pos = block.find("###DESC:")
            if desc_pos == -1:
                continue
            desc_line_end = block.find("\n", desc_pos)
            if desc_line_end == -1:
                continue
            code = block[desc_line_end:].strip()

        if len(code) < 30:
            continue

        samples.append({
            "label":    label,
            "lang":     lang,
            "desc":     desc,
            "code":     code,
            "expected": LABEL_MAP.get(label, label),
        })

    return samples


# ── 批次測試 ──────────────────────────────────────
def run_tests(samples, source_name):
    results = []
    total = len(samples)

    print(f"\n{'='*60}")
    print(f"測試來源：{source_name}（共 {total} 筆）")
    print(f"{'='*60}")

    for i, sample in enumerate(samples, 1):
        ext      = EXT_MAP.get(sample["lang"], ".py")
        filename = f"test_{i}{ext}"

        result   = analyze_code(sample["code"], filename)
        s        = result["summary"]

        cb_cat   = s.get("codebert_category", "無")
        cb_conf  = s.get("codebert_confidence", 0) or 0
        sg_hit   = s.get("high_priority_count", 0) > 0
        cb_ok    = cb_cat == sample["expected"]

        results.append({
            "編號":        i,
            "來源":        source_name,
            "語言":        sample["lang"],
            "預期":        sample["expected"],
            "CodeBERT":   cb_cat,
            "信心度":      cb_conf,
            "CB正確":      cb_ok,
            "Semgrep命中": sg_hit,
            "描述":        sample["desc"][:30],
        })

        cb_icon = "✅" if cb_ok else "❌"
        sg_icon = "✅" if sg_hit else "➖"
        print(f"[{i:3d}] {sample['lang']:<12} 預期:{sample['expected']:<12} "
              f"CB:{cb_cat:<12} {cb_conf:.0%} {cb_icon} Semgrep:{sg_icon}")

    return results


# ── 統計報告 ──────────────────────────────────────
def print_summary(all_results):
    total = len(all_results)
    cb_ok = sum(1 for r in all_results if r["CB正確"])
    sg_ok = sum(1 for r in all_results if r["Semgrep命中"])

    print(f"\n{'='*60}")
    print(f"總體結果（共 {total} 筆）")
    print(f"{'='*60}")
    print(f"CodeBERT 命中率：{cb_ok}/{total}（{cb_ok/total:.1%}）")
    print(f"Semgrep  命中率：{sg_ok}/{total}（{sg_ok/total:.1%}）")

    by_label = defaultdict(lambda: {"total": 0, "cb_ok": 0, "sg_ok": 0})
    for r in all_results:
        lbl = r["預期"]
        by_label[lbl]["total"]  += 1
        by_label[lbl]["cb_ok"]  += int(r["CB正確"])
        by_label[lbl]["sg_ok"]  += int(r["Semgrep命中"])

    print(f"\n各類別 CodeBERT 命中率：")
    print(f"{'類別':<16} {'命中':<6} {'總數':<6} {'命中率'}")
    print("-" * 40)
    for lbl, v in sorted(by_label.items()):
        rate = v["cb_ok"] / v["total"] if v["total"] else 0
        bar  = "█" * int(rate * 10)
        print(f"{lbl:<16} {v['cb_ok']:<6} {v['total']:<6} {rate:.0%} {bar}")

    errors = [r for r in all_results if not r["CB正確"]]
    if errors:
        print(f"\nCodeBERT 錯誤案例（{len(errors)} 筆）：")
        print(f"{'預期':<16} {'判斷為':<16} {'語言'}")
        print("-" * 48)
        for r in errors:
            print(f"{r['預期']:<16} {r['CodeBERT']:<16} {r['語言']}")


# ── 主程式 ────────────────────────────────────────
if __name__ == "__main__":
    FILES = {
        "Gemini": "reviewer/test_code/real_test/security_training_dataset_v1.txt",
        #"GPT":    "reviewer/test_code/real_test/security_training_examples_100.md",
    }

    os.makedirs("reviewer/test_code/real_test", exist_ok=True)

    all_results = []

    for source, filepath in FILES.items():
        if not os.path.exists(filepath):
            print(f"找不到檔案：{filepath}，跳過")
            continue

        samples = parse_file(filepath)
        print(f"{source}：解析到 {len(samples)} 筆有效樣本")

        results = run_tests(samples, source)
        all_results.extend(results)

    if all_results:
        print_summary(all_results)
    else:
        print("沒有任何測試結果")