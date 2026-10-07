import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from reviewer.code_analyzer import analyze_code

# 測試案例定義
TEST_CASES = [
    ("test1_sql_python.py",   "SQL 注入"),
    ("test2_sql_php.php",     "SQL 注入"),
    ("test3_cmd_python.py",   "指令注入"),
    ("test4_cmd_java.java",   "指令注入"),
    ("test5_xss_js.js",       "XSS"),
    ("test6_path_php.php",    "路徑遊走"),
    ("test7_secret_java.java","硬編碼密碼"),
    ("test8_crypto_python.py","弱加密"),
    ("test9_exfil_js.js",     "資料外洩"),
    ("test10_backdoor_php.php","後門"),
]

TEST_DIR = "reviewer/test_code/chatgpt_test"

correct = 0
total = len(TEST_CASES)
results = []

print("=" * 60)
print("ChatGPT 生成程式碼測試")
print("=" * 60)

for filename, expected in TEST_CASES:
    path = os.path.join(TEST_DIR, filename)
    with open(path, "r", encoding="utf-8") as f:
        code = f.read()

    result = analyze_code(code, filename)
    s = result["summary"]
    codebert_category = s.get("codebert_category", "無")
    codebert_conf = s.get("codebert_confidence", 0)
    semgrep_count = s.get("high_priority_count", 0)

    # 判斷是否正確
    codebert_correct = codebert_category == expected
    semgrep_correct = semgrep_count > 0

    if codebert_correct:
        correct += 1

    results.append({
        "檔案": filename,
        "預期類別": expected,
        "CodeBERT判斷": codebert_category,
        "信心度": f"{codebert_conf:.1%}" if codebert_conf else "N/A",
        "CodeBERT正確": "✅" if codebert_correct else "❌",
        "Semgrep命中": "✅" if semgrep_correct else "❌",
    })

print(f"\n{'檔案':<25} {'預期':<12} {'CodeBERT':<12} {'信心度':<8} {'CB正確':<8} {'Semgrep'}")
print("-" * 80)
for r in results:
    print(f"{r['檔案']:<25} {r['預期類別']:<12} {r['CodeBERT判斷']:<12} {r['信心度']:<8} {r['CodeBERT正確']:<8} {r['Semgrep命中']}")

print(f"\nCodeBERT 命中率：{correct}/{total}（{correct/total:.1%}）")
print(f"Semgrep 命中率：{sum(1 for r in results if r['Semgrep命中'] == '✅')}/{total}")