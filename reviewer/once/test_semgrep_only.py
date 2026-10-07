import subprocess
import json
import os

os.environ["PYTHONUTF8"] = "1"

# ── 設定路徑（因為你人在 reviewer 資料夾裡） ─────────────────
RULES_DIR = "rules"
TEST_CODE_DIR = "test_code"
OUTPUT_FILE = "semgrep_test_results.py"

# 用來儲存所有發現的漏洞，最後寫入檔案
all_final_results = {}

def run_semgrep_direct(target_file_path, rule_file_name):
    """
    不使用臨時檔，直接對實體測試檔案執行 Semgrep
    """
    rule_path = os.path.join(RULES_DIR, rule_file_name)
    
    if not os.path.exists(rule_path):
        print(f"❌ 找不到規則檔: {rule_path}，請確認是否已執行 python create_rules.py")
        return None

    if not os.path.exists(target_file_path):
        print(f"❌ 找不到測試檔案: {target_file_path}")
        return None

    try:
        # 直接拿實體檔案去跑掃描
        cmd = ["semgrep", "--config", rule_path, target_file_path, "--json", "--quiet"]
        process = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
        
        if process.returncode not in [0, 1]:
            print(f"❌ Semgrep 執行出錯: {process.stderr}")
            return None

        raw_output = process.stdout.strip()
        if not raw_output:
            return []
            
        result_json = json.loads(raw_output)
        return result_json.get("results", [])

    except FileNotFoundError:
        print("❌ 系統找不到 'semgrep' 指令")
        return None

def test_file(file_path, rule_file_name, lang_key):
    print(f"\n進行測試: {file_path}")
    print("-" * 60)
    
    findings = run_semgrep_direct(file_path, rule_file_name)

    if findings is None:
        print("   ⚠️ 測試未能完成，請修正上述錯誤。")
        return

    if not findings:
        print("   ✅ Semgrep 沒有抓到任何安全漏洞（或者新規則未命中）。")
        all_final_results[lang_key] = []
        return

    print(f"   🚨 警告！Semgrep 成功命中 {len(findings)} 個漏洞：")
    
    file_findings = []
    
    for i, match in enumerate(findings, 1):
        # 取得 Rule ID 
        rule_id = match.get("check_id", "unknown")
        message = match.get("extra", {}).get("message", "")
        line = match.get("start", {}).get("line", "??")
        
        # ── 萬能 CWE 安全提取器 ──
        extra = match.get("extra", {})
        metadata = extra.get("metadata", {})
        
        cwe_list = ["未標記"]
        
        # 嘗試路徑 1: 直接在 metadata.cwe
        if "cwe" in metadata:
            cwe_list = metadata["cwe"]
        # 嘗試路徑 2: 隱藏在 semgrep.dev 結構內
        elif "semgrep.dev" in metadata:
            rule_meta = metadata.get("semgrep.dev", {}).get("rule", {}).get("metadata", {})
            if "cwe" in rule_meta:
                cwe_list = rule_meta["cwe"]
                
        print(f"   [{i}] 行數: 第 {line} 行")
        print(f"      🔹 規則 ID: {rule_id}")
        print(f"      🔹 對照 CWE: {cwe_list}")
        print(f"      🔹 漏洞訊息: {message}")
        print()

        # 整理成結構化字典，準備存檔
        file_findings.append({
            "index": i,
            "line": line,
            "rule_id": rule_id,
            "cwe": cwe_list,
            "message": message
        })
        
    # 紀錄至全域字典中
    all_final_results[lang_key] = file_findings

if __name__ == "__main__":
    print("=" * 60)
    print("🚀 Semgrep 自訂規則獨立精準測試（多語言整合版）")
    print("=" * 60)
    
    # 1. 測試 Python
    py_path = os.path.join(TEST_CODE_DIR, "test.py")
    test_file(py_path, "python.yml", "python")

    # 2. 測試 JavaScript
    js_path = os.path.join(TEST_CODE_DIR, "test.js")
    test_file(js_path, "javascript.yml", "javascript")
    
    # 3. 測試 Java
    java_path = os.path.join(TEST_CODE_DIR, "Test.java")
    test_file(java_path, "java.yml", "java")
    
    # 4. 測試 C/C++ (全新加入✨)
    # 💡 對應小寫開頭的 test.cpp 檔案與 rules/cpp.yml 規則
    cpp_path = os.path.join(TEST_CODE_DIR, "test.cpp")
    test_file(cpp_path, "cpp.yml", "cpp")
    
    print("=" * 60)
    
    # ── 5. 將所有語言結果寫入到 semgrep_test_results.py ─────────────────
    print(f"💾 正在將各語言掃描結果寫入檔案: {OUTPUT_FILE} ...")
    try:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write("# -*- coding: utf-8 -*-\n")
            f.write("\"\"\"\n")
            f.write("此檔案由 test_semgrep_only.py 自動生成。\n")
            f.write("包含了自訂 Semgrep 規則的最新測試精準命中結果。\n")
            f.write("\"\"\"\n\n")
            f.write("SEMGREP_RESULTS = ")
            # 使用 indent 讓產生的 py 檔案排版漂亮、易讀
            f.write(json.dumps(all_final_results, indent=4, ensure_ascii=False))
            f.write("\n")
        print(f"✅ 檔案儲存成功！你可以直接在其他程式中使用 `from semgrep_test_results import SEMGREP_RESULTS` 讀取資料。")
    except Exception as e:
        print(f"❌ 寫入檔案時發生錯誤: {e}")
    print("=" * 60)