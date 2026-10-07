import subprocess
import json
import os
import sys

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
        if os.path.exists(OUTPUT_FILE) and not all_final_results.get(lang_key):
            load_existing_results()
        all_final_results[lang_key] = []
        return

    print(f"   🚨 警告！Semgrep 成功命中 {len(findings)} 個漏洞：")
    
    file_findings = []
    
    for i, match in enumerate(findings, 1):
        rule_id = match.get("check_id", "unknown")
        message = match.get("extra", {}).get("message", "")
        line = match.get("start", {}).get("line", "??")
        
        extra = match.get("extra", {})
        metadata = extra.get("metadata", {})
        
        cwe_list = ["未標記"]
        
        if "cwe" in metadata:
            cwe_list = metadata["cwe"]
        elif "semgrep.dev" in metadata:
            rule_meta = metadata.get("semgrep.dev", {}).get("rule", {}).get("metadata", {})
            if "cwe" in rule_meta:
                cwe_list = rule_meta["cwe"]
                
        print(f"   [{i}] 行數: 第 {line} 行")
        print(f"      🔹 規則 ID: {rule_id}")
        print(f"      🔹 对照 CWE: {cwe_list}")
        print(f"      🔹 漏洞訊息: {message}")
        print()

        file_findings.append({
            "index": i,
            "line": line,
            "rule_id": rule_id,
            "cwe": cwe_list,
            "message": message
        })
        
    all_final_results[lang_key] = file_findings

def load_existing_results():
    global all_final_results
    if os.path.exists(OUTPUT_FILE):
        try:
            with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
                content = f.read()
                if "SEMGREP_RESULTS = " in content:
                    json_str = content.split("SEMGREP_RESULTS = ")[1].strip()
                    all_final_results = json.loads(json_str)
        except Exception:
            pass 

# =============================================================================
# 🌟 主程式（已新增 TypeScript 測試配置與動態選單長度）
# =============================================================================
if __name__ == "__main__":
    print("=" * 60)
    print("🚀 Semgrep 自訂規則精準測試（互動選單版）")
    print("=" * 60)
    
    # 先載入歷史掃描結果，避免單獨測試時把別的紀錄覆蓋掉
    load_existing_results()

    # 定義所有支援的語言配置對照清單（已加入 TypeScript）
    lang_options = [
        {"name": "Python", "key": "python", "path": os.path.join(TEST_CODE_DIR, "test.py"), "rule": "python.yml"},
        {"name": "JavaScript", "key": "javascript", "path": os.path.join(TEST_CODE_DIR, "test.js"), "rule": "javascript.yml"},
        {"name": "TypeScript", "key": "typescript", "path": os.path.join(TEST_CODE_DIR, "test.ts"), "rule": "typescript.yml"},
        {"name": "Java", "key": "java", "path": os.path.join(TEST_CODE_DIR, "Test.java"), "rule": "java.yml"},
        {"name": "C++", "key": "cpp", "path": os.path.join(TEST_CODE_DIR, "test.cpp"), "rule": "cpp.yml"},
        {"name": "C", "key": "c", "path": os.path.join(TEST_CODE_DIR, "test.c"), "rule": "c.yml"},
        {"name": "C#", "key": "csharp", "path": os.path.join(TEST_CODE_DIR, "test.cs"), "rule": "csharp.yml"},
        {"name": "PHP", "key": "php", "path": os.path.join(TEST_CODE_DIR, "test.php"), "rule": "php.yml"},
    ]

    # 1. 輸出選單讓使用者觀看
    print("請選擇你要執行的測試項目：")
    for idx, lang in enumerate(lang_options, 1):
        print(f"   [{idx}] 單獨測試 {lang['name']} ({lang['key']})")
    print(f"   [{len(lang_options) + 1}] 執行所有語言測試")
    print("-" * 60)

    # 2. 獲取使用者輸入並進行防呆判定
    try:
        choice_input = input("請輸入項目數字 (按 Enter 預設執行全部): ").strip()
        
        # 預設行為（直接按 Enter）
        if not choice_input:
            user_choice = len(lang_options) + 1
        else:
            user_choice = int(choice_input)
            
        if user_choice < 1 or user_choice > (len(lang_options) + 1):
            print("❌ 輸入錯誤：數字超出範圍，程式結束。")
            sys.exit(1)
            
    except ValueError:
        print("❌ 輸入錯誤：請輸入有效的整數數字，程式結束。")
        sys.exit(1)

    print("=" * 60)

    # 3. 根據使用者的數字選擇，啟動對應測試流程
    if user_choice <= len(lang_options):
        # 使用者選擇了單一語言
        chosen = lang_options[user_choice - 1]
        print(f"🎯 已指定單獨測試項目: [{chosen['name']}]")
        test_file(chosen["path"], chosen["rule"], chosen["key"])
    else:
        # 使用者選擇了測試全部
        print("📋 執行 [所有語言] 完整測試...")
        for lang in lang_options:
            test_file(lang["path"], lang["rule"], lang["key"])
    
    print("=" * 60)
    
    # ── 5. 將結果寫入到 semgrep_test_results.py ─────────────────
    print(f"💾 正在將掃描結果更新至檔案: {OUTPUT_FILE} ...")
    try:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write("# -*- coding: utf-8 -*-\n")
            f.write("\"\"\"\n")
            f.write("此檔案由 test_semgrep_only.py 自動生成。\n")
            f.write("包含了自訂 Semgrep 規則的最新測試精準命中結果。\n")
            f.write("\"\"\"\n\n")
            f.write("SEMGREP_RESULTS = ")
            f.write(json.dumps(all_final_results, indent=4, ensure_ascii=False))
            f.write("\n")
        print(f"✅ 檔案儲存成功！")
    except Exception as e:
        print(f"❌ 寫入檔案時發生錯誤: {e}")
    print("=" * 60)