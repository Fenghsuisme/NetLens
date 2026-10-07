# -*- coding: utf-8 -*-
"""
rule_experiment.py — Semgrep 規則三組對照實驗（Python）

實驗目的：
  Semgrep 召回率是整個兩階段架構的天花板（實測 62.7%）。
  本實驗比較三組規則配置，用數據決定該用哪組。

三組配置：
  A 自訂規則：rules/python.yml（現有的）
  B 官方規則：p/security-audit（線上）
  C 混合：兩者都跑，結果合併去重

三個指標（缺一不可）：
  ① 召回率  — Gemini A類樣本裡命中幾筆（越高越好，這是天花板）
  ② 誤報數  — 對安全程式碼誤報幾筆（越低越好）
  ③ 每檔finding數 — 影響使用體驗（太多會淹沒使用者）

註：混合組會做去重（同 行號+CWE 只算一次），
    否則自訂與官方規則命中同一處會重複計數，數字失真。

執行：python rule_experiment.py
"""
import os
import re
import sys
from collections import defaultdict, Counter

# 已移入子目錄，需往上一層才能 import 到 reviewer/ 下的模組
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from transport_layer import run_semgrep, _normalize_cwe
from core.config_loader import normalize_label, get_category, cwe_to_category

TEST_FILE = "test_code/real_test/security_training_dataset_v1.txt"
REPORT = "dataset/rule_experiment_report.txt"
LANG = "python"

# 三組配置
CONFIGS = {
    "A_自訂": "rules/python.yml",
    "B_官方": "p/security-audit",
    # C 組在程式裡合併 A+B
}

# A 類 10 種的 label
A_CLASS_LABELS = {1, 2, 3, 6, 7, 8, 9, 10, 11, 12}

LABEL_NAMES = {
    0: "正常程式碼", 1: "指令注入", 2: "SQL 注入", 3: "程式碼執行",
    4: "資料外洩", 5: "後門", 6: "弱加密", 7: "硬編碼密碼",
    8: "路徑遊走", 9: "不安全反序列化", 10: "跨站腳本", 11: "原型污染",
    12: "惡意套件",
}

# ── 誤報測試樣本：安全但含敏感關鍵字的程式碼 ──
SAFE_SAMPLES = [
    ("參數化查詢", '''def get_user(request):
    user_id = request.args.get('id')
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchall()'''),
    ("ORM查詢", '''def get_user(request):
    user_id = request.args.get('id')
    return User.objects.filter(id=user_id).first()'''),
    ("subprocess無shell", '''def list_files():
    subprocess.run(["ls", "-la"], shell=False)'''),
    ("白名單驗證", '''def service(request):
    action = request.args.get('action')
    if action not in ['start', 'stop', 'restart']:
        raise ValueError("invalid action")
    subprocess.run(["systemctl", action, "nginx"])'''),
    ("bcrypt加密", '''def hash_password(pwd):
    import bcrypt
    return bcrypt.hashpw(pwd.encode(), bcrypt.gensalt())'''),
    ("固定路徑讀檔", '''def load_config():
    with open("/app/config/settings.json") as f:
        return json.load(f)'''),
    ("環境變數密碼", '''def connect():
    password = os.environ.get("DB_PASSWORD")
    return db.connect(user="root", password=password)'''),
]


def parse_gemini_python():
    """只取 Gemini 測試集裡的 Python A類樣本"""
    if not os.path.exists(TEST_FILE):
        print(f"❌ 找不到 {TEST_FILE}")
        return []
    content = open(TEST_FILE, encoding="utf-8").read()
    items = []
    for block in content.split("---SPLIT---"):
        block = block.strip()
        if not block:
            continue
        lm = re.search(r"###LABEL:(\S+)", block)
        langm = re.search(r"###LANG:(\S+)", block)
        if not lm or not langm:
            continue
        if langm.group(1).strip().lower() != LANG:
            continue
        cm = re.search(r"```\w*\n(.*?)```", block, re.DOTALL)
        if cm:
            code = cm.group(1).strip()
        else:
            pos = block.find("###DESC:")
            if pos == -1:
                continue
            nl = block.find("\n", pos)
            code = block[nl:].strip() if nl != -1 else ""
        if len(code) < 30:
            continue
        canon = normalize_label(lm.group(1).strip())
        if not canon:
            continue
        label = get_category(canon)["label"]
        if label not in A_CLASS_LABELS:
            continue
        items.append((label, code))
    return items


def get_findings(code, rules_path):
    """跑 Semgrep，回傳 [(cwe, line)]"""
    findings = run_semgrep(code, LANG, rules_path)
    out = []
    for f in findings:
        cwe = f.get("cwe")
        line = f.get("start_line")
        if cwe and line:
            out.append((cwe, line))
    return out


def merge_findings(list_a, list_b):
    """混合組：合併並依 (cwe, line) 去重"""
    seen = set()
    out = []
    for item in list_a + list_b:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def hits_target(findings, target_label):
    """判斷 finding 裡有沒有命中目標類別"""
    for cwe, _ in findings:
        cat = cwe_to_category(cwe)
        if cat and get_category(cat)["label"] == target_label:
            return True
    return False


def main():
    items = parse_gemini_python()
    if not items:
        print("❌ 沒有 Python A類測試樣本")
        return

    print(f"Python A類樣本：{len(items)} 筆")
    print(f"安全樣本（測誤報）：{len(SAFE_SAMPLES)} 筆\n")
    print("開始實驗（官方規則首次執行會下載，請耐心等候）...\n")

    lines = []

    def log(s=""):
        print(s)
        lines.append(s)

    # ── 收集每組的結果 ──
    results = {}      # config_name -> {...}
    per_sample = []   # 逐筆記錄，供混合組使用

    for idx, (label, code) in enumerate(items, 1):
        row = {"label": label}
        for name, rules in CONFIGS.items():
            row[name] = get_findings(code, rules)
        row["C_混合"] = merge_findings(row["A_自訂"], row["B_官方"])
        per_sample.append(row)
        if idx % 5 == 0:
            print(f"  已處理 {idx}/{len(items)}")

    safe_results = []
    print("\n處理安全樣本...")
    for name_desc, code in SAFE_SAMPLES:
        row = {"desc": name_desc}
        for name, rules in CONFIGS.items():
            row[name] = get_findings(code, rules)
        row["C_混合"] = merge_findings(row["A_自訂"], row["B_官方"])
        safe_results.append(row)

    # ── 統計 ──
    all_configs = list(CONFIGS.keys()) + ["C_混合"]

    log("=" * 76)
    log("Semgrep 規則三組對照實驗（Python）")
    log("=" * 76)
    log(f"\n測試樣本：Gemini A類 {len(items)} 筆")
    log(f"安全樣本：{len(SAFE_SAMPLES)} 筆（測誤報）")

    log("\n" + "─" * 76)
    log("【指標 ①：召回率】命中目標漏洞類別的比例")
    log("─" * 76)
    recall_stat = {}
    for cfg in all_configs:
        hit = sum(1 for r in per_sample if hits_target(r[cfg], r["label"]))
        recall_stat[cfg] = hit
        log(f"  {cfg:<12} {hit:>3}/{len(items)} = {hit/len(items):>6.1%}")

    log("\n" + "─" * 76)
    log("【指標 ②：誤報】對安全程式碼的 finding 數")
    log("─" * 76)
    log(f"  {'安全樣本':<18} " + "".join(f"{c:>10}" for c in all_configs))
    fp_stat = defaultdict(int)
    for row in safe_results:
        line = f"  {row['desc']:<18} "
        for cfg in all_configs:
            n = len(row[cfg])
            fp_stat[cfg] += n
            line += f"{n:>10}"
        log(line)
    log(f"  {'總計':<18} " + "".join(f"{fp_stat[c]:>10}" for c in all_configs))

    log("\n" + "─" * 76)
    log("【指標 ③：每檔平均 finding 數】影響使用體驗")
    log("─" * 76)
    for cfg in all_configs:
        total_f = sum(len(r[cfg]) for r in per_sample)
        log(f"  {cfg:<12} 漏洞樣本平均 {total_f/len(items):>5.1f} 個/檔")

    log("\n" + "─" * 76)
    log("【各類別召回率對比】")
    log("─" * 76)
    log(f"  {'類別':<14} {'樣本':>4} " + "".join(f"{c:>10}" for c in all_configs))
    by_label = defaultdict(list)
    for r in per_sample:
        by_label[r["label"]].append(r)
    for label in sorted(by_label.keys()):
        rows = by_label[label]
        line = f"  {LABEL_NAMES[label]:<14} {len(rows):>4} "
        for cfg in all_configs:
            hit = sum(1 for r in rows if hits_target(r[cfg], r["label"]))
            line += f"{hit:>4}/{len(rows):<5}"
        log(line)

    log("\n" + "=" * 76)
    log("【結論建議】")
    log("=" * 76)
    best_recall = max(all_configs, key=lambda c: recall_stat[c])
    least_fp = min(all_configs, key=lambda c: fp_stat[c])
    log(f"  召回率最高：{best_recall}（{recall_stat[best_recall]/len(items):.1%}）")
    log(f"  誤報最少：{least_fp}（{fp_stat[least_fp]} 個）")
    log("")
    log("  判讀方式：")
    log("    召回率是架構天花板，優先考慮")
    log("    但誤報過多會淹沒使用者，且目前 CodeBERT 過濾誤報能力弱")
    log("    建議選『召回率明顯較高，且誤報未暴增』的那組")

    os.makedirs("dataset", exist_ok=True)
    with open(REPORT, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"\n✅ 報告：{REPORT}")


if __name__ == "__main__":
    main()