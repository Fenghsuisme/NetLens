# -*- coding: utf-8 -*-
"""
confidence_analysis.py — CodeBERT 信心分布分析

目的：搞清楚 v6 模型「對真漏洞」和「對安全但會被Semgrep誤報的程式碼」
      信心度是否分得開。這決定「信心門檻」到底有沒有效。

不產生任何成果宣稱，純粹是現狀調查：
  - 若真漏洞信心明顯高於誤報 → 門檻有依據
  - 若兩者信心重疊嚴重       → 門檻無效，誠實承認，只能靠重訓

測試樣本分兩組（都是已知答案）：
  組A 真漏洞：字串拼接SQL、os.system拼接、eval等 → 應判漏洞、高信心
  組B 安全但會被Semgrep誤報：參數化查詢、安全的subprocess等
     → 理想上CodeBERT應判「正常」，實際看它信心多少

執行：python confidence_analysis.py
"""
import os
import sys
import glob
import re

import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

# 已移入子目錄，需往上一層才能 import 到 reviewer/ 下的模組
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

MODEL_DIR = "models/codebert_v6"
BASE_MODEL = "microsoft/codebert-base"
STRIP_COMMENTS = True

LABEL_NAMES = {
    0: "正常程式碼", 1: "指令注入", 2: "SQL 注入", 3: "程式碼執行",
    4: "資料外洩", 5: "後門", 6: "弱加密", 7: "硬編碼密碼",
    8: "路徑遊走", 9: "不安全反序列化", 10: "跨站腳本", 11: "原型污染",
    12: "惡意套件", 13: "跨站請求偽造", 14: "SSRF",
    15: "不受限檔案上傳", 16: "權限控制缺陷",
}

# ── 組 A：真漏洞（已知答案 = 有漏洞）──
REAL_VULNS = [
    ("SQL-字串拼接", "sql_injection", '''def get_user(request):
    user_id = request.args.get('id')
    query = "SELECT * FROM users WHERE id=" + user_id
    cursor.execute(query)
    return cursor.fetchall()'''),
    ("SQL-f-string", "sql_injection", '''def search(request):
    name = request.args.get('name')
    cursor.execute(f"SELECT * FROM products WHERE name='{name}'")
    return cursor.fetchall()'''),
    ("指令注入-os.system", "command_injection", '''def ping(request):
    host = request.args.get('host')
    os.system("ping -c 1 " + host)'''),
    ("指令注入-subprocess-shell", "command_injection", '''def run(request):
    cmd = request.args.get('cmd')
    subprocess.call(cmd, shell=True)'''),
    ("程式碼執行-eval", "code_execution", '''def calc(request):
    expr = request.args.get('expr')
    result = eval(expr)
    return result'''),
    ("路徑遊走", "path_traversal", '''def download(request):
    filename = request.args.get('file')
    with open("/var/data/" + filename) as f:
        return f.read()'''),
    ("弱加密-md5", "weak_cryptography", '''def hash_password(pwd):
    import hashlib
    return hashlib.md5(pwd.encode()).hexdigest()'''),
    ("硬編碼密碼", "hardcoded_secret", '''def connect():
    password = "admin123456"
    return db.connect(user="root", password=password)'''),
]

# ── 組 B：安全但會被 Semgrep 誤報（已知答案 = 正常）──
SAFE_BUT_FLAGGED = [
    ("SQL-參數化查詢", "應為正常", '''def get_user(request):
    user_id = request.args.get('id')
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchall()'''),
    ("SQL-ORM", "應為正常", '''def get_user(request):
    user_id = request.args.get('id')
    user = User.objects.filter(id=user_id).first()
    return user'''),
    ("指令-無shell固定參數", "應為正常", '''def check():
    subprocess.run(["ls", "-la"], shell=False)'''),
    ("指令-白名單", "應為正常", '''def service(request):
    action = request.args.get('action')
    if action not in ['start', 'stop', 'restart']:
        raise ValueError("invalid")
    subprocess.run(["systemctl", action, "nginx"])'''),
    ("加密-bcrypt", "應為正常", '''def hash_password(pwd):
    import bcrypt
    return bcrypt.hashpw(pwd.encode(), bcrypt.gensalt())'''),
    ("檔案-固定路徑", "應為正常", '''def load_config():
    with open("/app/config/settings.json") as f:
        return json.load(f)'''),
    ("密碼-從環境變數", "應為正常", '''def connect():
    password = os.environ.get("DB_PASSWORD")
    return db.connect(user="root", password=password)'''),
]


def _strip(code):
    s = str(code)
    s = re.sub(r'"""(.*?)"""', "", s, flags=re.DOTALL)
    s = re.sub(r"'''(.*?)'''", "", s, flags=re.DOTALL)
    s = re.sub(r"/\*.*?\*/", "", s, flags=re.DOTALL)
    s = re.sub(r"//.*", "", s)
    s = re.sub(r"#.*", "", s)
    return re.sub(r"\n\s*\n+", "\n", s).strip()


def _resolve(model_dir):
    if os.path.exists(os.path.join(model_dir, "model.safetensors")):
        return model_dir
    ckpts = [c for c in glob.glob(os.path.join(model_dir, "checkpoint-*"))
             if os.path.exists(os.path.join(c, "model.safetensors"))]
    ckpts.sort(key=lambda p: int(p.split("-")[-1]))
    return ckpts[-1] if ckpts else None


def main():
    model_path = _resolve(MODEL_DIR)
    if not model_path:
        print(f"❌ 找不到模型 {MODEL_DIR}")
        return

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    tok = AutoTokenizer.from_pretrained(BASE_MODEL)
    model = AutoModelForSequenceClassification.from_pretrained(model_path).to(device)
    model.eval()

    def classify(code):
        c = _strip(code) if STRIP_COMMENTS else code
        enc = tok(c[:2000], max_length=512, padding="max_length",
                  truncation=True, return_tensors="pt").to(device)
        with torch.no_grad():
            probs = torch.softmax(model(**enc).logits, dim=1)
            label = int(torch.argmax(probs, dim=1).item())
            conf = float(probs[0][label].item())
            # 也記錄「正常程式碼」那一類的機率
            normal_prob = float(probs[0][0].item())
        return label, conf, normal_prob

    lines = []

    def log(s=""):
        print(s)
        lines.append(s)

    log("=" * 74)
    log("CodeBERT v6 信心分布分析")
    log("=" * 74)
    log("\n目的：確認「真漏洞」與「安全但被Semgrep誤報」的信心是否分得開")
    log("      分得開 → 信心門檻有依據；分不開 → 只能靠重訓\n")

    # 組 A：真漏洞
    log("─" * 74)
    log("組 A：真漏洞（期望：判為漏洞，高信心）")
    log("─" * 74)
    log(f"  {'案例':<24} {'判定':<12} {'信心':>6} {'正常類機率':>10}")
    real_confs = []
    real_correct = 0
    for name, expect_cat, code in REAL_VULNS:
        label, conf, normal_p = classify(code)
        is_vuln = label != 0
        real_correct += is_vuln
        if is_vuln:
            real_confs.append(conf)
        mark = "✓" if is_vuln else "✗漏報"
        log(f"  {name:<24} {LABEL_NAMES[label]:<12} {conf:>5.0%} {normal_p:>9.0%}  {mark}")

    # 組 B：安全但被誤報
    log("\n" + "─" * 74)
    log("組 B：安全但會被Semgrep誤報（期望：判為正常程式碼）")
    log("─" * 74)
    log(f"  {'案例':<24} {'判定':<12} {'信心':>6} {'正常類機率':>10}")
    safe_as_normal = 0
    safe_vuln_confs = []   # 被誤判成漏洞時的信心
    for name, _, code in SAFE_BUT_FLAGGED:
        label, conf, normal_p = classify(code)
        is_normal = label == 0
        safe_as_normal += is_normal
        if not is_normal:
            safe_vuln_confs.append(conf)
        mark = "✓正確" if is_normal else f"✗誤判為{LABEL_NAMES[label]}"
        log(f"  {name:<24} {LABEL_NAMES[label]:<12} {conf:>5.0%} {normal_p:>9.0%}  {mark}")

    # ── 分析 ──
    log("\n" + "=" * 74)
    log("分析")
    log("=" * 74)
    log(f"\n組A 真漏洞：{real_correct}/{len(REAL_VULNS)} 判為漏洞")
    if real_confs:
        log(f"  判對時的信心：最低 {min(real_confs):.0%}、"
            f"平均 {sum(real_confs)/len(real_confs):.0%}、最高 {max(real_confs):.0%}")
    log(f"\n組B 安全程式碼：{safe_as_normal}/{len(SAFE_BUT_FLAGGED)} 正確判為正常")
    if safe_vuln_confs:
        log(f"  被誤判為漏洞時的信心：最低 {min(safe_vuln_confs):.0%}、"
            f"平均 {sum(safe_vuln_confs)/len(safe_vuln_confs):.0%}、"
            f"最高 {max(safe_vuln_confs):.0%}")

    # 門檻是否有效
    log("\n【門檻可行性判斷】")
    if real_confs and safe_vuln_confs:
        real_min = min(real_confs)
        safe_max = max(safe_vuln_confs)
        if real_min > safe_max:
            log(f"  ✓ 分得開！真漏洞最低信心 {real_min:.0%} > 誤判最高信心 {safe_max:.0%}")
            log(f"    門檻可設在 {safe_max:.0%}–{real_min:.0%} 之間")
        else:
            overlap_lo = safe_max
            overlap_hi = real_min
            log(f"  ⚠️ 有重疊：真漏洞信心低到 {real_min:.0%}，"
                f"誤判信心高到 {safe_max:.0%}")
            log(f"    信心區間重疊，單一門檻無法乾淨分開兩者")
            log(f"    → 門檻只能降低（非消除）誤報，需誠實說明；根治靠路線B重訓")
    elif not safe_vuln_confs:
        log(f"  ✓ 組B 全部正確判為正常，v6 對這些安全模式辨識良好")
        log(f"    （但樣本少，需更多案例確認）")
    else:
        log(f"  組A 或組B 樣本不足以判斷")

    log("\n※ 本分析僅為現狀調查，樣本量小（各約7-8筆），")
    log("  結論僅供參考，不作為成果宣稱。實際門檻需更大樣本驗證。")

    with open("dataset/confidence_report.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print("\n✅ 報告：dataset/confidence_report.txt")


if __name__ == "__main__":
    main()