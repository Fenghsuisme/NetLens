# -*- coding: utf-8 -*-
"""
audit_teammate_labels.py — 稽核組員資料的標籤正確性

方法：相對比較法（Relative Scoring）
  這是先前成功抓出 GPT 測試檔 70% 錯置的方法。

  原理：不問「這段程式碼有沒有 X 漏洞的關鍵字」（絕對比對，對「缺少防護」
  型漏洞會失效），而是問「這段程式碼最像哪一類漏洞」——
  把程式碼對 17 類的特徵各評一次分，看最高分是不是它宣稱的標籤。

  這樣即使某類的關鍵字列得不完整，只要它相對於其他類仍是最高分，
  就不會被誤判為錯置。

判讀：
  錯置率 < 15%  → 資料品質可接受
  錯置率 15-40% → 中度問題，特定類別需重生
  錯置率 > 40%  → 嚴重問題，該類別資料不可用

執行：python audit_teammate_labels.py
"""
import os
import re
import sys
from collections import defaultdict, Counter

import pandas as pd

# 已移入子目錄，需往上一層才能 import 到 reviewer/ 下的模組
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.config_loader import label_to_category, get_category

TEAMMATE_CSV = "dataset/teammate_aligned.csv"
REPORT = "dataset/teammate_label_audit.txt"
SAMPLE_PER_CLASS = 400      # 每類抽樣數（全掃太慢）
SEED = 42

# ── 各類漏洞的「特徵權重表」──────────────────────
# 高權重 = 該類的決定性特徵；低權重 = 相關但不專屬
# 分數 = 命中特徵的權重總和
SIGNATURES = {
    # 只保留「決定性特徵」。先前版本包含 "file"/"http"/"url" 等通用字，
    # 導致任何 web 程式碼都對路徑遊走/資料外洩/SSRF 得高分，
    # 把其他類別全部吃掉（原型污染被判 82.7% 錯置但模型 F1 達 0.909 → 工具誤判）。
    "sql_injection": {
        3: ["execute(", "executequery", "cursor.execute", "createquery",
            "queryforlist", "queryrawunsafe", "executeupdate"],
        2: ["select * from", "insert into", "delete from", "update set",
            " where id", "order by"],
    },
    "command_injection": {
        3: ["os.system", "subprocess.", "shell_exec", "runtime.getruntime",
            "processbuilder", "child_process", "os.popen", "passthru("],
        2: ["shell=true", "/bin/sh", "cmd.exe", "powershell -"],
    },
    "code_execution": {
        3: ["eval(", "new function(", "compile(", "scriptengine",
            "parseexpression", "mvel.eval", "ognl.getvalue",
            "create_function", "assert($"],
        2: ["exec(", "__import__("],
    },
    "xss": {
        3: ["innerhtml", "document.write", "outerhtml", "mark_safe",
            "render_template_string", "dangerouslysetinnerhtml",
            "getwriter().print", "getwriter().write"],
        2: ["|safe", "autoescape", "htmlspecialchars"],
    },
    "path_traversal": {
        3: ["../", "..\\\\", "file_get_contents(", "readfile(",
            "extractall(", "zipentry", "getnextentry"],
        2: ["os.path.join(", "path.join(", "new fileinputstream",
            "new filereader"],
    },
    "weak_cryptography": {
        3: ["md5", "sha1(", "\"des\"", "'des'", "rc4", "ecb",
            "hashlib.md5", "createhash('md5')", "messagedigest.getinstance"],
        2: ["verify=false", "rejectunauthorized", "trustallcerts"],
    },
    "hardcoded_secret": {
        3: ["password = \"", "password = '", "password=\"", "api_key =",
            "apikey =", "secret_key =", "aws_access_key", "private_key ="],
        2: ["const password", "string password =", "$password ="],
    },
    "insecure_deserialization": {
        3: ["pickle.load", "unserialize(", "objectinputstream", "readobject(",
            "yaml.load(", "marshal.load", "xmldecoder", "node-serialize",
            "enabledefaulttyping", "parseobject("],
    },
    "prototype_pollution": {
        3: ["__proto__", "prototype[", "object.prototype",
            "constructor.prototype", "setprototypeof"],
        2: ["deepmerge", "_.merge", "object.assign({}, "],
    },
    "malicious_import": {
        3: ["colourama", "reqeusts", "jeiiyfish", "crossenv",
            "flatmap-stream", "event-stream", "python3-dateutil"],
        2: ["postinstall", "preinstall", "b64decode(", "atob("],
    },
    "data_exfiltration": {
        3: ["requests.post(", "axios.post(", "smtplib", "send_mail(",
            "printstacktrace(", "os.environ", "process.env",
            "traceback.format_exc"],
        2: ["res.json(err", "err.stack"],
    },
    "backdoor": {
        3: ["backdoor", "master_key", "magic_password", "skip_auth",
            "== \"admin\" &&", "bypass_auth", "secret_admin"],
        2: ["debug_mode = true", "if (debug)", "hardcoded master"],
    },
    "csrf": {
        3: ["csrf", "samesite", "csrf_exempt", "wtf_csrf_enabled",
            ".csrf().disable()", "csrfprotection", "ignoremethods",
            "csrftoken", "@csrf"],
    },
    "ssrf": {
        3: ["requests.get(url", "urlopen(url", "axios.get(url",
            "new url(", "openconnection()", "curl_exec",
            "file_get_contents($url", "resttemplate.getforobject"],
        2: ["webhook", "callback_url", "target_url", "fetch_url"],
    },
    "file_upload": {
        3: ["getoriginalfilename", "$_files", "move_uploaded_file",
            "multer(", "uploadfile", "createwritestream(", "getpart(",
            "files.mv(", "file.save("],
        2: ["multipart/form-data", "enctype"],
    },
    "broken_access_control": {
        3: ["permitall()", "anonymous()", "isuserinrole", "@preauthorize",
            "allow_anonymous", "checkauthorization = false",
            "setauthenticated(true)", "access-control-allow-origin\", \"*"],
        2: ["findbyid(req", "find_by_id(request", "req.params.id",
            "$_get['id']", "@rolesallowed"],
    },
}


def score_code(code, category):
    """對某類別評分：命中的特徵權重總和"""
    low = str(code).lower()
    sigs = SIGNATURES.get(category)
    if not sigs:
        return 0
    score = 0
    for weight, keywords in sigs.items():
        for kw in keywords:
            if kw in low:
                score += weight
    return score


def best_match(code):
    """回傳這段程式碼最像的類別與分數"""
    scores = {cat: score_code(code, cat) for cat in SIGNATURES}
    best = max(scores, key=scores.get)
    return best, scores[best], scores


def main():
    if not os.path.exists(TEAMMATE_CSV):
        print(f"❌ 找不到 {TEAMMATE_CSV}")
        print("   請先執行 integrate_teammate_data.py")
        return

    df = pd.read_csv(TEAMMATE_CSV)
    print(f"載入組員資料：{len(df)} 筆\n")

    lines = []

    def log(s=""):
        print(s)
        lines.append(s)

    log("=" * 76)
    log("組員資料標籤稽核報告（相對比較法）")
    log("=" * 76)
    log("\n方法說明：")
    log("  對每段程式碼，計算它對 16 類漏洞特徵的相符分數，")
    log("  取最高分者為「程式碼實際看起來的類別」，與宣稱標籤比對。")
    log("  此方法先前成功抓出 GPT 測試檔 70% 的標籤錯置。")

    total_checked = 0
    total_mismatch = 0
    per_class_result = {}
    confusion = defaultdict(Counter)   # 宣稱標籤 → 實際看起來的類別

    for label in sorted(df["label"].unique()):
        cat = label_to_category(label)
        if not cat or cat == "clean" or cat not in SIGNATURES:
            continue
        sub = df[df["label"] == label]
        n = min(SAMPLE_PER_CLASS, len(sub))
        sample = sub.sample(n=n, random_state=SEED)

        mismatch = 0
        zero_score = 0
        for code in sample["code"]:
            best, best_score, _ = best_match(code)
            own_score = score_code(code, cat)
            if best_score == 0:
                # 特徵表收緊後，零分代表「無法判斷」而非「標籤錯誤」
                # 不計入錯置，僅記錄
                zero_score += 1
            elif best != cat and best_score > own_score:
                mismatch += 1
                confusion[cat][best] += 1

        rate = mismatch / n
        per_class_result[label] = {
            "cat": cat, "n": n, "mismatch": mismatch,
            "rate": rate, "zero": zero_score,
        }
        total_checked += n
        total_mismatch += mismatch

    overall = total_mismatch / total_checked if total_checked else 0

    log(f"\n【總覽】")
    log(f"  抽樣總數：{total_checked}")
    log(f"  疑似錯置：{total_mismatch}")
    log(f"  整體錯置率：{overall:.1%}   （不含無法判斷者）")
    if overall > 0.40:
        log("  ⚠️ 嚴重：資料標籤大量錯置，該批資料不建議用於訓練")
    elif overall > 0.15:
        log("  ⚠️ 中度：部分類別需重新生成")
    else:
        log("  ✓ 品質可接受")

    log(f"\n【各類別錯置率】")
    log(f"  {'label':<6} {'類別':<22} {'抽樣':>5} {'錯置':>5} {'錯置率':>8} {'無特徵':>7}")
    log("  " + "-" * 62)
    for label in sorted(per_class_result.keys()):
        r = per_class_result[label]
        info = get_category(r["cat"])
        zh = info.get("name_zh", r["cat"])
        flag = ""
        if r["rate"] > 0.40:
            flag = "  ⚠️嚴重"
        elif r["rate"] > 0.15:
            flag = "  ⚠️"
        log(f"  {label:<6} {zh:<22} {r['n']:>5} {r['mismatch']:>5} "
            f"{r['rate']:>7.1%} {r['zero']:>7}{flag}")

    log(f"\n【錯置流向】（宣稱是 A，但看起來像 B）")
    log("  " + "-" * 62)
    for cat in sorted(confusion.keys()):
        info = get_category(cat)
        zh = info.get("name_zh", cat) if info else cat
        top = confusion[cat].most_common(3)
        if not top:
            continue
        flows = "、".join(
            f"{get_category(b).get('name_zh', b) if get_category(b) else b}({c})"
            for b, c in top
        )
        log(f"  {zh:<22} → {flows}")

    log(f"\n【判讀建議】")
    worst = sorted(per_class_result.items(), key=lambda x: -x[1]["rate"])[:5]
    log("  錯置率最高的 5 類（優先重新生成）：")
    for label, r in worst:
        info = get_category(r["cat"])
        zh = info.get("name_zh", r["cat"])
        log(f"    {zh:<22} {r['rate']:>6.1%}")

    log("\n  註：本方法為啟發式判斷，可能有誤差。")
    log("      建議對錯置率高的類別，人工抽看 5-10 筆確認。")

    with open(REPORT, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"\n✅ 報告：{REPORT}")


if __name__ == "__main__":
    main()