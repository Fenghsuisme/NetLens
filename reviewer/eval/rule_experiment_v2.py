# -*- coding: utf-8 -*-
"""
rule_experiment_v2.py — Semgrep 規則對照實驗（修正版）

相對 v1 的修正：
  1. 改用 testset_parser 共用解析器
     v1 自己寫的解析只抓到有 ``` 標記的 10 筆，
     漏掉 84 筆「###DESC: 後直接接程式碼」的樣本，導致分母錯誤。
  2. 納入補強規則（rules/supplement_hardcoded.yml）
  3. 支援跨語言評估（不再只做 Python）
  4. 各類別樣本數不足時會標記，避免誤讀統計

四組配置：
  A 自訂       rules/{lang}.yml
  B 官方       p/security-audit
  C 自訂+補強   自訂 + supplement_hardcoded
  D 全部       自訂 + 補強 + 官方

三個指標：
  ① 召回率        命中目標漏洞類別的比例（架構天花板）
  ② 誤報          對安全程式碼的 finding 數
  ③ 每檔finding數  影響使用體驗

執行：
  python rule_experiment_v2.py              # 全語言
  python rule_experiment_v2.py python       # 只做 python
"""
import os
import sys
from collections import defaultdict

# 已移入子目錄，需往上一層才能 import 到 reviewer/ 下的模組
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from testset_parser import parse_testset
from transport_layer import run_semgrep
from core.config_loader import get_category, cwe_to_category

REPORT = "dataset/rule_experiment_v2_report.txt"
# 補強規則（可多份，逐一針對實測發現的盲區）
SUPPLEMENT_RULES = [
    "rules/supplement_hardcoded.yml",   # CWE-798：Java static final、雲端金鑰格式
    "rules/supplement_sqli.yml",        # CWE-89：ORM/查詢建構器的 raw 方法拼接
    "rules/supplement_xss.yml",         # CWE-79：HTML 字串拼接、模板關閉轉義
    "rules/supplement_path.yml",        # CWE-22：基底路徑與外部輸入拼接
    "rules/supplement_crypto.yml",      # CWE-327：DES/ECB/RC4 等弱演算法
    "rules/supplement_proto.yml",       # CWE-1321：遞迴合併未過濾危險 key
    "rules/supplement_codeexec.yml",    # CWE-94：PHP eval、動態載入等
]

# A 類 10 種的 label（片段可判定：存在危險 sink）
A_CLASS_LABELS = {1, 2, 3, 6, 7, 8, 9, 10, 11, 12}
# B 類（上下文判定：缺少防護），目前擱置，但新測試集有樣本可供觀察
B_CLASS_LABELS = {4, 5, 13, 14, 15, 16, 17}

LABEL_NAMES = {
    0: "正常程式碼",
    1: "指令注入", 2: "SQL 注入", 3: "程式碼執行", 4: "資料外洩",
    5: "後門", 6: "弱加密", 7: "硬編碼密碼", 8: "路徑遊走",
    9: "不安全反序列化", 10: "跨站腳本", 11: "原型污染", 12: "惡意套件",
    13: "跨站請求偽造", 14: "SSRF", 15: "IDOR",
    16: "不受限檔案上傳", 17: "權限控制缺陷",
}

# ── 誤報測試樣本（各語言的安全寫法）──
SAFE_SAMPLES = [
    ("python", "參數化查詢", '''def get_user(request):
    user_id = request.args.get('id')
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchall()'''),
    ("python", "ORM查詢", '''def get_user(request):
    user_id = request.args.get('id')
    return User.objects.filter(id=user_id).first()'''),
    ("python", "subprocess無shell", '''def list_files():
    subprocess.run(["ls", "-la"], shell=False)'''),
    ("python", "白名單驗證", '''def service(request):
    action = request.args.get('action')
    if action not in ['start', 'stop', 'restart']:
        raise ValueError("invalid")
    subprocess.run(["systemctl", action, "nginx"])'''),
    ("python", "bcrypt加密", '''def hash_password(pwd):
    import bcrypt
    return bcrypt.hashpw(pwd.encode(), bcrypt.gensalt())'''),
    ("python", "環境變數密碼", '''def connect():
    password = os.environ.get("DB_PASSWORD")
    return db.connect(user="root", password=password)'''),
    ("javascript", "參數化查詢JS", '''async function getUser(req, res) {
    const userId = req.query.id;
    const result = await db.query("SELECT * FROM users WHERE id = $1", [userId]);
    res.json(result.rows);
}'''),
    ("javascript", "環境變數JS", '''const dbPassword = process.env.DB_PASSWORD;
const apiKey = process.env.API_KEY;
const client = new Client({ password: dbPassword });'''),
    ("java", "PreparedStatement", '''public User getUser(String userId) throws SQLException {
    String sql = "SELECT * FROM users WHERE id = ?";
    PreparedStatement stmt = conn.prepareStatement(sql);
    stmt.setString(1, userId);
    return parseUser(stmt.executeQuery());
}'''),
    ("java", "環境變數Java", '''public class Config {
    private static final String DB_PASSWORD = System.getenv("DB_PASSWORD");
    public static String getPassword() { return DB_PASSWORD; }
}'''),
    ("php", "PDO預備語句", '''<?php
function getUser($pdo, $userId) {
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
    $stmt->execute(['id' => $userId]);
    return $stmt->fetch();
}'''),
]


def build_configs(lang):
    """依語言產生四組規則配置"""
    custom = f"rules/{lang}.yml"
    supplements = [p for p in SUPPLEMENT_RULES if os.path.exists(p)]
    return {
        "A_自訂": [custom],
        "B_官方": ["p/security-audit"],
        "C_自訂+補強": [custom] + supplements,
        "D_全部": [custom] + supplements + ["p/security-audit"],
    }


# 惡意套件偵測（typosquatting）
# 不經 Semgrep：其判定需計算與熱門套件的編輯距離，pattern 比對無法做到
try:
    from typosquat_detector import scan_imports
    HAS_TYPOSQUAT = True
except ImportError:
    HAS_TYPOSQUAT = False


def get_findings(code, lang, rule_paths, with_typosquat=True):
    """跑多份規則並合併去重，回傳 [(cwe, line)]"""
    seen = set()
    out = []
    for path in rule_paths:
        if not str(path).startswith(("p/", "r/")) and not os.path.exists(path):
            continue
        try:
            for f in run_semgrep(code, lang, path):
                cwe, line = f.get("cwe"), f.get("start_line")
                if cwe and line and (cwe, line) not in seen:
                    seen.add((cwe, line))
                    out.append((cwe, line))
        except Exception:
            continue

    # 惡意套件：獨立模組，僅在含補強規則的配置中啟用
    # （A_自訂 與 B_官方 兩組不含，以維持對照的純粹性）
    if with_typosquat and HAS_TYPOSQUAT:
        try:
            for f in scan_imports(code, lang):
                key = ("CWE-829", f["line"])
                if key not in seen:
                    seen.add(key)
                    out.append(key)
        except Exception:
            pass
    return out


def hits_target(findings, target_label):
    for cwe, _ in findings:
        cat = cwe_to_category(cwe)
        if cat:
            info = get_category(cat)
            if info and info["label"] == target_label:
                return True
    return False


def main():
    import argparse, random
    ap = argparse.ArgumentParser(description="Semgrep 規則對照實驗")
    ap.add_argument("lang", nargs="?", default=None,
                    help="只測指定語言（python/javascript/php/java）")
    ap.add_argument("-n", "--sample", type=int, default=0,
                    help="每類抽樣筆數（0=全部）。2742筆×4組會跑很久，建議先 -n 30")
    ap.add_argument("--with-b", action="store_true",
                    help="同時評估 B 類（目前擱置的 7 類），供觀察 Semgrep 對它們的效果")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    lang_filter = args.lang

    target_labels = set(A_CLASS_LABELS)
    if args.with_b:
        target_labels |= B_CLASS_LABELS

    items = parse_testset(lang=lang_filter, labels=target_labels)

    # 每類抽樣（避免全跑太久）
    if args.sample > 0:
        random.seed(args.seed)
        by_label = defaultdict(list)
        for it in items:
            by_label[it["label"]].append(it)
        sampled = []
        for label, group in by_label.items():
            random.shuffle(group)
            sampled.extend(group[:args.sample])
        items = sampled
    if not items:
        print("❌ 沒有 A 類測試樣本")
        return

    langs_in_use = sorted({it["lang"] for it in items})
    print(f"A 類測試樣本：{len(items)} 筆（語言：{', '.join(langs_in_use)}）")

    safe = [s for s in SAFE_SAMPLES if not lang_filter or s[0] == lang_filter]
    print(f"安全樣本（測誤報）：{len(safe)} 筆")
    print("\n開始實驗（首次跑官方規則會下載，請稍候）...\n")

    config_names = ["A_自訂", "B_官方", "C_自訂+補強", "D_全部"]

    # ── 漏洞樣本 ──
    per_sample = []
    for i, it in enumerate(items, 1):
        cfgs = build_configs(it["lang"])
        row = {"label": it["label"], "lang": it["lang"]}
        for name in config_names:
            # 惡意套件偵測屬「補強」的一部分，僅 C/D 組啟用
            use_ts = name in ("C_自訂+補強", "D_全部")
            row[name] = get_findings(it["code"], it["lang"], cfgs[name],
                                     with_typosquat=use_ts)
        per_sample.append(row)
        if i % 10 == 0:
            print(f"  漏洞樣本 {i}/{len(items)}")

    # ── 安全樣本 ──
    print("\n處理安全樣本...")
    safe_rows = []
    for lang, desc, code in safe:
        cfgs = build_configs(lang)
        row = {"desc": f"{desc}({lang})"}
        for name in config_names:
            use_ts = name in ("C_自訂+補強", "D_全部")
            row[name] = get_findings(code, lang, cfgs[name],
                                     with_typosquat=use_ts)
        safe_rows.append(row)

    # ── 報告 ──
    lines = []

    def log(s=""):
        print(s)
        lines.append(s)

    log("=" * 78)
    log("Semgrep 規則對照實驗 v2（修正解析後）")
    log("=" * 78)
    log(f"\n測試樣本：A 類 {len(items)} 筆")
    log(f"語言：{', '.join(langs_in_use)}")
    log(f"安全樣本：{len(safe)} 筆")
    found = [os.path.basename(p) for p in SUPPLEMENT_RULES if os.path.exists(p)]
    missing = [os.path.basename(p) for p in SUPPLEMENT_RULES if not os.path.exists(p)]
    log(f"補強規則：{', '.join(found) if found else '無'}")
    if missing:
        log(f"　　（未找到：{', '.join(missing)}）")

    log("\n" + "─" * 78)
    log("【指標 ①：召回率】")
    log("─" * 78)
    recall = {}
    for cfg in config_names:
        hit = sum(1 for r in per_sample if hits_target(r[cfg], r["label"]))
        recall[cfg] = hit
        log(f"  {cfg:<14} {hit:>3}/{len(items)} = {hit/len(items):>6.1%}")

    log("\n" + "─" * 78)
    log("【指標 ②：誤報】對安全程式碼的 finding 數")
    log("─" * 78)
    log(f"  {'安全樣本':<24} " + "".join(f"{c:>13}" for c in config_names))
    fp = defaultdict(int)
    for row in safe_rows:
        line = f"  {row['desc']:<24} "
        for cfg in config_names:
            n = len(row[cfg])
            fp[cfg] += n
            line += f"{n:>13}"
        log(line)
    log(f"  {'總計':<24} " + "".join(f"{fp[c]:>13}" for c in config_names))

    log("\n" + "─" * 78)
    log("【指標 ③：每檔平均 finding 數】")
    log("─" * 78)
    for cfg in config_names:
        avg = sum(len(r[cfg]) for r in per_sample) / len(per_sample)
        log(f"  {cfg:<14} {avg:>5.1f} 個/檔")

    log("\n" + "─" * 78)
    log("【各類別召回率】")
    log("─" * 78)
    by_label = defaultdict(list)
    for r in per_sample:
        by_label[r["label"]].append(r)

    def _class_table(title, label_set):
        rows_in = [l for l in sorted(by_label) if l in label_set]
        if not rows_in:
            return None
        log(f"\n  {title}")
        log(f"  {'類別':<16} {'樣本':>4} " + "".join(f"{c:>13}" for c in config_names))
        log("  " + "-" * (22 + 13 * len(config_names)))
        agg = {c: [0, 0] for c in config_names}
        for label in rows_in:
            rows = by_label[label]
            line = f"  {LABEL_NAMES.get(label, label):<16} {len(rows):>4} "
            for cfg in config_names:
                hit = sum(1 for r in rows if hits_target(r[cfg], r["label"]))
                agg[cfg][0] += hit
                agg[cfg][1] += len(rows)
                line += f"{hit:>6}/{len(rows):<6}"
            log(line)
        log("  " + "-" * (22 + 13 * len(config_names)))
        line = f"  {'小計':<16} {agg[config_names[0]][1]:>4} "
        for cfg in config_names:
            h, t = agg[cfg]
            line += f"{h/t:>12.1%} "
        log(line)
        return agg

    a_agg = _class_table("A 類（片段可判定，本階段主力）", A_CLASS_LABELS)
    b_agg = _class_table("B 類（上下文判定，目前擱置）", B_CLASS_LABELS)
    if b_agg:
        log("\n  註：B 類本質是「缺少防護」，片段判定效果有限，")
        log("      此處僅供觀察 Semgrep 規則對它們的涵蓋程度。")

    missing = [LABEL_NAMES[l] for l in A_CLASS_LABELS if l not in by_label]
    if missing:
        log(f"\n  ⚠️ 測試集無樣本、無法評估的類別：{', '.join(missing)}")

    log("\n" + "=" * 78)
    log("【結論】")
    log("=" * 78)
    best = max(config_names, key=lambda c: recall[c])
    log(f"  召回率最高：{best}（{recall[best]/len(items):.1%}，誤報 {fp[best]} 個）")
    base = recall["A_自訂"]
    for cfg in config_names:
        if cfg == "A_自訂":
            continue
        d_recall = (recall[cfg] - base) / len(items)
        d_fp = fp[cfg] - fp["A_自訂"]
        log(f"  {cfg:<14} 相對自訂：召回 {d_recall:+.1%}，誤報 {d_fp:+d} 個")

    os.makedirs("dataset", exist_ok=True)
    with open(REPORT, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"\n✅ 報告：{REPORT}")


if __name__ == "__main__":
    main()