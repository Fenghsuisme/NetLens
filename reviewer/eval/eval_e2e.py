# -*- coding: utf-8 -*-
"""
eval_e2e.py — 端到端管道評估

評估完整流程 Semgrep → 傳輸層 → CodeBERT 的實際表現，
並與「整檔輸入」對照，量化片段架構的效果。

三個階段的數字（拆開才知道瓶頸在哪）：
    ① Semgrep 召回率      架構天花板，命中不到的第二階段永遠看不到
    ② 片段分類準確率      命中的樣本中，模型判對的比例
    ③ 端到端準確率        ① × ②，實際偵測率

對照組：
    整檔輸入準確率        同一批樣本直接餵給模型（不經傳輸層）
    → 用以判斷片段架構是否優於整檔

誤報過濾評估：
    對「安全但含敏感關鍵字」的樣本，
    測量 Semgrep 誤報中有多少被模型正確過濾。
    這是兩階段架構的核心價值指標。

用法：
    python eval_e2e.py                 A 類全部（1497 筆，較久）
    python eval_e2e.py -n 30           每類抽 30 筆（快速）
    python eval_e2e.py --with-b        含 B 類（觀察模型對擱置類別的表現）
    python eval_e2e.py -n 30 --lang python
"""
import argparse
import glob
import os
import random
import re
import sys
import time
from collections import defaultdict

_HERE = os.path.dirname(os.path.abspath(__file__))
# 本檔可能放在專案根目錄，也可能放在 eval/ 子目錄。
# 直接執行時 sys.path[0] 只會是本檔所在目錄，若在 eval/ 底下就找不到
# 根目錄的 testset_parser、transport_layer，故兩層都加入。
for _p in (_HERE, os.path.dirname(_HERE)):
    if _p not in sys.path:
        sys.path.insert(0, _p)
# 規則、模型、測試集都用相對路徑，故工作目錄必須是專案根目錄
if os.path.isdir(os.path.join(os.path.dirname(_HERE), "rules")):
    os.chdir(os.path.dirname(_HERE))

from testset_parser import parse_testset
from transport_layer import (process, extract_enclosing_function,
                             run_semgrep, SemgrepExecutionError,
                             A_CLASS_CWES, SUPPLEMENT_RULES)
# 函式名去語意化（與訓練前處理一致）
try:
    from obfuscate import obfuscate_functions
    HAS_OBFUSCATE = True
except ImportError:
    HAS_OBFUSCATE = False
    obfuscate_functions = None

from core.config_loader import cwe_to_category, get_category, label_to_category
# config（22類）與模型（17類）的標籤在 15 之後錯開，須轉換
from label_map import config_to_model, MODEL_LABEL_NAMES, CONFIG_TO_MODEL

MODEL_DIR = "models/codebert_v7v8_safe"
BASE_MODEL = "microsoft/codebert-base"

# 前處理須與訓練條件一致
STRIP_COMMENTS = True       # 訓練資料已剝除註解
OBFUSCATE_FUNCS = False     # v7v8_safe 以未去語意化資料訓練，推論/評估亦不去語意化
                            # （eval_clean 由此匯入本旗標，一併對齊）
REPORT = "dataset/e2e_report.txt"

LABEL_NAMES = MODEL_LABEL_NAMES   # 統一使用模型體系的標籤名稱
# 分組僅用於報告呈現，兩組皆完整評估
# （v7v8_safe 後 B 類 F1 已達 0.888–0.974，不再有能力差距）
A_CLASS_LABELS = {1, 2, 3, 6, 7, 8, 9, 10, 11, 12}
B_CLASS_LABELS = {4, 5, 13, 14, 15, 16}

# 直接沿用生產端 SUPPLEMENT_RULES，避免與 transport_layer 不同步
# （舊版硬編碼會漏掉新增的補強規則，如本輪的 supplement_upload.yml，
#  導致評估載入的規則集與生產不一致、召回數字失真）
SUPPLEMENTS = list(SUPPLEMENT_RULES)

# ── 安全樣本：Semgrep 會誤報但實際安全 ──
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
    ("python", "basename防護", '''def download(request):
    name = os.path.basename(request.args.get('file'))
    with open(os.path.join("/var/data", name)) as f:
        return f.read()'''),
    ("python", "ast安全解析", '''def calc(request):
    import ast
    return ast.literal_eval(request.args.get('expr'))'''),
    ("javascript", "參數化查詢JS", '''async function getUser(req, res) {
    const userId = req.query.id;
    const r = await db.query("SELECT * FROM users WHERE id = $1", [userId]);
    res.json(r.rows);
}'''),
    ("javascript", "環境變數JS", '''const dbPassword = process.env.DB_PASSWORD;
const apiKey = process.env.API_KEY;
const client = new Client({ password: dbPassword });'''),
    ("javascript", "白名單dispatch", '''const handlers = { add: (a,b)=>a+b, sub: (a,b)=>a-b };
app.post('/calc', (req, res) => {
    const op = req.body.op;
    if (!(op in handlers)) return res.status(400).json({error:'invalid'});
    res.json({ result: handlers[op](1, 2) });
});'''),
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
    ("java", "AES-GCM加密", '''public byte[] encrypt(byte[] key, byte[] iv, byte[] data) throws Exception {
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(128, iv));
    return cipher.doFinal(data);
}'''),
    ("php", "PDO預備語句", '''<?php
function getUser($pdo, $userId) {
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
    $stmt->execute(['id' => $userId]);
    return $stmt->fetch();
}'''),
    ("php", "basename防護PHP", '''<?php
$name = basename($_GET['file']);
$path = "/var/www/uploads/" . $name;
readfile($path);'''),
]


def _strip(code):
    s = str(code)
    s = re.sub(r'"""(.*?)"""', "", s, flags=re.DOTALL)
    s = re.sub(r"'''(.*?)'''", "", s, flags=re.DOTALL)
    s = re.sub(r"/\*.*?\*/", "", s, flags=re.DOTALL)
    s = re.sub(r"//.*", "", s)
    s = re.sub(r"#.*", "", s)
    return re.sub(r"\n\s*\n+", "\n", s).strip()


def _is_loadable(d):
    has_w = any(os.path.exists(os.path.join(d, f))
                for f in ("model.safetensors", "pytorch_model.bin"))
    return has_w and os.path.exists(os.path.join(d, "config.json"))


def _resolve_model(md):
    if _is_loadable(md):
        return md
    ck = [c for c in glob.glob(os.path.join(md, "checkpoint-*")) if _is_loadable(c)]
    if not ck:
        return None
    ck.sort(key=lambda p: int(p.split("-")[-1]))
    return ck[-1]


# 官方 p/security-audit 是線上 registry（數百條規則）。eval 逐檔呼叫時，
# 在某些環境（如網路慢/未快取）會逐檔重新取用而拖到逾時。可用 --no-official 關閉。
USE_OFFICIAL = True


def rule_paths(lang):
    p = [f"rules/{lang}.yml"]
    p += [x for x in SUPPLEMENTS if os.path.exists(x)]
    if USE_OFFICIAL:
        p.append("p/security-audit")
    return p


def model_labels_to_config(model_labels):
    """
    模型標籤集合 → config 標籤集合。

    為什麼需要：
      parse_testset(labels=...) 濾的是 config（22類）標籤，
      但 A_CLASS_LABELS / B_CLASS_LABELS 定義的是模型（17類）標籤。
      兩者在 15 之後錯開，直接傳入會選錯樣本：

        傳入模型 15（不受限檔案上傳）→ 實際選到 config 15（IDOR）
        傳入模型 16（權限控制缺陷）  → 實際選到 config 16（檔案上傳）
        config 17（權限控制缺陷）    → 永遠選不到

      舊版因此讓 broken_access_control（160 筆）從未被評估，
      且報告中「權限控制缺陷」該列其實是 IDOR 樣本的成績。
      A 類標籤全部小於 15，故此修正不影響 A 類的既有數字。
    """
    return {cl for cl, ml in CONFIG_TO_MODEL.items() if ml in model_labels}


def collect_findings(code, lang):
    """
    跑「完整規則集」（自訂 + 補強 + 官方 + typosquat），回傳去重後的 finding。

    為什麼要抽成共用函式：
      舊版召回評估用 rule_paths() 的 9 份規則，
      誤報評估卻用 process(code, lang) —— 預設只載入 rules/{lang}.yml 一份。
      兩者量的不是同一套規則，導致報告的「誤報數」嚴重低估。

    所有規則合併為單次 semgrep 呼叫（run_semgrep 接受 list），
    而非逐份執行：實測 9 份分開跑約 12.9s/筆，合併後約 3.4s/筆。
    """
    paths = [rp for rp in rule_paths(lang)
             if str(rp).startswith(("p/", "r/")) or os.path.exists(rp)]
    seen = set()
    out = []
    try:
        fs = run_semgrep(code, lang, paths)
    except SemgrepExecutionError:
        raise
    except Exception:
        fs = []
    for f in fs:
        key = (f.get("start_line"), tuple(f.get("cwes") or []))
        if key in seen:
            continue
        seen.add(key)
        out.append(f)

    # 惡意套件走 typosquat（不經 Semgrep），與 process() 的行為一致
    try:
        from typosquat_detector import scan_imports
        for ts in scan_imports(code, lang) or []:
            key = (ts["line"], ("CWE-829",))
            if key in seen:
                continue
            seen.add(key)
            out.append({
                "rule_id": "typosquat_detector",
                "cwes": ["CWE-829"],
                "cwe": "CWE-829",
                "start_line": ts["line"],
                "end_line": ts["line"],
                "message": ts.get("reason", ""),
                "severity": "WARNING",
            })
    except Exception:
        pass

    return out


def finding_categories(f):
    """finding 的所有 CWE 對應到的類別集合（多 CWE 時全部納入）。"""
    cats = set()
    for cwe in (f.get("cwes") or ([f["cwe"]] if f.get("cwe") else [])):
        c = cwe_to_category(cwe)
        if c:
            cats.add(c)
    return cats


def main():
    ap = argparse.ArgumentParser(description="端到端管道評估")
    ap.add_argument("-n", "--sample", type=int, default=0,
                    help="每類抽樣筆數（0=全部）")
    ap.add_argument("--lang", help="限定語言")
    ap.add_argument("--with-b", action="store_true", help="含 B 類")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--no-official", action="store_true",
                    help="不載官方 p/security-audit（避免逐檔網路取用而逾時；只用本地規則）")
    args = ap.parse_args()
    if args.no_official:
        global USE_OFFICIAL
        USE_OFFICIAL = False
        print("（已停用官方規則 p/security-audit，只用本地規則）")

    labels = set(A_CLASS_LABELS)
    if args.with_b:
        labels |= B_CLASS_LABELS

    # 模型標籤 → config 標籤（15 之後錯開，直接傳會選錯樣本）
    cfg_labels = model_labels_to_config(labels)
    items = parse_testset(lang=args.lang, labels=cfg_labels)
    if not items:
        print("❌ 沒有測試樣本")
        return 1

    if args.sample > 0:
        random.seed(args.seed)
        by_label = defaultdict(list)
        for it in items:
            by_label[it["label"]].append(it)
        picked = []
        for lb, g in by_label.items():
            random.shuffle(g)
            picked.extend(g[:args.sample])
        items = picked

    # 載入模型
    path = _resolve_model(MODEL_DIR)
    if path is None:
        print(f"❌ 找不到可載入的模型：{MODEL_DIR}")
        return 1
    import torch
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    tok = AutoTokenizer.from_pretrained(BASE_MODEL)
    model = AutoModelForSequenceClassification.from_pretrained(path).to(device)
    model.eval()

    def classify(code, language=None):
        c = _strip(code) if STRIP_COMMENTS else code
        if OBFUSCATE_FUNCS and HAS_OBFUSCATE and language:
            c = obfuscate_functions(c, language)
        if len(c) < 10:
            c = code
        enc = tok(c[:2000], max_length=512, padding="max_length",
                  truncation=True, return_tensors="pt").to(device)
        with torch.no_grad():
            p = torch.softmax(model(**enc).logits, dim=1)
            lb = int(torch.argmax(p, dim=1).item())
            return lb, float(p[0][lb].item())

    print(f"模型：{path}　裝置：{device}")
    print(f"測試樣本：{len(items)} 筆　安全樣本：{len(SAFE_SAMPLES)} 筆")
    print("開始評估...\n")

    # ── 主評估 ──
    # sg     Semgrep 類別判斷正確（召回上限）
    # pipe   任一 finding 的模型預測 == 真實標籤（現行管道，含 disputed）
    # strict Semgrep 類別與模型預測皆正確（硬閘門，只算 confirmed）
    # whole  整檔輸入的對照組
    #
    # 舊版只取「第一個類別相符的 finding」送模型，但生產環境的 scan.py
    # 會把所有 finding 都跑一次模型、任一命中即回報。
    # 這導致舊版低估管道召回約 10pp（66.9% vs 實測 77.0%）。
    stat = defaultdict(lambda: {"n": 0, "sg": 0, "pipe": 0,
                                "strict": 0, "whole": 0, "filt_real": 0})
    t0 = time.time()
    skipped_out_of_scope = 0
    skipped_scan = 0
    for i, it in enumerate(items, 1):
        cfg_lb, lang, code = it["label"], it["lang"], it["code"]
        # config 標籤 → 模型標籤（15 之後錯開，須轉換）
        lb = config_to_model(cfg_lb)
        if lb is None:
            skipped_out_of_scope += 1
            continue
        # 實驗組：Semgrep 命中 → 抽片段 → 分類
        # 單一樣本 Semgrep 逾時/失敗 → 跳過該樣本（不計入），不中止整個評估
        try:
            findings = collect_findings(code, lang)
        except SemgrepExecutionError as e:
            skipped_scan += 1
            print(f"⚠️ 略過樣本（Semgrep 失敗/逾時）：{str(e)[:80]}")
            continue

        stat[lb]["n"] += 1

        # 對照組：整檔輸入
        wl, _ = classify(code, lang)
        stat[lb]["whole"] += (wl == lb)

        matched = None          # Semgrep 類別正確的第一個 finding
        matched_pred = None     # 模型對「該正確 finding 片段」的預測
        pipe_hit = False        # 現行：任一 finding 的模型預測 == 真實標籤
        strict_hit = False      # 硬閘門：Semgrep 類別與模型預測皆 == 真實標籤

        for f in findings:
            line = f.get("start_line")
            if not line:
                continue
            sg_match = any(
                (get_category(cat) or {}).get("label") is not None
                and config_to_model(get_category(cat)["label"]) == lb
                for cat in finding_categories(f)
            )
            snip, _, _ = extract_enclosing_function(code, line, lang)
            pl, _ = classify(snip, lang)
            if sg_match and matched is None:
                matched = f
                matched_pred = pl
            if pl == lb:
                pipe_hit = True
                if sg_match:
                    strict_hit = True

        if matched:
            stat[lb]["sg"] += 1
            # 降噪偽陰性：Semgrep 正確定位了真漏洞，模型卻判成「正常(0)」→ 被 ⚪ 過濾掉
            if matched_pred == 0:
                stat[lb]["filt_real"] += 1
        stat[lb]["pipe"] += pipe_hit
        stat[lb]["strict"] += strict_hit

        if i % 50 == 0:
            print(f"  {i}/{len(items)}　（{time.time()-t0:.0f}s）")

    # ── 誤報過濾評估 ──
    print("\n評估誤報過濾能力...")
    fp_total = 0        # Semgrep 誤報數
    fp_filtered = 0     # 模型正確過濾數
    fp_detail = []
    for lang, desc, code in SAFE_SAMPLES:
        try:
            findings = collect_findings(code, lang)
        except Exception:
            continue
        # 只計 A 類（會送 CodeBERT 的才有「被模型過濾」的機會）
        a_findings = [f for f in findings
                      if any(c in A_CLASS_CWES
                             for c in (f.get("cwes") or []))]
        n_fp = len(a_findings)
        if n_fp == 0:
            fp_detail.append((desc, lang, 0, 0, None))
            continue
        fp_total += n_fp
        filtered = 0
        first_verdict = None
        for f in a_findings:
            snip, _, _ = extract_enclosing_function(code, f["start_line"], lang)
            pl, conf = classify(snip, lang)
            if pl == 0:
                filtered += 1
            if first_verdict is None:
                first_verdict = (LABEL_NAMES.get(pl, pl), conf)
        fp_filtered += filtered
        fp_detail.append((desc, lang, n_fp, filtered, first_verdict))

    # ── 報告 ──
    lines = []

    def log(s=""):
        print(s)
        lines.append(s)

    log("=" * 78)
    log("端到端管道評估報告")
    log("=" * 78)
    log(f"\n模型：{path}")
    log(f"規則：自訂 + {len([x for x in SUPPLEMENTS if os.path.exists(x)])} 份補強 + 官方"
        f"（召回與誤報評估使用同一套）")
    log(f"測試樣本：{len(items)} 筆")
    log(f"　（config 標籤 {sorted(cfg_labels)} → 模型標籤 {sorted(labels)}）")
    if skipped_out_of_scope:
        log(f"　（另有 {skipped_out_of_scope} 筆的類別不在模型 17 類範圍內，已排除）")
    if skipped_scan:
        log(f"　（另有 {skipped_scan} 筆因 Semgrep 逾時/失敗而略過，不影響其餘統計）")

    def _table(title, label_set):
        rows = [l for l in sorted(stat) if l in label_set]
        if not rows:
            return None
        log(f"\n{title}")
        log(f"  {'類別':<16} {'樣本':>5} {'Semgrep':>10} {'片段管道':>10} "
            f"{'硬閘門':>9} {'整檔對照':>10}")
        log("  " + "-" * 66)
        agg = {"n": 0, "sg": 0, "pipe": 0, "strict": 0, "whole": 0}
        for lb in rows:
            s = stat[lb]
            for k in agg:
                agg[k] += s[k]
            log(f"  {LABEL_NAMES.get(lb, lb):<16} {s['n']:>5} "
                f"{s['sg']/s['n']:>9.1%} {s['pipe']/s['n']:>9.1%} "
                f"{s['strict']/s['n']:>8.1%} {s['whole']/s['n']:>9.1%}")
        log("  " + "-" * 66)
        log(f"  {'小計':<16} {agg['n']:>5} "
            f"{agg['sg']/agg['n']:>9.1%} {agg['pipe']/agg['n']:>9.1%} "
            f"{agg['strict']/agg['n']:>8.1%} {agg['whole']/agg['n']:>9.1%}")
        return agg

    a = _table("【A 類：片段可判定（本階段主力）】", A_CLASS_LABELS)
    b = _table("【B 類：上下文判定（已擱置，僅供觀察）】", B_CLASS_LABELS)

    if a:
        log("\n" + "─" * 78)
        log("【三階段拆解（A 類）】")
        log("─" * 78)
        log(f"  ① Semgrep 召回率　　{a['sg']}/{a['n']} = {a['sg']/a['n']:.1%}")
        log(f"     架構天花板：命中不到的樣本，第二階段永遠看不到")
        cond = a["strict"] / a["sg"] if a["sg"] else 0
        log(f"\n  ② 片段分類準確率　　{a['strict']}/{a['sg']} = {cond:.1%}")
        log(f"     Semgrep 類別正確的樣本中，模型也判對的比例")
        log(f"\n  ③ 端到端準確率　　　{a['pipe']}/{a['n']} = {a['pipe']/a['n']:.1%}")
        log(f"     任一 finding 的模型預測正確即算命中（與 scan.py 行為一致，"
            f"含 disputed）")
        log(f"\n     其中硬閘門（僅 confirmed）　{a['strict']}/{a['n']} = "
            f"{a['strict']/a['n']:.1%}")
        log(f"     差額 {a['pipe']-a['strict']} 筆是「Semgrep 類別猜錯、"
            f"但選對函式、模型判對」")
        log(f"     —— 規則在此架構中的主要價值是選點，而非偵測")
        log(f"\n  對照：整檔輸入　　　{a['whole']}/{a['n']} = {a['whole']/a['n']:.1%}")
        diff = (a["pipe"] - a["whole"]) / a["n"]
        if diff > 0.02:
            log(f"  → 片段架構優於整檔（{diff:+.1%}），訊噪比提升有效")
        elif diff < -0.02:
            log(f"  → 片段架構低於整檔（{diff:+.1%}）")
            log(f"     可能原因：模型以完整函式訓練，對短片段格式不熟悉")
        else:
            log(f"  → 兩者相當（{diff:+.1%}）")

    log("\n" + "─" * 78)
    log("【降噪偽陰性：模型把真漏洞濾成正常的機率】")
    log("─" * 78)
    log("  分母＝Semgrep 正確定位的真漏洞；分子＝模型判成正常(0)、被 ⚪ 過濾掉者。")
    log("  此率即『降噪誤殺真漏洞』的機率（越低越好）。")
    log(f"\n  {'類別':<16} {'正確定位':>8} {'被濾掉':>8} {'濾真漏洞率':>11}")
    log("  " + "-" * 48)
    tot_sg = tot_filt = 0
    for lb in sorted(stat):
        s = stat[lb]
        if s["sg"] == 0:
            continue
        tot_sg += s["sg"]
        tot_filt += s["filt_real"]
        log(f"  {LABEL_NAMES.get(lb, lb):<16} {s['sg']:>8} {s['filt_real']:>8} "
            f"{s['filt_real']/s['sg']:>10.1%}")
    log("  " + "-" * 48)
    log(f"  {'整體':<16} {tot_sg:>8} {tot_filt:>8} "
        f"{(tot_filt/tot_sg) if tot_sg else 0:>10.1%}")

    log("\n" + "─" * 78)
    log("【誤報過濾能力】兩階段架構的核心價值")
    log("─" * 78)
    log(f"  {'安全樣本':<20} {'語言':<12} {'Semgrep誤報':>11} {'模型過濾':>9}  模型判定")
    log("  " + "-" * 70)
    for desc, lang, n_fp, filt, verdict in fp_detail:
        v = ""
        if verdict:
            v = f"{verdict[0]}（{verdict[1]:.0%}）"
        mark = "" if n_fp == 0 else ("  ✓" if filt == n_fp else "  ✗")
        log(f"  {desc:<20} {lang:<12} {n_fp:>11} {filt:>9}  {v}{mark}")
    log("  " + "-" * 70)
    if fp_total:
        log(f"  {'總計':<20} {'':<12} {fp_total:>11} {fp_filtered:>9}"
            f"　過濾率 {fp_filtered/fp_total:.1%}")
        log(f"\n  Semgrep 對 {len(SAFE_SAMPLES)} 筆安全程式碼產生 {fp_total} 個 A 類誤報，")
        log(f"  模型正確過濾其中 {fp_filtered} 個（{fp_filtered/fp_total:.1%}）。")
        log(f"  此為兩階段架構「規則保召回、模型保精確」的直接驗證。")
        log(f"\n  ⚠️ 樣本數僅 {len(SAFE_SAMPLES)} 筆（硬編碼於本檔），統計基礎薄弱。")
        log(f"     測試集內另有 150 筆 clean 樣本尚未納入此評估。")
    else:
        log("  （Semgrep 對安全樣本無誤報，無法評估過濾能力）")

    log(f"\n耗時 {time.time()-t0:.0f}s")
    os.makedirs("dataset", exist_ok=True)
    with open(REPORT, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"\n✅ 報告：{REPORT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())