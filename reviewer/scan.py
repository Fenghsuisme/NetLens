# -*- coding: utf-8 -*-
"""
scan.py — NetLens Reviewer 完整掃描管道

流程：
    原始碼
      ↓ Semgrep（自訂 + 7 份補強 + 官方，高召回）
      ↓ typosquat_detector（惡意套件，編輯距離比對）
      ↓ 傳輸層：依 CWE 分流、抽取所在函式
      ↓ CodeBERT v6_2（17 類，高精確）
      ↓ 融合：兩引擎比對、分級、去重
    掃描報告

輸出分四級：
    ✅ 確認漏洞    Semgrep 與 CodeBERT 判定一致
    🔍 存疑        兩引擎判定不同，並列兩者結果
    ⚪ 已過濾      CodeBERT 判為正常程式碼（Semgrep 誤報）
    📋 僅 Semgrep  B 類漏洞，未經模型深析

用法：
    python scan.py path/to/file.py          掃單一檔案
    python scan.py path/to/project/         掃整個目錄
    python scan.py file.py --json           輸出 JSON（供程式介接）
    python scan.py file.py --no-model       只跑 Semgrep（不載入模型，快）
    python scan.py file.py --show-snippet   顯示片段內容

設計說明：
    v6_2 訓練時已剝除註解，故推論時亦剝除以維持條件一致。
    傳輸層抽取「整個函式」而非固定行數，因漏洞判斷需完整函式邏輯。
"""
import argparse
import glob
import json
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from transport_layer import (process, process_all, rule_paths,
                             LANG_EXT, SemgrepExecutionError)

# 模型 17 類中，哪些是「單一函式片段即可判定」的。
# 其餘（資料外洩、後門、CSRF、SSRF、檔案上傳、權限控制）需要跨檔案上下文。
# 注意：這與「模型支援哪些類別」是兩回事——模型現已支援全部 17 類
# （vuln_categories.json 3.2.0），但片段是否足以判定仍是架構性質。
FRAGMENT_JUDGEABLE_LABELS = {1, 2, 3, 6, 7, 8, 9, 10, 11, 12}
# 函式名去語意化（與訓練前處理一致）
try:
    from obfuscate import obfuscate_functions
    HAS_OBFUSCATE = True
except ImportError:
    HAS_OBFUSCATE = False
    obfuscate_functions = None

from core.config_loader import label_to_category, get_category
from label_map import config_to_model, MODEL_LABEL_NAMES

# ── 設定 ──────────────────────────────────────────
MODEL_DIR = "models/codebert_v7v8_safe"
BASE_MODEL = "microsoft/codebert-base"

# ── 前處理設定：必須與訓練條件一致 ──
# 訓練與推論的前處理若不一致，模型會看到訓練時未見過的分布
STRIP_COMMENTS = True       # 訓練資料已剝除註解（避免從 "# VULNERABILITY: X" 作弊）
OBFUSCATE_FUNCS = False     # v7v8_safe 由 merge_17class.py 產出的 train_17_v7v8.csv
                            # 訓練，該資料「未」去語意化（去語意化版是舊 v7 的
                            # train_17_v7_obfuscated.csv，非本模型）。故推論亦不去
                            # 語意化以保持一致。⚠️ 勿設 True —— 若又放回 obfuscate.py
                            # 會讓推論去語意化、反而與訓練不一致（v6_2 時期才需要）。
MAX_FILES = 500
SKIP_DIRS = {"node_modules", ".git", "venv", ".venv", "__pycache__",
             "dist", "build", "target", "vendor", ".idea", ".vscode"}

# v6_2 的 17 類（標籤順序與 v6 相同）
LABEL_NAMES = MODEL_LABEL_NAMES   # 模型體系（17 類）

# 全 17 類皆送模型判定。
#
# 先前 v6_2 時期 B 類（CSRF/SSRF/檔案上傳/權限控制）F1 僅 0.000–0.240，
# 曾判斷為「片段無法顯示缺少的防護」而擱置；
# 但 v7v8_safe 將這幾類的訓練樣本自 10–47 筆增至 438–500 筆後，
# F1 提升至 0.888–0.974（不受限檔案上傳 0.000 → 0.971），
# 顯示主因為訓練樣本不足而非本質限制，故取消特殊處理。
A_CLASS_LABELS = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
B_CLASS_LABELS = {13, 14, 15, 16}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "": 4}

# B 策略：低信心的 disputed（模型與 Semgrep 類別不一致）多為噪音。
# 抑制 model_conf < DISPUTE_CONF_MIN 的 disputed 可降誤報；confirmed 不受影響。
# 0.0 = 關閉。調法：先用 eval_clean 的信心門檻 sweep 找 FP 拐點，
# 再用 eval_e2e 確認召回代價，取兩者平衡點設定。
DISPUTE_CONF_MIN = 0.0

# D 策略：呈現分層。這些「缺少檢查」型類別本質低精確度（實測準確率 5–36%，
# 且漏洞在於缺少授權/token/過濾檢查，超出 pattern matching 能力），
# 即使模型 confirmed 也不確定，降級為「建議人工複查」而非「確認漏洞」，
# 讓「確認漏洞」清單維持高訊噪比。
LOW_TRUST_CATEGORIES = {"csrf", "idor", "broken_access_control",
                        "data_exfiltration", "ssrf"}


def _strip_comments(code):
    s = str(code)
    s = re.sub(r'"""(.*?)"""', "", s, flags=re.DOTALL)
    s = re.sub(r"'''(.*?)'''", "", s, flags=re.DOTALL)
    s = re.sub(r"/\*.*?\*/", "", s, flags=re.DOTALL)
    s = re.sub(r"//.*", "", s)
    s = re.sub(r"#.*", "", s)
    return re.sub(r"\n\s*\n+", "\n", s).strip()


def _is_loadable(d):
    """
    判斷目錄是否為可載入的模型。
    需同時具備權重與 config —— 只有 model.safetensors 而缺 config.json 時，
    transformers 會拋出 "Unrecognized model" 錯誤（實際踩過此坑：
    訓練中斷後根目錄只存了權重，config 留在 checkpoint 裡）。
    """
    has_weight = any(os.path.exists(os.path.join(d, f))
                     for f in ("model.safetensors", "pytorch_model.bin"))
    has_config = os.path.exists(os.path.join(d, "config.json"))
    return has_weight and has_config


def _resolve_model(model_dir):
    """
    找出可載入的模型位置。
    優先用根目錄的最終模型，若不完整則自動退回最新的 checkpoint。
    """
    if not os.path.isdir(model_dir):
        return None, None

    if _is_loadable(model_dir):
        return model_dir, "最終模型"

    ckpts = [c for c in glob.glob(os.path.join(model_dir, "checkpoint-*"))
             if _is_loadable(c)]
    if not ckpts:
        # 給出可診斷的錯誤訊息，而非僅回傳 None
        w = os.path.exists(os.path.join(model_dir, "model.safetensors"))
        cfg = os.path.exists(os.path.join(model_dir, "config.json"))
        if w and not cfg:
            print(f"⚠️ {model_dir} 有權重但缺 config.json")
            print(f"   若 checkpoint 內有 config，可執行：")
            print(f"   cp {model_dir}/checkpoint-*/config.json {model_dir}/")
        return None, None

    ckpts.sort(key=lambda p: int(p.split("-")[-1]))
    return ckpts[-1], f"checkpoint {os.path.basename(ckpts[-1])}"


class Scanner:
    def __init__(self, use_model=True, with_official=True):
        self.model = None
        self.tok = None
        self.device = None
        self.model_path = None
        self.with_official = with_official
        if use_model:
            self._load_model()

    def _load_model(self):
        path, kind = _resolve_model(MODEL_DIR)
        if path is None:
            raise RuntimeError(
                f"找不到模型：{MODEL_DIR}\n"
                f"　請確認該目錄下有 model.safetensors 或 checkpoint-* 子目錄")
        import torch
        from transformers import AutoTokenizer, AutoModelForSequenceClassification
        self.torch = torch
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.tok = AutoTokenizer.from_pretrained(BASE_MODEL)
        self.model = AutoModelForSequenceClassification.from_pretrained(path)
        self.model.to(self.device)
        self.model.eval()
        self.model_path = path
        self.model_kind = kind

    def classify(self, snippet, language=None):
        """回傳 (label, 名稱, 信心)"""
        if self.model is None:
            return None, None, None
        code = _strip_comments(snippet) if STRIP_COMMENTS else snippet
        if OBFUSCATE_FUNCS and HAS_OBFUSCATE and language:
            code = obfuscate_functions(code, language)
        if len(code) < 10:
            code = snippet
        enc = self.tok(code[:2000], max_length=512, padding="max_length",
                       truncation=True, return_tensors="pt").to(self.device)
        with self.torch.no_grad():
            probs = self.torch.softmax(self.model(**enc).logits, dim=1)
            label = int(self.torch.argmax(probs, dim=1).item())
            conf = float(probs[0][label].item())
        return label, LABEL_NAMES.get(label, str(label)), conf

    def scan_code(self, code, language, filename=""):
        """掃描單段程式碼，回傳結構化結果"""
        # 使用完整規則集（自訂 + 7 份補強 + 官方）。
        # 舊版呼叫 process(code, language) 只載入 rules/{language}.yml 一份，
        # 補強規則與官方規則從未在產品中執行。
        transport = process_all(code, language,
                                with_official=self.with_official)

        confirmed, disputed, filtered = [], [], []

        for item in transport["to_codebert"]:
            rec = {
                "file": filename,
                "line": item["hit_line"],
                "snippet_start": item["snippet_start"],
                "snippet_end": item["snippet_end"],
                "engine_rule": item["semgrep_rule"],
                "engine_cwe": item["semgrep_cwe"],
                "engine_category": item["semgrep_category"],
                "engine_category_zh": item["semgrep_category_zh"],
                "snippet": item["snippet"],
            }
            # 惡意套件的額外資訊
            for k in ("package", "reason", "similar_to"):
                if k in item:
                    rec[k] = item[k]

            if self.model is None:
                rec["verdict"] = "engine_only"
                confirmed.append(rec)
                continue

            label, name, conf = self.classify(item["snippet"], language)
            rec["model_label"] = label
            rec["model_name"] = name
            rec["model_conf"] = conf

            # Semgrep 的類別採 config 體系，須轉成模型體系才能比對
            sg_info = get_category(item["semgrep_category"])
            sg_model_label = (config_to_model(sg_info["label"])
                              if sg_info else None)
            if label == 0:
                rec["verdict"] = "filtered"
                filtered.append(rec)
            elif label == sg_model_label:
                rec["verdict"] = "confirmed"
                confirmed.append(rec)
            elif (item.get("fragment_judgeable")
                  and label not in FRAGMENT_JUDGEABLE_LABELS):
                # 軟閘門：Semgrep 標的是「單一函式即可判定」的類別
                # （SQL 注入、XSS 等），模型卻回答需要跨檔案上下文的類別
                # （CSRF、權限控制、後門）。片段裡沒有判斷後者所需的資訊，
                # 這種判定在架構上無效，不呈現。
                #
                # 條件加上 fragment_judgeable 是必要的：自 CWE-912 等
                # B 類 CWE 納入模型分流後，一個後門 finding 由模型正確
                # 判為「後門」時，label 5 本就不在 FRAGMENT_JUDGEABLE_LABELS
                # 內；若不檢查來源類別，正確答案會被自己的閘門刪掉。
                rec["verdict"] = "incoherent"
                rec["filter_reason"] = (
                    f"規則標的為片段可判定類別，模型卻判為需上下文的「{name}」")
                filtered.append(rec)
            elif conf is not None and conf < DISPUTE_CONF_MIN:
                # B 策略：低信心的 disputed 多為噪音，抑制不呈現
                rec["verdict"] = "low_confidence"
                rec["filter_reason"] = (
                    f"兩引擎不一致且模型信心 {conf:.0%} < {DISPUTE_CONF_MIN:.0%}")
                filtered.append(rec)
            else:
                rec["verdict"] = "disputed"
                disputed.append(rec)

        # 依行號排序
        for lst in (confirmed, disputed, filtered):
            lst.sort(key=lambda r: r["line"])

        return {
            "file": filename,
            "language": language,
            "confirmed": confirmed,
            "disputed": disputed,
            "filtered": filtered,
            "engine_only": transport["semgrep_only"],
            "skipped": transport["skipped"],
        }


def collect_files(path):
    """收集要掃描的檔案"""
    if os.path.isfile(path):
        ext = os.path.splitext(path)[1].lower()
        lang = next((l for l, e in LANG_EXT.items() if e == ext), None)
        return [(path, lang)] if lang else []

    files = []
    for root, dirs, names in os.walk(path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        for n in names:
            ext = os.path.splitext(n)[1].lower()
            lang = next((l for l, e in LANG_EXT.items() if e == ext), None)
            if lang:
                files.append((os.path.join(root, n), lang))
            if len(files) >= MAX_FILES:
                return files
    return files


def print_report(results, show_snippet=False):
    # D 策略：確認漏洞只計高信任類別；低信任 confirmed 併入建議複查
    total_c = sum(1 for r in results for x in r["confirmed"]
                  if x.get("engine_category") not in LOW_TRUST_CATEGORIES)
    total_d = sum(len(r["disputed"]) for r in results) + \
        sum(1 for r in results for x in r["confirmed"]
            if x.get("engine_category") in LOW_TRUST_CATEGORIES)
    total_f = sum(len(r["filtered"]) for r in results)
    total_e = sum(len(r["engine_only"]) for r in results)

    print("=" * 76)
    print("NetLens Reviewer 掃描報告")
    print("=" * 76)

    for r in results:
        has_any = r["confirmed"] or r["disputed"] or r["filtered"] or r["engine_only"]
        if not has_any:
            continue
        print(f"\n📄 {r['file']}（{r['language']}）")

        # D 策略：低精確度類別（CSRF/IDOR/權限/資料外洩/SSRF）即使 confirmed
        # 也降級到「建議複查」，讓「確認漏洞」維持高訊噪比。
        conf_high = [x for x in r["confirmed"]
                     if x.get("engine_category") not in LOW_TRUST_CATEGORIES]
        review = [x for x in r["confirmed"]
                  if x.get("engine_category") in LOW_TRUST_CATEGORIES] + r["disputed"]
        review.sort(key=lambda z: z["line"])

        if conf_high:
            print(f"\n  ✅ 確認漏洞（{len(conf_high)}）")
            for x in conf_high:
                conf = f"　信心 {x['model_conf']:.0%}" if x.get("model_conf") else ""
                name = x.get("model_name") or x["engine_category_zh"]
                print(f"     第 {x['line']:>4} 行　{name}"
                      f"（{x['engine_cwe']}）{conf}")
                if x.get("package"):
                    sim = f"，可能想引用 {x['similar_to']}" if x.get("similar_to") else ""
                    print(f"              套件：{x['package']}　{x['reason']}{sim}")
                if show_snippet:
                    for ln in x["snippet"].split("\n")[:12]:
                        print(f"              | {ln}")

        if review:
            print(f"\n  🔍 建議人工複查（{len(review)}）"
                  f"　低精確度類別或兩引擎不一致，需上下文判斷")
            for x in review:
                cf = f"（{x['model_conf']:.0%}）" if x.get("model_conf") else ""
                print(f"     第 {x['line']:>4} 行　"
                      f"規則：{x['engine_category_zh']}　"
                      f"模型：{x.get('model_name','?')}{cf}")

        if r["filtered"]:
            print(f"\n  ⚪ 已過濾：模型判為正常程式碼（{len(r['filtered'])}）")
            for x in r["filtered"]:
                print(f"     第 {x['line']:>4} 行　"
                      f"規則報 {x['engine_category_zh']}，"
                      f"模型判正常（{x['model_conf']:.0%}）")

        if r["engine_only"]:
            print(f"\n  📋 僅規則偵測，未經模型深析（{len(r['engine_only'])}）")
            for x in r["engine_only"]:
                print(f"     第 {x['line']:>4} 行　{x['category_zh']}（{x['cwe']}）")

    print("\n" + "=" * 76)
    print(f"摘要　確認漏洞 {total_c}　建議複查 {total_d}　"
          f"已過濾誤報 {total_f}　僅規則偵測 {total_e}")
    print("=" * 76)


def main():
    ap = argparse.ArgumentParser(description="NetLens Reviewer 掃描")
    ap.add_argument("path", help="檔案或目錄")
    ap.add_argument("--json", action="store_true", help="輸出 JSON")
    ap.add_argument("--no-model", action="store_true",
                    help="只跑規則掃描，不載入模型（速度快）")
    ap.add_argument("--show-snippet", action="store_true", help="顯示片段內容")
    ap.add_argument("--no-official", action="store_true",
                    help="不載入官方規則 p/security-audit（離線環境用）")
    ap.add_argument("--out", help="將 JSON 結果寫入檔案")
    args = ap.parse_args()

    if not os.path.exists(args.path):
        print(f"❌ 找不到 {args.path}")
        return 1

    files = collect_files(args.path)
    if not files:
        print(f"❌ 沒有可掃描的檔案（支援：{', '.join(LANG_EXT.values())}）")
        return 1

    if not args.json:
        print(f"掃描 {len(files)} 個檔案...")

    t0 = time.time()
    try:
        scanner = Scanner(use_model=not args.no_model,
                          with_official=not args.no_official)
    except RuntimeError as e:
        print(f"❌ {e}")
        return 1
    load_time = time.time() - t0

    if not args.json and scanner.model is not None:
        print(f"模型：{scanner.model_path}（{scanner.model_kind}）"
              f"　裝置：{scanner.device}　載入 {load_time:.1f}s\n")

    results = []
    t1 = time.time()
    for i, (fp, lang) in enumerate(files, 1):
        try:
            code = open(fp, encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        try:
            results.append(scanner.scan_code(code, lang, fp))
        except SemgrepExecutionError as e:
            print(f"❌ Semgrep 執行失敗：{e}")
            print("   請先執行 python semgrep_health.py 檢查")
            return 1
        if not args.json and len(files) > 5 and i % 10 == 0:
            print(f"  {i}/{len(files)}")
    scan_time = time.time() - t1

    if args.json or args.out:
        payload = {
            "model": scanner.model_path,
            "files_scanned": len(files),
            "elapsed_sec": round(scan_time, 2),
            "results": results,
        }
        text = json.dumps(payload, ensure_ascii=False, indent=2)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(text)
            print(f"✅ 已輸出：{args.out}")
        if args.json:
            print(text)
    else:
        print_report(results, args.show_snippet)
        print(f"\n掃描耗時 {scan_time:.1f}s"
              f"（{scan_time/max(1,len(files)):.2f}s/檔）")

    return 0


if __name__ == "__main__":
    sys.exit(main())