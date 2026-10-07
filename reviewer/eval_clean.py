# -*- coding: utf-8 -*-
"""
eval_clean.py — 用測試集的 clean 樣本評估誤報

與 eval_e2e.py 共用規則集與推論邏輯（直接 import，不重寫），
確保量到的是同一套系統。

輸出四個指標：
    ① Semgrep 誤報率   觸發樣本數 ÷ clean 樣本數        規則精確度
    ② 模型過濾率       過濾 finding ÷ A類 finding       模型的實際價值
    ③ 殘留誤報率       殘留樣本數 ÷ clean 樣本數        使用者實際看到的
    ③' 一致性閘門後     改用「模型預測 == Semgrep 類別」的殘留率

A / B 類必須分開看：
    A 類 → 抽片段送 CodeBERT → 有機會被過濾
    B 類 → 走 semgrep_only 直接列報告 → 完全沒有過濾，全數呈現給使用者

快取：
    Semgrep 佔總耗時約九成。第一次跑會把 finding 與模型預測寫入快取，
    之後調整閘門策略可用 --analyze-only 秒級重算。

用法：
    python eval_clean.py                  完整跑（約 30 分鐘）
    python eval_clean.py --analyze-only   只重算指標（讀快取，數秒）
    python eval_clean.py -n 20            快速冒煙測試
"""
import argparse
import json
import os
import sys
import time
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# eval_e2e.py 位於 eval/ 子目錄，需一併加入 path 才能 import collect_findings 等
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "eval"))

from testset_parser import parse_testset
from transport_layer import (extract_enclosing_function,
                             MODEL_ELIGIBLE_CWES, FRAGMENT_JUDGEABLE_CWES,
                             SKIP_CWES, SemgrepExecutionError)
from core.config_loader import get_category
from label_map import config_to_model, MODEL_LABEL_NAMES

# 與 eval_e2e 共用，避免任何不一致
from eval_e2e import (collect_findings, finding_categories,
                      _strip, _resolve_model, MODEL_DIR, BASE_MODEL,
                      STRIP_COMMENTS, OBFUSCATE_FUNCS,
                      HAS_OBFUSCATE, obfuscate_functions)

CACHE = "dataset/clean_fp_cache.json"


def classify_of(f):
    """
    finding 的分流：'A'（送模型）/ 'B'（僅列報告）/ 'skip'（孤兒 CWE）。
    依據必須與 transport_layer.process() 一致 —— 是 MODEL_ELIGIBLE_CWES
    （模型有沒有這個輸出類別），不是 FRAGMENT_JUDGEABLE_CWES。
    兩者自 vuln_categories.json 3.2.0 起不再等價。
    """
    cwes = f.get("cwes") or ([f["cwe"]] if f.get("cwe") else [])
    if not cwes:
        return "skip"
    if all(c in SKIP_CWES for c in cwes):
        return "skip"
    if any(c in MODEL_ELIGIBLE_CWES for c in cwes):
        return "A"
    return "B"


def is_fragment_judgeable(f):
    """Semgrep 標的是否為「單一函式即可判定」的類別（供軟閘門使用）。"""
    cwes = f.get("cwes") or ([f["cwe"]] if f.get("cwe") else [])
    return any(c in FRAGMENT_JUDGEABLE_CWES for c in cwes)


def semgrep_model_label(f):
    """finding 的 Semgrep 類別 → 模型標籤（供一致性閘門比對）。"""
    for cat in finding_categories(f):
        info = get_category(cat)
        if info:
            ml = config_to_model(info["label"])
            if ml is not None:
                return ml
    return None


def build_cache(limit=None):
    """跑 Semgrep + 模型，把結果寫入快取。"""
    items = parse_testset(labels={0})
    if not items:
        print("❌ 取不到 clean 樣本（config label 0）")
        return None
    if limit:
        items = items[:limit]

    path = _resolve_model(MODEL_DIR)
    if path is None:
        print(f"❌ 找不到模型：{MODEL_DIR}")
        return None
    import torch
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    tok = AutoTokenizer.from_pretrained(BASE_MODEL)
    model = AutoModelForSequenceClassification.from_pretrained(path).to(device)
    model.eval()

    def classify(code, language=None):        # 與 eval_e2e 完全相同
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
    print(f"clean 樣本：{len(items)} 筆\n")

    records = []
    t0 = time.time()
    for i, it in enumerate(items, 1):
        lang, code = it["lang"], it["code"]
        try:
            findings = collect_findings(code, lang)
        except SemgrepExecutionError as e:
            print(f"❌ Semgrep 失敗：{e}")
            return None

        rec = {"lang": lang, "findings": []}
        for f in findings:
            kind = classify_of(f)
            entry = {
                "rule": f.get("rule_id", "?"),
                "cwes": f.get("cwes") or [],
                "line": f.get("start_line"),
                "kind": kind,
                "frag": is_fragment_judgeable(f),
                "sg_label": semgrep_model_label(f),
                "pred": None,
                "conf": None,
            }
            # 只有 A 類會送模型（與生產環境的 process() 一致）
            if kind == "A" and entry["line"]:
                snip, _, _ = extract_enclosing_function(code, entry["line"], lang)
                pl, conf = classify(snip, lang)
                entry["pred"] = pl
                entry["conf"] = round(conf, 4)
            rec["findings"].append(entry)
        records.append(rec)

        if i % 25 == 0:
            print(f"  {i}/{len(items)}　（{time.time()-t0:.0f}s）")

    os.makedirs(os.path.dirname(CACHE), exist_ok=True)
    with open(CACHE, "w", encoding="utf-8") as fh:
        json.dump(records, fh, ensure_ascii=False)
    print(f"\n✅ 快取：{CACHE}　（耗時 {time.time()-t0:.0f}s）")
    return records


_A_PRED = {1, 2, 3, 6, 7, 8, 9, 10, 11, 12}


def _residual_at_conf(records, T):
    """信心門檻殘留：在軟閘門之上，再抑制「disputed 且模型信心 < T」的 finding。
    confirmed（模型與 Semgrep 一致）不受門檻影響。回傳殘留樣本數。"""
    resid = 0
    for rec in records:
        for f in rec["findings"]:
            if f["kind"] != "A":
                continue
            pred, sg = f["pred"], f["sg_label"]
            if pred == 0:                       # 模型判正常，已濾掉
                continue
            frag = f.get("frag", True)
            if not ((not frag) or pred in _A_PRED):   # 軟閘門殺掉
                continue
            agree = (sg is not None and pred == sg)
            if not agree and (f.get("conf") or 0) < T:  # 低信心 disputed 抑制
                continue
            resid += 1
            break
    return resid


def analyze(records):
    n = len(records)
    name = lambda l: MODEL_LABEL_NAMES.get(l, str(l))

    # 模型 17 類中，哪些是「片段可判定」的 A 類
    A_PRED = {1, 2, 3, 6, 7, 8, 9, 10, 11, 12}

    a_total = a_filtered = 0
    b_total = skip_total = 0
    fired_a = fired_any = 0
    resid_now = resid_soft = resid_hard = 0
    kill_soft = kill_hard = 0

    surv_rule = Counter(); all_rule = Counter()
    surv_pred = Counter()
    b_rule = Counter()
    mismatch_b = Counter()        # 模型答 B 類 → 架構上無效
    mismatch_a = Counter()        # 模型答另一個 A 類 → 可能是對的

    for rec in records:
        fs = rec["findings"]
        a = [f for f in fs if f["kind"] == "A"]
        b = [f for f in fs if f["kind"] == "B"]
        skip_total += sum(1 for f in fs if f["kind"] == "skip")
        b_total += len(b)
        for f in b:
            b_rule[f["rule"]] += 1
        if fs:
            fired_any += 1
        if a:
            fired_a += 1
        a_total += len(a)

        alive_now = alive_soft = alive_hard = 0
        for f in a:
            all_rule[f["rule"]] += 1
            pred, sg = f["pred"], f["sg_label"]
            if pred == 0:
                a_filtered += 1
                continue

            alive_now += 1
            surv_rule[f["rule"]] += 1
            surv_pred[name(pred)] += 1

            agree = (sg is not None and pred == sg)
            sg_zh = name(sg) if sg is not None else "?"
            frag = f.get("frag", True)

            # 軟閘門：僅當 Semgrep 標的為「片段可判定」的類別時才套用。
            # 若不檢查來源，一個後門 finding 被模型正確判為「後門」（label 5）
            # 也會因為 5 不在 A_PRED 內而被誤殺 —— 與 scan.py 同一條件。
            if (not frag) or pred in A_PRED:
                alive_soft += 1
            else:
                kill_soft += 1
                mismatch_b[(sg_zh, name(pred))] += 1

            # 硬閘門：要求模型預測與 Semgrep 類別完全一致
            if agree:
                alive_hard += 1
            else:
                kill_hard += 1
                if pred in A_PRED:
                    mismatch_a[(sg_zh, name(pred))] += 1

        if alive_now:
            resid_now += 1
        if alive_soft:
            resid_soft += 1
        if alive_hard:
            resid_hard += 1

    W = 68
    print("\n" + "=" * W)
    print(f"clean 樣本 {n} 筆")
    print("=" * W)
    print(f"  Semgrep finding 總數        {a_total + b_total + skip_total}")
    print(f"    送 CodeBERT（模型可判定）   {a_total}")
    print(f"    僅列報告（模型不支援）      {b_total}")
    print(f"    孤兒 CWE（跳過）           {skip_total}")

    print("\n" + "-" * W)
    print("【A 類 = 模型可判定（codebert_supported），會送 CodeBERT】")
    print("-" * W)
    print(f"  ① Semgrep 誤報率   {fired_a}/{n} = {fired_a/n:.1%}")
    if a_total:
        print(f"  ② 模型過濾率       {a_filtered}/{a_total} = {a_filtered/a_total:.1%}")

    print(f"\n  ③ 殘留誤報率　三種閘門對照")
    print(f"    {'閘門':<28}{'殘留樣本':>10}{'殘留率':>10}{'額外壓掉':>10}")
    print("    " + "-" * 58)
    print(f"    {'現行（pred != clean）':<28}{resid_now:>10}{resid_now/n:>10.1%}{'—':>10}")
    print(f"    {'軟（壓掉 B 類預測）':<28}{resid_soft:>10}{resid_soft/n:>10.1%}{kill_soft:>10}")
    print(f"    {'硬（pred == Semgrep）':<28}{resid_hard:>10}{resid_hard/n:>10.1%}{kill_hard:>10}")
    if resid_now:
        print(f"\n    軟閘門降幅 {(resid_now-resid_soft)/resid_now:>5.0%}"
              f"　　硬閘門降幅 {(resid_now-resid_hard)/resid_now:>5.0%}")
        print(f"    軟閘門壓掉的都是「A 類片段 → B 類預測」，架構上本就無效，零風險。")
        print(f"    硬閘門另外壓掉 {kill_hard - kill_soft} 個 A 類間的不一致，"
              f"其中可能有正確偵測。")

    # 信心門檻 sweep：在軟閘門之上，抑制低信心的 disputed（B 策略）
    # 只砍「模型與 Semgrep 不一致且信心低」的 finding，confirmed 不受影響。
    print(f"\n  ④ 信心門檻（軟閘門之上，抑制 disputed 且 conf < T）")
    print(f"    {'門檻 T':<28}{'殘留樣本':>10}{'殘留率':>10}")
    print("    " + "-" * 48)
    for T in (0.0, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95):
        r = _residual_at_conf(records, T)
        tag = "（＝軟閘門）" if T == 0.0 else ""
        print(f"    {('conf ≥ %.2f' % T):<28}{r:>10}{r/n:>10.1%}  {tag}")
    print("    註：此表只反映 FP 下降；召回代價需另用 eval_e2e 對照。")

    if b_total:
        print("\n" + "-" * W)
        print("【僅列報告：模型不支援的類別（記憶體類），無過濾】")
        print("-" * W)
        for r, c in b_rule.most_common(10):
            print(f"  {c:>4}  {r}")

    if surv_rule:
        print("\n" + "-" * W)
        print("【現行閘門下，模型濾不掉的 A 類規則】")
        print("-" * W)
        for r, c in surv_rule.most_common(15):
            print(f"  {c:>4}/{all_rule[r]:<4}  {r}")

    if mismatch_b:
        print("\n" + "-" * W)
        print("【軟閘門會壓掉的：片段可判類別 → 需上下文類別（架構上無效）】")
        print("-" * W)
        for (sg, pred), c in mismatch_b.most_common(15):
            print(f"  {c:>4}  {sg:<16} → {pred}")

    if mismatch_a:
        print("\n" + "-" * W)
        print("【硬閘門才會壓掉的：A 類間不一致（可能是正確偵測）】")
        print("-" * W)
        for (sg, pred), c in mismatch_a.most_common(15):
            print(f"  {c:>4}  {sg:<16} → {pred}")

    if surv_pred:
        print("\n  模型把誤報判成什麼：")
        for k, v in surv_pred.most_common():
            print(f"  {v:>4}  {k}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--analyze-only", action="store_true",
                    help="讀快取重算指標，不跑 Semgrep 與模型")
    ap.add_argument("-n", "--limit", type=int, help="限制樣本數（冒煙測試）")
    args = ap.parse_args()

    if args.analyze_only:
        if not os.path.exists(CACHE):
            print(f"❌ 找不到快取 {CACHE}，請先完整跑一次")
            return 1
        records = json.load(open(CACHE, encoding="utf-8"))
        print(f"讀取快取：{CACHE}（{len(records)} 筆）")
    else:
        records = build_cache(args.limit)
        if records is None:
            return 1

    analyze(records)
    return 0


if __name__ == "__main__":
    sys.exit(main())