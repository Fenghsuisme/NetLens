# -*- coding: utf-8 -*-
"""tmp_eval_clean.py — 用與 eval_e2e 完全相同的規則集與推論邏輯評估誤報。
放在專案根目錄執行：python tmp_eval_clean.py
"""
import os, sys, time
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "eval"))

from testset_parser import parse_testset
from transport_layer import (run_semgrep, extract_enclosing_function,
                             SemgrepExecutionError)
from core.config_loader import cwe_to_category
# 直接沿用 eval_e2e 的設定，避免任何不一致
from eval_e2e import (rule_paths, _strip, _resolve_model,
                      MODEL_DIR, BASE_MODEL,
                      STRIP_COMMENTS, OBFUSCATE_FUNCS,
                      HAS_OBFUSCATE, obfuscate_functions,
                      LABEL_NAMES)

INCLUDE_TYPOSQUAT = True     # 生產管道會跑，這裡也跑


def main():
    items = parse_testset(labels={0})          # ← 只取 clean
    if not items:
        print("❌ 取不到 clean 樣本，確認 label 0 是否為 clean")
        return 1

    path = _resolve_model(MODEL_DIR)
    if path is None:
        print(f"❌ 找不到模型：{MODEL_DIR}")
        return 1
    import torch
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    tok = AutoTokenizer.from_pretrained(BASE_MODEL)
    model = AutoModelForSequenceClassification.from_pretrained(path).to(device)
    model.eval()

    def classify(code, language=None):          # 與 eval_e2e line 220 相同
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
    print(f"clean 樣本：{len(items)} 筆")
    print(f"規則集：與 eval_e2e 相同（自訂 + 補強 + 官方）\n")

    n = len(items)
    fired = residual = 0
    fp_total = fp_filtered = 0
    surv_rule = defaultdict(int)      # 模型濾不掉的規則
    surv_pred = defaultdict(int)      # 模型誤判成什麼
    all_rule = defaultdict(int)

    t0 = time.time()
    for i, it in enumerate(items, 1):
        lang, code = it["lang"], it["code"]
        seen, findings = set(), []

        for rp in rule_paths(lang):
            if not str(rp).startswith(("p/", "r/")) and not os.path.exists(rp):
                continue
            try:
                for f in run_semgrep(code, lang, rp):
                    cwe = f.get("cwe")
                    if not cwe or not cwe_to_category(cwe):
                        continue
                    key = (f.get("start_line"), cwe)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(f)
            except SemgrepExecutionError as e:
                print(f"❌ Semgrep 失敗：{e}")
                return 1
            except Exception:
                continue

        if INCLUDE_TYPOSQUAT:
            try:
                from typosquat_detector import scan_imports
                for ts in scan_imports(code, lang) or []:
                    key = (ts["line"], "CWE-829")
                    if key not in seen:
                        seen.add(key)
                        findings.append({"start_line": ts["line"],
                                         "cwe": "CWE-829",
                                         "check_id": "typosquat_detector"})
            except Exception:
                pass

        if not findings:
            continue

        fired += 1
        fp_total += len(findings)
        alive = 0
        for f in findings:
            rid = f.get("check_id", f.get("rule_id", "?"))
            all_rule[rid] += 1
            snip, _, _ = extract_enclosing_function(code, f["start_line"], lang)
            pl, _ = classify(snip, lang)
            if pl == 0:
                fp_filtered += 1
            else:
                alive += 1
                surv_rule[rid] += 1
                surv_pred[LABEL_NAMES.get(pl, pl)] += 1
        if alive:
            residual += 1

        if i % 25 == 0:
            print(f"  {i}/{n}　（{time.time()-t0:.0f}s）")

    print("\n" + "=" * 62)
    print(f"① Semgrep 誤報率（樣本層）  {fired}/{n} = {fired/n:.1%}")
    print(f"   Semgrep 誤報數（finding） {fp_total}")
    if fp_total:
        print(f"② 模型過濾率（finding層）  {fp_filtered}/{fp_total} = {fp_filtered/fp_total:.1%}")
    print(f"③ 殘留誤報率（樣本層）      {residual}/{n} = {residual/n:.1%}")
    print("=" * 62)

    if surv_rule:
        print("\n模型濾不掉的規則（真正該修的）：")
        for k, v in sorted(surv_rule.items(), key=lambda x: -x[1])[:15]:
            print(f"  {v:>4}/{all_rule[k]:<4}  {k}")
        print("\n模型把誤報判成什麼：")
        for k, v in sorted(surv_pred.items(), key=lambda x: -x[1]):
            print(f"  {v:>4}  {k}")

    print(f"\n耗時 {time.time()-t0:.0f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())