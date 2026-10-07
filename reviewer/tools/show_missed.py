# -*- coding: utf-8 -*-
"""
show_missed.py — 檢視 Semgrep 抓不到的樣本（用於設計新規則）

修正說明：
  舊版自己寫解析邏輯，只認 ```code``` 區塊，
  導致 94 筆測試集只解析到 10 筆
  （其餘 84 筆是「###DESC: 後直接接程式碼」格式），
  於是「SQL 注入漏 4 筆」被誤報成「漏 0 筆」。
  現改用 testset_parser 共用解析器，與 rule_experiment_v2 基準一致。

規則來源與 rule_experiment_v2 的 D 組相同（自訂 + 補強 + 官方）。

用法：
  python show_missed.py sql_injection          # 全語言
  python show_missed.py sql_injection python   # 限定語言
  python show_missed.py xss --brief            # 只列摘要
"""
import os
import sys

# 已移入子目錄，需往上一層才能 import 到 reviewer/ 下的模組
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from testset_parser import parse_testset
from transport_layer import run_semgrep, SemgrepExecutionError, SUPPLEMENT_RULES
from core.config_loader import get_category, cwe_to_category

# 直接沿用生產端的補強規則清單，避免與 transport_layer 不同步
# （舊版硬編碼 7 份，缺 backdoor/csrf，量到的漏抓分流不代表生產行為）
SUPPLEMENTS = SUPPLEMENT_RULES
MAX_SHOW = 1200


def rule_paths(lang):
    paths = [f"rules/{lang}.yml"]
    paths += [p for p in SUPPLEMENTS if os.path.exists(p)]
    paths.append("p/security-audit")
    return paths


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    brief = "--brief" in sys.argv

    if not args:
        print("用法：python show_missed.py <類別> [語言] [--brief]")
        print("類別例：sql_injection / xss / path_traversal / weak_cryptography")
        return

    target = args[0]
    lang_filter = args[1] if len(args) > 1 else None

    info = get_category(target)
    if not info:
        print(f"找不到類別 {target}")
        return
    target_label = info["label"]
    target_zh = info.get("name_zh", target)

    items = parse_testset(lang=lang_filter, labels={target_label})
    if not items:
        print(f"測試集中沒有「{target_zh}」的樣本")
        return

    print("=" * 74)
    print(f"檢視「{target_zh}」抓不到的樣本")
    print(f"語言：{lang_filter or '全部'}　樣本數：{len(items)}")
    print(f"規則：自訂 + 補強 + 官方（同實驗 D 組）")
    print("=" * 74)

    missed = []
    errors = 0

    for it in items:
        hit = False
        hit_cwes = set()
        for path in rule_paths(it["lang"]):
            if not str(path).startswith(("p/", "r/")) and not os.path.exists(path):
                continue
            try:
                for f in run_semgrep(it["code"], it["lang"], path):
                    cwe = f.get("cwe")
                    if not cwe:
                        continue
                    hit_cwes.add(cwe)
                    cat = cwe_to_category(cwe)
                    if cat:
                        ci = get_category(cat)
                        if ci and ci["label"] == target_label:
                            hit = True
            except SemgrepExecutionError as e:
                print(f"\nSemgrep 執行失敗：{e}")
                print("   結果不可信，請先跑 python semgrep_health.py")
                errors += 1
                break
            except Exception:
                continue
        if not hit:
            missed.append((it, sorted(hit_cwes)))

    if errors:
        print(f"\n有 {errors} 筆因執行失敗未能判定，請修復 Semgrep 後重跑")
        return

    print(f"\n抓到：{len(items) - len(missed)}/{len(items)}　漏抓：{len(missed)} 筆\n")

    for i, (it, other_cwes) in enumerate(missed, 1):
        print("=" * 74)
        print(f"漏抓樣本 {i}（{it['lang']}）")
        if other_cwes:
            print(f"  被其他規則命中的 CWE：{', '.join(other_cwes)}")
        else:
            print(f"  完全沒有任何規則命中")
        if it.get("desc"):
            print(f"  情境：{it['desc'][:80]}")
        print("=" * 74)
        if not brief:
            code = it["code"]
            print(code[:MAX_SHOW])
            if len(code) > MAX_SHOW:
                print(f"\n...（後略 {len(code) - MAX_SHOW} 字元）")
        print()

    if missed:
        print("=" * 74)
        print("設計新規則時的參考：")
        print("  1. 看這些樣本用了什麼寫法，現有 pattern 為何抓不到")
        print("  2. 若「被其他規則命中」→ 可能是 CWE 對應問題，非 pattern 問題")
        print("  3. 若「完全沒命中」→ 是 pattern 涵蓋不足，需補新 pattern")
        print("=" * 74)


if __name__ == "__main__":
    main()