# -*- coding: utf-8 -*-
"""
diagnose_hits.py — 診斷樣本被哪些規則命中、對應到哪些類別

用途：查證統計矛盾。
  例：rule_experiment 顯示 Python 硬編碼密碼召回 0/3，
      但 show_missed 顯示跨語言只漏 1 筆 Java。
      → 代表那 3 筆 Python「有被抓到，但沒對應到硬編碼密碼類別」。
      本腳本印出每筆被哪些規則命中、各自對應什麼 CWE/類別，
      即可判斷是「規則搶先命中」還是「CWE 對應鏈斷裂」。

用法：
  python diagnose_hits.py hardcoded_secret python
  python diagnose_hits.py sql_injection
  （第二參數省略 = 全部語言）
"""
import os
import re
import sys

# 已移入子目錄，需往上一層才能 import 到 reviewer/ 下的模組
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from transport_layer import run_semgrep
from core.config_loader import (normalize_label, get_category,
                                cwe_to_category, label_to_category)

TEST_FILE = "test_code/real_test/security_training_dataset_v1.txt"

# 要比對的規則來源
RULE_SETS = {
    "自訂": lambda lang: f"rules/{lang}.yml",
    "補強": lambda lang: "rules/supplement_hardcoded.yml",
    "官方": lambda lang: "p/security-audit",
}


def parse_samples(target_cat, lang_filter=None):
    if not os.path.exists(TEST_FILE):
        print(f"❌ 找不到 {TEST_FILE}")
        return []
    target_label = get_category(target_cat)["label"]
    content = open(TEST_FILE, encoding="utf-8").read()
    out = []
    for block in content.split("---SPLIT---"):
        block = block.strip()
        if not block:
            continue
        lm = re.search(r"###LABEL:(\S+)", block)
        langm = re.search(r"###LANG:(\S+)", block)
        if not lm or not langm:
            continue
        lang = langm.group(1).strip().lower()
        if lang_filter and lang != lang_filter:
            continue
        canon = normalize_label(lm.group(1).strip())
        if not canon or get_category(canon)["label"] != target_label:
            continue
        cm = re.search(r"```\w*\n(.*?)```", block, re.DOTALL)
        if not cm:
            continue
        code = cm.group(1).strip()
        if len(code) >= 30:
            out.append((lang, code))
    return out


def main():
    if len(sys.argv) < 2:
        print("用法：python diagnose_hits.py <類別> [語言]")
        print("例：python diagnose_hits.py hardcoded_secret python")
        return

    target = sys.argv[1]
    lang_filter = sys.argv[2] if len(sys.argv) > 2 else None

    info = get_category(target)
    if not info:
        print(f"❌ 找不到類別 {target}")
        return
    target_label = info["label"]
    target_zh = info.get("name_zh", target)

    samples = parse_samples(target, lang_filter)
    print("=" * 74)
    print(f"診斷：「{target_zh}」（label {target_label}）")
    print(f"語言：{lang_filter or '全部'}　樣本數：{len(samples)}")
    print("=" * 74)

    if not samples:
        print("（無符合的樣本）")
        return

    hit_target_count = 0

    for i, (lang, code) in enumerate(samples, 1):
        print(f"\n{'─' * 74}")
        print(f"樣本 {i}（{lang}）")
        print("─" * 74)
        # 顯示程式碼前幾行供辨識
        for ln in code.split("\n")[:6]:
            print(f"   | {ln[:70]}")
        if len(code.split("\n")) > 6:
            print(f"   | ...（共 {len(code.split(chr(10)))} 行）")

        any_target = False
        print(f"\n   命中的規則：")
        for set_name, path_fn in RULE_SETS.items():
            path = path_fn(lang)
            # 補強規則只在存在時跑
            if set_name == "補強" and not os.path.exists(path):
                continue
            try:
                findings = run_semgrep(code, lang, path)
            except Exception as e:
                print(f"     [{set_name}] 執行失敗：{e}")
                continue
            if not findings:
                print(f"     [{set_name}] （無命中）")
                continue
            for f in findings:
                cwe = f.get("cwe")
                rule_id = f.get("rule_id", "?").split(".")[-1]
                cat = cwe_to_category(cwe) if cwe else None
                cat_info = get_category(cat) if cat else None
                cat_zh = cat_info.get("name_zh") if cat_info else "—對不到類別"
                is_target = cat_info and cat_info["label"] == target_label
                if is_target:
                    any_target = True
                mark = "  ★命中目標" if is_target else ""
                print(f"     [{set_name}] 第{f.get('start_line')}行 "
                      f"{rule_id:<38} {str(cwe):<10} → {cat_zh}{mark}")

        if any_target:
            hit_target_count += 1
            print(f"\n   ✓ 有命中目標類別")
        else:
            print(f"\n   ✗ 未命中目標類別（可能被其他規則搶先，或 CWE 對應斷裂）")

    print("\n" + "=" * 74)
    print(f"總結：{hit_target_count}/{len(samples)} 筆命中目標類別「{target_zh}」")
    print("=" * 74)
    print("\n判讀：")
    print("  若樣本有被其他規則命中但非目標類別 → 規則搶先/CWE歸類問題")
    print("  若完全沒有任何規則命中           → 規則涵蓋不足，需補 pattern")
    print("  若命中的 CWE 對不到類別          → config 的 CWE 對應鏈斷裂")


if __name__ == "__main__":
    main()