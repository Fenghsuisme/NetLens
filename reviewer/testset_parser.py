# -*- coding: utf-8 -*-
"""
testset_parser.py — 測試集解析的單一事實來源

背景：
  先前 test_v6_real.py / rule_experiment.py / inspect_testset.py
  各自寫了解析邏輯，導致同一份測試檔解析出 94 / 21 / 10 三種不同筆數，
  所有基於這些數字的實驗結論都不可靠。

  根因：測試檔格式不一致
    前 10 筆：###DESC: 之後有 ```python ... ``` 程式碼區塊
    後 84 筆：###DESC: 之後直接接程式碼，無 ``` 標記

  本模組統一處理兩種格式，供所有腳本 import 使用。

用法：
  from testset_parser import parse_testset
  items = parse_testset()                       # 全部
  items = parse_testset(lang="python")          # 只要 python
  items = parse_testset(labels={1,2,3})         # 只要特定 label
  # 回傳 [{"label", "category", "category_zh", "lang", "code", "desc"}]

直接執行可看測試集組成：
  python testset_parser.py
"""
import os
import re
import sys
from collections import defaultdict, Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from core.config_loader import normalize_label, get_category

# 測試集優先序：新版（2742筆/18類）→ 舊版（94筆/10類，保留供對照）
TEST_FILE_CANDIDATES = [
    "test_code/real_test/testset_merged.txt",
    "test_code/real_test/security_training_dataset_v1.txt",
]


def _default_test_file():
    for p in TEST_FILE_CANDIDATES:
        if os.path.exists(p):
            return p
    return TEST_FILE_CANDIDATES[0]


DEFAULT_TEST_FILE = None   # 執行時才決定，見 parse_testset
MIN_CODE_LEN = 30


def _extract_code(block):
    """
    從一個區段抽出程式碼，相容兩種格式：
      格式A：```python\n...\n```      → 取區塊內容
      格式B：###DESC: 之後直接是程式碼  → 取 DESC 行之後的全部
    """
    # 格式 A
    m = re.search(r"```\w*\n(.*?)```", block, re.DOTALL)
    if m:
        return m.group(1).strip()

    # 格式 B：取 ###DESC: 那行之後的內容
    pos = block.find("###DESC:")
    if pos == -1:
        return None
    nl = block.find("\n", pos)
    if nl == -1:
        return None
    code = block[nl + 1:].strip()
    # 去掉可能殘留的 ``` 標記
    code = re.sub(r"^```\w*\s*", "", code)
    code = re.sub(r"```\s*$", "", code)
    return code.strip()


def parse_testset(path=None, lang=None, labels=None, verbose=False):
    """
    解析測試集。

    參數：
      path    測試檔路徑
      lang    只取此語言（"python" 等），None = 全部
      labels  只取這些 label（set），None = 全部
      verbose 印出解析過程統計

    回傳：
      [{"label", "category", "category_zh", "lang", "code", "desc"}, ...]
    """
    if path is None:
        path = _default_test_file()
    if not os.path.exists(path):
        if verbose:
            print(f"❌ 找不到 {path}")
            print(f"   （已嘗試：{', '.join(TEST_FILE_CANDIDATES)}）")
        return []

    content = open(path, encoding="utf-8").read()
    blocks = content.split("---SPLIT---")

    items = []
    stat = Counter()
    unmapped = []

    for block in blocks:
        block = block.strip()
        if not block:
            continue
        stat["區段"] += 1

        lm = re.search(r"###LABEL:(\S+)", block)
        if not lm:
            stat["無LABEL"] += 1
            continue
        raw_label = lm.group(1).strip()

        code = _extract_code(block)
        if not code:
            stat["無法抽出程式碼"] += 1
            continue
        if len(code) < MIN_CODE_LEN:
            stat["程式碼過短"] += 1
            continue

        langm = re.search(r"###LANG:(\S+)", block)
        item_lang = langm.group(1).strip().lower() if langm else "unknown"

        descm = re.search(r"###DESC:(.*)", block)
        desc = descm.group(1).strip() if descm else ""

        canon = normalize_label(raw_label)
        if not canon:
            unmapped.append(raw_label)
            stat["標籤無法對應"] += 1
            continue
        info = get_category(canon)

        stat["成功"] += 1

        # 過濾
        if lang and item_lang != lang:
            continue
        if labels is not None and info["label"] not in labels:
            continue

        items.append({
            "label": info["label"],
            "category": canon,
            "category_zh": info.get("name_zh", canon),
            "lang": item_lang,
            "code": code,
            "desc": desc,
        })

    if verbose:
        print(f"解析 {path}")
        for k, v in stat.most_common():
            print(f"  {k:<16} {v}")
        if unmapped:
            print(f"  無法對應的標籤：{dict(Counter(unmapped))}")
        print(f"  套用篩選後回傳：{len(items)} 筆")

    return items


def _show_composition():
    """印出測試集組成表"""
    used = _default_test_file()
    print(f"使用測試集：{used}\n")
    items = parse_testset(verbose=True)
    if not items:
        return

    grid = defaultdict(Counter)
    for it in items:
        grid[(it["label"], it["category_zh"])][it["lang"]] += 1

    langs = sorted({it["lang"] for it in items})

    print("\n" + "=" * (30 + 11 * len(langs) + 8))
    print("測試集組成（類別 × 語言）")
    print("=" * (30 + 11 * len(langs) + 8))
    print(f"{'label':<6} {'類別':<20} " +
          "".join(f"{l[:10]:>11}" for l in langs) + f"{'合計':>8}")
    print("-" * (30 + 11 * len(langs) + 8))
    for key in sorted(grid.keys()):
        label, zh = key
        row = grid[key]
        line = f"{label:<6} {zh:<20} "
        for l in langs:
            line += f"{row.get(l, 0):>11}"
        line += f"{sum(row.values()):>8}"
        print(line)
    print("-" * (30 + 11 * len(langs) + 8))
    tot = f"{'':6} {'合計':<20} "
    for l in langs:
        tot += f"{sum(c.get(l, 0) for c in grid.values()):>11}"
    tot += f"{len(items):>8}"
    print(tot)

    # A 類 10 種涵蓋度
    A_CLASS = {1: "指令注入", 2: "SQL注入", 3: "程式碼執行", 6: "弱加密",
               7: "硬編碼密碼", 8: "路徑遊走", 9: "不安全反序列化",
               10: "跨站腳本", 11: "原型污染", 12: "惡意套件"}
    print(f"\n【A 類 10 種的測試樣本數】")
    counts = Counter(it["label"] for it in items)
    for label, name in A_CLASS.items():
        n = counts.get(label, 0)
        if n == 0:
            mark = "  ✗ 無樣本，無法評估"
        elif n < 5:
            mark = "  ⚠️ 樣本過少，統計意義有限"
        else:
            mark = "  ✓"
        print(f"  {label:>2} {name:<14} {n:>3} 筆{mark}")

    B_CLASS = {4: "資料外洩", 5: "後門", 13: "CSRF", 14: "SSRF",
               15: "IDOR", 16: "檔案上傳", 17: "權限控制缺陷", 0: "正常程式碼"}
    print(f"\n【非 A 類（B類/擱置/clean）的樣本】")
    for label, n in sorted(counts.items()):
        if label not in A_CLASS:
            zh = B_CLASS.get(label) or next(
                (z for (l, z) in grid if l == label), str(label))
            print(f"  {label:>2} {zh:<14} {n:>3} 筆")


if __name__ == "__main__":
    _show_composition()