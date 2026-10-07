# -*- coding: utf-8 -*-
"""
merge_testsets.py — 合併並清洗測試集

輸入：
  testset_18class.txt       完整 18 類，每類約 150 筆
  dataset_1317_verify.txt   B 類 5 種補充，各 10 筆

處理：
  1. 修復可救的格式問題（如 LABEL: 少了開頭的 ###）
  2. 剔除生成失敗的樣本（AI 思考過程外洩，特徵是長度異常 + 自言自語）
  3. 跨檔去重（用程式碼指紋）
  4. 標籤正規化（用 config_loader，處理別名）
  5. 輸出統一格式 + 統計報告

生成失敗的判定依據（實測發現）：
  - 長度異常（>50000 字元，正常樣本多在 500-3000）
  - 含思考殘留關鍵詞（"Make sure"、"I'll produce"、"Write the code"）
  - 重複片語（如 "response. response. response." 連續出現）

輸出：
  test_code/real_test/testset_merged.txt   合併後的測試集
  dataset/testset_merge_report.txt          報告

執行：
  python merge_testsets.py
  python merge_testsets.py --in a.txt b.txt --out merged.txt
"""
import argparse
import hashlib
import os
import re
import sys
from collections import Counter, defaultdict

# 已移入子目錄，需往上一層才能 import 到 reviewer/ 下的模組
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from core.config_loader import normalize_label, get_category
    HAS_CONFIG = True
except Exception:
    HAS_CONFIG = False

DEFAULT_INPUTS = [
    "testset_18class.txt",
    "dataset_1317_verify.txt",
]
DEFAULT_OUT = "test_code/real_test/testset_merged.txt"
REPORT = "dataset/testset_merge_report.txt"

MAX_CODE_LEN = 20000      # 超過此長度視為生成異常
MIN_CODE_LEN = 30
MAX_BLOCK_LEN = 50000     # 整個區段的長度上限

# 生成失敗的特徵：模型的思考過程外洩
THINKING_MARKERS = [
    "make sure description", "i'll produce", "write the code",
    "write verify line", "final output", "self-check:",
    "need to include import", "better to just write",
    "output format", "ensure length",
]


def looks_like_thinking_leak(text):
    """判斷是否為 AI 思考過程外洩"""
    low = text[:3000].lower()
    hits = sum(1 for m in THINKING_MARKERS if m in low)
    if hits >= 2:
        return True, f"含 {hits} 個思考殘留標記"
    # 重複片語（如 "response. response. response."）
    m = re.search(r"((?:\b\w+\b[.,]\s+){1,3})\1{5,}", text[:5000])
    if m:
        return True, "含大量重複片語"
    return False, None


def fix_label_line(block):
    """
    修復可救的格式問題：
      LABEL:xxx  →  ###LABEL:xxx（少了開頭的 ###）
    """
    fixed = False
    # 只在行首且該行沒有 ### 前綴時修復
    new = re.sub(r"(?m)^(?<!#)(LABEL|LANG|DESC|VERIFY):", r"###\1:", block)
    if new != block:
        fixed = True
    return new, fixed


def extract_code(block):
    """抽出程式碼，相容有無 ``` 標記兩種格式"""
    m = re.search(r"```\w*\r?\n(.*?)```", block, re.DOTALL)
    if m:
        return m.group(1).strip()
    for marker in ("###VERIFY:", "###DESC:"):
        pos = block.find(marker)
        if pos != -1:
            nl = block.find("\n", pos)
            if nl == -1:
                continue
            code = block[nl + 1:].strip()
            code = re.sub(r"^```\w*\s*", "", code)
            code = re.sub(r"```\s*$", "", code)
            return code.strip()
    return None


def fingerprint(code):
    return hashlib.md5(re.sub(r"\s+", "", code).lower().encode()).hexdigest()


def parse_file(path):
    """解析單一檔案，回傳 (樣本清單, 統計)"""
    if not os.path.exists(path):
        return [], {"檔案不存在": 1}

    content = open(path, encoding="utf-8", errors="ignore").read()
    content = content.replace("\r\n", "\n")
    blocks = content.split("---SPLIT---")

    items = []
    stat = Counter()
    rejected = []

    for i, raw in enumerate(blocks):
        block = raw.strip()
        if not block:
            continue
        stat["區段"] += 1

        # 整段過長 → 生成異常
        if len(block) > MAX_BLOCK_LEN:
            stat["剔除:區段過長"] += 1
            rejected.append((i, f"區段 {len(block)} 字元（上限 {MAX_BLOCK_LEN}）"))
            continue

        # 思考過程外洩
        leak, reason = looks_like_thinking_leak(block)
        if leak:
            stat["剔除:思考外洩"] += 1
            rejected.append((i, reason))
            continue

        # 嘗試修復格式
        block, fixed = fix_label_line(block)
        if fixed:
            stat["修復:標籤格式"] += 1

        lm = re.search(r"###LABEL:(\S+)", block)
        if not lm:
            stat["剔除:無標籤"] += 1
            rejected.append((i, "無 ###LABEL"))
            continue
        raw_label = lm.group(1).strip()

        code = extract_code(block)
        if not code:
            stat["剔除:無程式碼"] += 1
            rejected.append((i, f"{raw_label} 無法定位程式碼"))
            continue
        if len(code) < MIN_CODE_LEN:
            stat["剔除:程式碼過短"] += 1
            rejected.append((i, f"{raw_label} 程式碼僅 {len(code)} 字元"))
            continue
        if len(code) > MAX_CODE_LEN:
            stat["剔除:程式碼過長"] += 1
            rejected.append((i, f"{raw_label} 程式碼 {len(code)} 字元"))
            continue

        lg = re.search(r"###LANG:(\S+)", block)
        lang = lg.group(1).strip().lower() if lg else "unknown"
        dm = re.search(r"###DESC:(.*)", block)
        desc = dm.group(1).strip() if dm else ""
        vm = re.search(r"###VERIFY:(.*)", block)
        verify = vm.group(1).strip() if vm else ""

        # 標籤正規化
        canon = raw_label
        if HAS_CONFIG:
            c = normalize_label(raw_label)
            if c:
                canon = c
            else:
                stat["警告:標籤無法對應"] += 1

        items.append({
            "label": canon,
            "raw_label": raw_label,
            "lang": lang,
            "desc": desc,
            "verify": verify,
            "code": code,
            "source": os.path.basename(path),
        })
        stat["成功"] += 1

    return items, stat, rejected


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inputs", nargs="*", default=DEFAULT_INPUTS)
    ap.add_argument("--out", default=DEFAULT_OUT)
    args = ap.parse_args()

    lines = []

    def log(s=""):
        print(s)
        lines.append(s)

    log("=" * 74)
    log("測試集合併與清洗")
    log("=" * 74)

    all_items = []
    for path in args.inputs:
        log(f"\n【{path}】")
        items, stat, rejected = parse_file(path)
        for k, v in stat.most_common():
            log(f"  {k:<20} {v}")
        if rejected:
            log(f"  剔除明細（前 8 筆）：")
            for i, r in rejected[:8]:
                log(f"    段{i}: {r}")
        all_items.extend(items)

    if not all_items:
        log("\n❌ 沒有解析到任何樣本")
        return

    # 跨檔去重
    log(f"\n【跨檔去重】")
    seen = {}
    deduped = []
    dup_detail = Counter()
    for it in all_items:
        fp = fingerprint(it["code"])
        if fp in seen:
            dup_detail[f"{seen[fp]} ↔ {it['source']}"] += 1
            continue
        seen[fp] = it["source"]
        deduped.append(it)
    log(f"  合併前 {len(all_items)} 筆 → 去重後 {len(deduped)} 筆"
        f"（移除 {len(all_items) - len(deduped)}）")
    for k, v in dup_detail.most_common(5):
        log(f"    {k}: {v} 筆")

    # 統計
    labels = Counter(it["label"] for it in deduped)
    langs = Counter(it["lang"] for it in deduped)
    grid = defaultdict(Counter)
    for it in deduped:
        grid[it["label"]][it["lang"]] += 1

    log(f"\n【最終組成】{len(deduped)} 筆")
    lang_list = sorted(langs)
    log(f"  {'類別':<26} " + "".join(f"{l[:9]:>10}" for l in lang_list) + f"{'合計':>8}")
    log("  " + "-" * (26 + 10 * len(lang_list) + 8))
    for label in sorted(labels, key=lambda x: -labels[x]):
        row = grid[label]
        line = f"  {label:<26} "
        for l in lang_list:
            line += f"{row.get(l, 0):>10}"
        line += f"{labels[label]:>8}"
        log(line)
    log("  " + "-" * (26 + 10 * len(lang_list) + 8))
    tot = f"  {'合計':<26} "
    for l in lang_list:
        tot += f"{langs[l]:>10}"
    tot += f"{len(deduped):>8}"
    log(tot)

    log(f"\n  來源分布：")
    for s, n in Counter(it["source"] for it in deduped).most_common():
        log(f"    {s:<32} {n:>5}")

    # 有 VERIFY 欄位的比例（品質指標）
    with_verify = sum(1 for it in deduped if it["verify"])
    log(f"\n  含 ###VERIFY 自我驗證：{with_verify}/{len(deduped)}"
        f"（{with_verify/len(deduped):.1%}）")

    # 輸出
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        for i, it in enumerate(deduped):
            f.write(f"###LABEL:{it['label']}\n")
            f.write(f"###LANG:{it['lang']}\n")
            if it["desc"]:
                f.write(f"###DESC:{it['desc']}\n")
            if it["verify"]:
                f.write(f"###VERIFY:{it['verify']}\n")
            f.write("```\n")
            f.write(it["code"])
            f.write("\n```\n")
            f.write("---SPLIT---\n")

    log(f"\n✅ 已輸出：{args.out}")
    log(f"   格式：###LABEL / ###LANG / ###DESC / ###VERIFY + ```程式碼``` + ---SPLIT---")

    os.makedirs("dataset", exist_ok=True)
    with open(REPORT, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"\n報告：{REPORT}")


if __name__ == "__main__":
    main()