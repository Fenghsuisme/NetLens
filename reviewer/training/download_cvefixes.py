# -*- coding: utf-8 -*-
"""
download_cvefixes.py — 下載 CVEfixes 真實漏洞資料並對齊到本專案 schema

資料來源：hitoshura25/cvefixes（HuggingFace，已整理版，含 CWE / 語言 / 漏洞前後程式碼）

流程：
  1. 串流下載 12,987 筆（streaming 避免一次吃滿記憶體）
  2. 每筆：
       vulnerable_code → 對應 CWE 的漏洞類別（正樣本）
       fixed_code      → clean（負樣本，標記 source 以便追蹤）
  3. 用 config_loader.cwe_to_category 把 CVEfixes 的 CWE 對應到本專案 18 類
       對不上的 CWE 記錄下來（供之後擴充 catalog）
  4. 依語言分兩份輸出：
       web    → python / javascript / typescript / php / java
       native → c / cpp
  5. 格式對齊 dataset_aligned.csv（code, language, label, category, category_zh, cwe, source）
  6. 產出詳細報告

放在 reviewer/ 底下執行：python download_cvefixes.py
"""
import os
import sys
from collections import Counter, defaultdict

import pandas as pd

# 已移入子目錄，需往上一層才能 import 到 reviewer/ 下的模組
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.config_loader import cwe_to_category, get_category, normalize_label

# ── 設定 ──────────────────────────────────────────
HF_DATASET = "hitoshura25/cvefixes"
OUT_DIR = "dataset/cvefixes"
MIN_CODE_LEN = 30
MAX_CODE_LEN = 4000          # 過長的截斷（真實 commit 可能很長）

# CVEfixes 的語言字串 → 本專案語言代號
LANG_NORMALIZE = {
    "python": "python",
    "javascript": "javascript",
    "typescript": "typescript",
    "php": "php",
    "java": "java",
    "c": "c",
    "c++": "cpp", "cpp": "cpp",
}
WEB_LANGS = {"python", "javascript", "typescript", "php", "java"}
NATIVE_LANGS = {"c", "cpp"}

# clean 樣本用的 label（來自 vuln_categories.json 的 clean）
_CLEAN = get_category("clean")
CLEAN_LABEL = _CLEAN["label"] if _CLEAN else 0


def _norm_cwe(cwe):
    s = str(cwe).upper().replace(" ", "")
    if s.startswith("CWE-"):
        num = ""
        for ch in s[4:]:
            if ch.isdigit(): num += ch
            else: break
        return f"CWE-{num}" if num else s
    if s.isdigit():
        return f"CWE-{s}"
    return s


def _clean_code(text):
    if text is None:
        return ""
    t = str(text).strip()
    if len(t) > MAX_CODE_LEN:
        t = t[:MAX_CODE_LEN]
    return t


def main():
    try:
        from datasets import load_dataset
    except ImportError:
        print("❌ 需要 datasets 套件：pip install datasets")
        return

    print(f"開始串流下載 {HF_DATASET} ...")
    print("（streaming 模式，逐筆處理，不會一次吃滿記憶體）\n")

    try:
        ds = load_dataset(HF_DATASET, split="train", streaming=True)
    except Exception as e:
        print(f"❌ 下載失敗：{e}")
        print("   若是網路問題，可掛 VPN 或設定 HF_ENDPOINT 鏡像後重試。")
        return

    web_rows = []
    native_rows = []

    stats = {
        "total": 0,
        "vuln_kept": 0,
        "clean_kept": 0,
        "dropped_lang": 0,
        "dropped_cwe": 0,
        "dropped_short": 0,
    }
    unmapped_cwe = Counter()          # 對不上本專案類別的 CWE
    lang_dist = Counter()
    category_dist = Counter()

    for item in ds:
        stats["total"] += 1
        if stats["total"] % 2000 == 0:
            print(f"  已處理 {stats['total']} 筆 ...")

        # 語言正規化
        raw_lang = str(item.get("language", "")).strip().lower()
        lang = LANG_NORMALIZE.get(raw_lang)
        if lang is None:
            stats["dropped_lang"] += 1
            continue

        # CWE 對應到本專案類別
        cwe = _norm_cwe(item.get("cwe_id", ""))
        category = cwe_to_category(cwe)
        if category is None:
            stats["dropped_cwe"] += 1
            unmapped_cwe[cwe] += 1
            continue

        info = get_category(category)
        label = info["label"]
        cat_zh = info.get("name_zh", category)

        target = web_rows if lang in WEB_LANGS else native_rows

        # 正樣本：vulnerable_code
        vcode = _clean_code(item.get("vulnerable_code", ""))
        if len(vcode) >= MIN_CODE_LEN:
            target.append({
                "code": vcode, "language": lang, "label": label,
                "category": category, "category_zh": cat_zh, "cwe": cwe,
                "source": "cvefixes_vuln",
            })
            stats["vuln_kept"] += 1
            lang_dist[lang] += 1
            category_dist[category] += 1
        else:
            stats["dropped_short"] += 1

        # 負樣本：fixed_code → clean
        fcode = _clean_code(item.get("fixed_code", ""))
        if len(fcode) >= MIN_CODE_LEN:
            target.append({
                "code": fcode, "language": lang, "label": CLEAN_LABEL,
                "category": "clean", "category_zh": "正常程式碼", "cwe": "",
                "source": "cvefixes_fixed",
            })
            stats["clean_kept"] += 1

    # ── 輸出 ──────────────────────────────────────
    os.makedirs(OUT_DIR, exist_ok=True)

    def _save(rows, name):
        if not rows:
            print(f"  （{name} 無資料）")
            return None
        df = pd.DataFrame(rows).drop_duplicates(subset=["code"]).reset_index(drop=True)
        path = os.path.join(OUT_DIR, name)
        df.to_csv(path, index=False, encoding="utf-8")
        return df, path

    web_res = _save(web_rows, "cvefixes_aligned_web.csv")
    native_res = _save(native_rows, "cvefixes_aligned_native.csv")

    # ── 報告 ──────────────────────────────────────
    lines = []
    lines.append("=" * 60)
    lines.append("CVEfixes 下載對齊報告")
    lines.append("=" * 60)
    lines.append(f"\n原始總筆數：{stats['total']}")
    lines.append(f"保留漏洞樣本（vulnerable_code）：{stats['vuln_kept']}")
    lines.append(f"保留正常樣本（fixed_code→clean）：{stats['clean_kept']}")
    lines.append(f"\n丟棄統計：")
    lines.append(f"  語言不支援：{stats['dropped_lang']}")
    lines.append(f"  CWE 對不上本專案類別：{stats['dropped_cwe']}")
    lines.append(f"  程式碼過短：{stats['dropped_short']}")

    if web_res:
        lines.append(f"\nWeb 語言輸出：{web_res[1]}（{len(web_res[0])} 筆）")
    if native_res:
        lines.append(f"Native 語言輸出：{native_res[1]}（{len(native_res[0])} 筆）")

    lines.append(f"\n漏洞樣本語言分布：")
    for lang, cnt in lang_dist.most_common():
        lines.append(f"  {lang:<14} {cnt:>6}")

    lines.append(f"\n漏洞樣本類別分布：")
    for cat, cnt in category_dist.most_common():
        info = get_category(cat)
        zh = info.get("name_zh", cat) if info else cat
        lines.append(f"  {cat:<24} {zh:<10} {cnt:>6}")

    lines.append(f"\n對不上本專案類別的 CWE（前25，供擴充 catalog 參考）：")
    for cwe, cnt in unmapped_cwe.most_common(25):
        lines.append(f"  {cwe:<12} {cnt:>5} 筆")

    report = "\n".join(lines)
    with open(os.path.join(OUT_DIR, "cvefixes_report.txt"), "w", encoding="utf-8") as f:
        f.write(report)
    print("\n" + report)
    print(f"\n✅ 報告已存：{os.path.join(OUT_DIR, 'cvefixes_report.txt')}")


if __name__ == "__main__":
    main()