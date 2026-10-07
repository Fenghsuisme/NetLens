# -*- coding: utf-8 -*-
"""
align_dataset.py — 將散落的 raw 訓練資料對齊到新 schema（18類體系，本次只保留原13類）

流程：
  1. 遞迴搜集 dataset/ 底下所有檔名含 'raw' 的 CSV
  2. 逐筆用 config_loader 正規化標籤 → 標準類別代號
  3. 只保留原 13 類（label 0-12）；正規化失敗或屬新5類者丟棄並記錄
  4. 從 config 自動補齊 label / category_zh / cwe
  5. 跨檔去重、品質過濾（過短/空白）
  6. 輸出乾淨訓練資料 + 對齊報告

放在 reviewer/ 底下執行：python align_dataset.py
"""
import os
import sys
import glob
from collections import defaultdict, Counter

import pandas as pd

# 讓 core 可被 import（此腳本放在 reviewer/ 根目錄執行）
# 已移入子目錄，需往上一層才能 import 到 reviewer/ 下的模組
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.config_loader import (
    normalize_label, get_category, label_to_category,
)

# ── 設定 ──────────────────────────────────────────
DATASET_DIR = "dataset"
OUTPUT_CSV = "dataset/dataset_aligned.csv"
REPORT_TXT = "dataset/alignment_report.txt"
MIN_CODE_LEN = 30
KEEP_LABELS = set(range(13))   # 只保留原 13 類（label 0-12）

# 可能的欄位名容錯（不同來源檔案欄位名可能不同）
CODE_COLS = ["code", "func", "source_code", "snippet", "content"]
LABEL_COLS = ["category", "label_name", "vuln_type", "type", "label", "category_zh", "category_en"]
LANG_COLS = ["language", "lang"]


def _pick_col(df, candidates):
    """從候選欄位名中找出 df 實際有的第一個"""
    for c in candidates:
        if c in df.columns:
            return c
    return None


def _resolve_category(raw_value):
    """
    把一筆資料的原始標籤值 → 標準類別代號。
    支援：文字標籤（含別名）、中文名、數字 label。
    回傳 (canon_category, reason)；失敗時 canon 為 None。
    """
    if pd.isna(raw_value):
        return None, "標籤為空"
    s = str(raw_value).strip()
    if s == "":
        return None, "標籤為空"

    # 數字 label
    if s.isdigit():
        canon = label_to_category(int(s))
        if canon is None:
            return None, f"數字label {s} 無對應"
        return canon, None

    # 文字/別名/中文
    canon = normalize_label(s)
    if canon is None:
        return None, f"未知標籤 '{s}'"
    return canon, None


def main():
    raw_files = sorted(glob.glob(os.path.join(DATASET_DIR, "**", "*raw*.csv"),
                                 recursive=True))
    if not raw_files:
        print(f"❌ 在 {DATASET_DIR} 底下找不到任何檔名含 'raw' 的 CSV")
        return

    print(f"找到 {len(raw_files)} 個 raw 檔案：")
    for f in raw_files:
        print(f"  - {f}")
    print()

    all_rows = []
    report_lines = []
    per_source = defaultdict(lambda: {"read": 0, "kept": 0, "dropped": 0})
    drop_reasons = Counter()

    for path in raw_files:
        # source 標記 = 相對於 dataset/ 的路徑（去掉副檔名）
        source = os.path.relpath(path, DATASET_DIR).replace(os.sep, "/").replace(".csv", "")
        try:
            df = pd.read_csv(path)
        except Exception as e:
            report_lines.append(f"[讀取失敗] {path}: {e}")
            continue

        code_col = _pick_col(df, CODE_COLS)
        label_col = _pick_col(df, LABEL_COLS)
        lang_col = _pick_col(df, LANG_COLS)

        if code_col is None or label_col is None:
            report_lines.append(
                f"[跳過] {path}: 找不到程式碼欄位或標籤欄位"
                f"（現有欄位：{list(df.columns)}）")
            continue

        for _, row in df.iterrows():
            per_source[source]["read"] += 1
            code = str(row[code_col]) if not pd.isna(row[code_col]) else ""
            lang = str(row[lang_col]).strip().lower() if lang_col and not pd.isna(row.get(lang_col)) else "unknown"

            # 品質過濾
            if len(code.strip()) < MIN_CODE_LEN:
                per_source[source]["dropped"] += 1
                drop_reasons["程式碼過短"] += 1
                continue

            # 標籤對齊
            canon, reason = _resolve_category(row[label_col])
            if canon is None:
                per_source[source]["dropped"] += 1
                drop_reasons[reason] += 1
                continue

            info = get_category(canon)
            label_num = info["label"]

            # 只保留原 13 類
            if label_num not in KEEP_LABELS:
                per_source[source]["dropped"] += 1
                drop_reasons[f"新類別暫不納入({canon})"] += 1
                continue

            all_rows.append({
                "code": code,
                "language": lang,
                "label": label_num,
                "category": canon,
                "category_zh": info.get("name_zh", canon),
                "cwe": info.get("primary_cwe") or "",
                "source": source,
            })
            per_source[source]["kept"] += 1

    if not all_rows:
        print("❌ 沒有任何有效資料")
        return

    df_out = pd.DataFrame(all_rows)

    # 跨檔去重
    before = len(df_out)
    df_out = df_out.drop_duplicates(subset=["code"]).reset_index(drop=True)
    dedup_removed = before - len(df_out)

    # 打亂
    df_out = df_out.sample(frac=1, random_state=42).reset_index(drop=True)

    # 輸出
    os.makedirs(DATASET_DIR, exist_ok=True)
    df_out.to_csv(OUTPUT_CSV, index=False, encoding="utf-8")

    # ── 報告 ──────────────────────────────────────
    lines = []
    lines.append("=" * 60)
    lines.append("資料集對齊報告")
    lines.append("=" * 60)
    lines.append(f"\n來源檔案數：{len(raw_files)}")
    lines.append(f"對齊後總筆數：{len(df_out)}（去重移除 {dedup_removed} 筆）\n")

    lines.append("各來源貢獻：")
    lines.append(f"  {'來源':<28} {'讀取':>7} {'保留':>7} {'丟棄':>7}")
    lines.append("  " + "-" * 52)
    for src in sorted(per_source.keys()):
        v = per_source[src]
        lines.append(f"  {src:<28} {v['read']:>7} {v['kept']:>7} {v['dropped']:>7}")

    lines.append("\n丟棄原因統計：")
    for reason, cnt in drop_reasons.most_common():
        lines.append(f"  {reason:<32} {cnt:>7}")

    lines.append("\n對齊後各類別分布：")
    dist = df_out.groupby(["label", "category", "category_zh"]).size().reset_index(name="count")
    dist = dist.sort_values("label")
    for _, r in dist.iterrows():
        lines.append(f"  {r['label']:>2}  {r['category']:<24} {r['category_zh']:<10} {r['count']:>6}")

    lines.append("\n各語言分布：")
    for lang, cnt in df_out["language"].value_counts().items():
        lines.append(f"  {lang:<14} {cnt:>6}")

    report = "\n".join(lines)
    with open(REPORT_TXT, "w", encoding="utf-8") as f:
        f.write(report)

    print(report)
    print(f"\n✅ 已輸出：{OUTPUT_CSV}")
    print(f"✅ 報告：{REPORT_TXT}")


if __name__ == "__main__":
    main()