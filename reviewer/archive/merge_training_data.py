# -*- coding: utf-8 -*-
"""
merge_training_data.py — 合併合成資料 + CVEfixes 真實資料，產出最終 web 訓練/驗證集

流程：
  1. 合併 dataset_aligned.csv（合成）+ cvefixes_aligned_web.csv（真實 web）
  2. 只保留 web 語言 label（0-17），濾掉記憶體類（18-21）
  3. 防資料洩漏：從訓練資料剔除 194 筆測試集的內容（用 code 正規化比對）
  4. 跨批去重
  5. stratify 切訓練/驗證集（80/20）
  6. 輸出 + 報告

放在 reviewer/ 底下執行：python merge_training_data.py
"""
import os
import sys
import re
import hashlib
from collections import Counter

import pandas as pd
from sklearn.model_selection import train_test_split

# 已移入子目錄，需往上一層才能 import 到 reviewer/ 下的模組
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ── 設定 ──────────────────────────────────────────
SYNTH_CSV = "dataset/dataset_aligned.csv"
CVEFIX_WEB_CSV = "dataset/cvefixes/cvefixes_aligned_web.csv"
TEST_FILES = [
    "test_code/real_test/security_training_dataset_v1.txt",
    "test_code/real_test/security_training_examples_100.md",
]
OUT_TRAIN = "dataset/train_web.csv"
OUT_VAL = "dataset/val_web.csv"
REPORT = "dataset/merge_report.txt"

WEB_LABELS = set(range(13))   # 本次只訓原13類（0-12）；新5類(13-17)資料不足，暫不訓
VAL_RATIO = 0.2
SEED = 42


def _normalize_code(code):
    """正規化程式碼用於比對：去空白、去換行、小寫，取 hash"""
    s = re.sub(r"\s+", "", str(code)).lower()
    return hashlib.md5(s.encode("utf-8")).hexdigest()


def _load_test_code_hashes():
    """讀取 194 筆測試資料的 code，回傳其正規化 hash 集合"""
    hashes = set()
    count = 0
    for path in TEST_FILES:
        if not os.path.exists(path):
            print(f"  ⚠️ 找不到測試檔 {path}，跳過（防洩漏可能不完整）")
            continue
        content = open(path, encoding="utf-8").read()
        for block in content.split("---SPLIT---"):
            # 抓 code：優先 ```...```，否則 ###DESC 之後
            m = re.search(r"```\w*\n(.*?)```", block, re.DOTALL)
            if m:
                code = m.group(1).strip()
            else:
                pos = block.find("###DESC:")
                if pos == -1:
                    continue
                nl = block.find("\n", pos)
                if nl == -1:
                    continue
                code = block[nl:].strip()
            if len(code) >= 30:
                hashes.add(_normalize_code(code))
                count += 1
    print(f"  載入測試集 {count} 筆的內容指紋（用於防洩漏）")
    return hashes


def main():
    # 載入合成 + 真實
    if not os.path.exists(SYNTH_CSV):
        print(f"❌ 找不到 {SYNTH_CSV}")
        return
    synth = pd.read_csv(SYNTH_CSV)
    print(f"合成資料：{len(synth)} 筆")

    if os.path.exists(CVEFIX_WEB_CSV):
        cvefix = pd.read_csv(CVEFIX_WEB_CSV)
        print(f"CVEfixes web：{len(cvefix)} 筆")
    else:
        cvefix = pd.DataFrame()
        print("⚠️ 找不到 CVEfixes web 檔，只用合成資料")

    combined = pd.concat([synth, cvefix], ignore_index=True) if len(cvefix) else synth

    # 只保留 web label
    before = len(combined)
    combined = combined[combined["label"].isin(WEB_LABELS)].reset_index(drop=True)
    removed_native = before - len(combined)

    # 防洩漏：剔除測試集內容
    print("\n防資料洩漏檢查：")
    test_hashes = _load_test_code_hashes()
    combined["_hash"] = combined["code"].apply(_normalize_code)
    leak_mask = combined["_hash"].isin(test_hashes)
    leaked = int(leak_mask.sum())
    combined = combined[~leak_mask].reset_index(drop=True)
    print(f"  從訓練資料剔除與測試集重疊：{leaked} 筆")

    # 去重
    before_dedup = len(combined)
    combined = combined.drop_duplicates(subset=["_hash"]).reset_index(drop=True)
    dedup = before_dedup - len(combined)
    combined = combined.drop(columns=["_hash"])

    # 切訓練/驗證（stratify 保持類別比例；類別太少時自動退回一般切分）
    label_counts = combined["label"].value_counts()
    can_stratify = label_counts.min() >= 2
    if can_stratify:
        train_df, val_df = train_test_split(
            combined, test_size=VAL_RATIO, random_state=SEED,
            stratify=combined["label"]
        )
    else:
        rare = label_counts[label_counts < 2].index.tolist()
        print(f"  ⚠️ 類別 {rare} 樣本過少，改用非 stratify 切分")
        train_df, val_df = train_test_split(
            combined, test_size=VAL_RATIO, random_state=SEED
        )

    os.makedirs("dataset", exist_ok=True)
    train_df.to_csv(OUT_TRAIN, index=False, encoding="utf-8")
    val_df.to_csv(OUT_VAL, index=False, encoding="utf-8")

    # 報告
    lines = []
    lines.append("=" * 60)
    lines.append("訓練資料合併報告（web 原13類）")
    lines.append("=" * 60)
    lines.append(f"\n合成資料：{len(synth)}")
    lines.append(f"CVEfixes web：{len(cvefix)}")
    lines.append(f"排除非本次類別(label13-21)：{removed_native}")
    lines.append(f"防洩漏剔除(與測試集重疊)：{leaked}")
    lines.append(f"去重移除：{dedup}")
    lines.append(f"\n最終總筆數：{len(combined)}")
    lines.append(f"  訓練集：{len(train_df)}")
    lines.append(f"  驗證集：{len(val_df)}")

    lines.append(f"\n各類別分布（訓練集）：")
    dist = train_df.groupby(["label", "category"]).size().reset_index(name="c").sort_values("label")
    for _, r in dist.iterrows():
        lines.append(f"  {r['label']:>2}  {r['category']:<24} {r['c']:>6}")

    lines.append(f"\n資料來源分布：")
    for src, cnt in combined["source"].value_counts().items():
        lines.append(f"  {src:<20} {cnt:>6}")

    report = "\n".join(lines)
    open(REPORT, "w", encoding="utf-8").write(report)
    print("\n" + report)
    print(f"\n✅ 訓練集：{OUT_TRAIN}")
    print(f"✅ 驗證集：{OUT_VAL}")


if __name__ == "__main__":
    main()