# -*- coding: utf-8 -*-
"""
fetch_cvefixes_full.py — 取得 CVEfixes 完整版並檢查 schema

背景：
  你們目前用的 hitoshura25/cvefixes 只有 12,987 筆（已處理的精簡版）。
  CVEfixes 官方完整版有 277,948 筆（126,599 筆漏洞樣本），
  且包含 method_change 資料表（函式層級 + 行號），比檔案層級 diff 精確得多。

兩種取得方式：
  A. HuggingFace: starsofchance/CVEfixes_v1.0.8（完整版，分 4 份）
     注意：該資料集的 HF viewer 有時間欄位解析錯誤，
          需直接下載 parquet 檔而非用 load_dataset()
  B. 官方 SQLite: https://github.com/secureIT-project/CVEfixes
     （資料在 Zenodo，解壓後約 30-50GB）

用法：
  # 方式 A：從 HF 下載到指定磁碟
  python fetch_cvefixes_full.py --hf --out D:/cvefixes_data

  # 方式 B：已手動下載 SQLite，只檢查 schema
  python fetch_cvefixes_full.py --db D:/cvefixes_data/CVEfixes.db

  # 只列出 HF 上有哪些檔案（不下載）
  python fetch_cvefixes_full.py --list
"""
import os
import sys
import argparse
import sqlite3
import json

HF_REPO = "starsofchance/CVEfixes_v1.0.8"

# 我們需要的資料表（依重要性排序）
WANTED_TABLES = [
    "method_change",       # ★ 函式層級程式碼 + 行號（最重要）
    "file_change",         # 檔案層級 diff + 語言 + 檔名
    "commits",             # commit 資訊（用於規模過濾）
    "fixes",               # CVE ↔ commit 關聯
    "cve",                 # CVE metadata
    "cwe_classification",  # CVE ↔ CWE 關聯
    "cwe",                 # CWE 說明
    "repository",          # 專案資訊
]


def list_hf_files():
    try:
        from huggingface_hub import list_repo_files
    except ImportError:
        print("❌ 需要 huggingface_hub：pip install huggingface_hub")
        return
    print(f"列出 {HF_REPO} 的檔案...\n")
    try:
        files = list_repo_files(HF_REPO, repo_type="dataset")
    except Exception as e:
        print(f"❌ 讀取失敗：{e}")
        return
    for f in sorted(files):
        print(f"  {f}")
    print(f"\n共 {len(files)} 個檔案")


def download_hf(out_dir):
    try:
        from huggingface_hub import snapshot_download
    except ImportError:
        print("❌ 需要 huggingface_hub：pip install huggingface_hub")
        return None
    os.makedirs(out_dir, exist_ok=True)
    print(f"下載 {HF_REPO} 至 {out_dir}")
    print("（檔案較大，請耐心等候；中斷後重跑會續傳）\n")
    try:
        path = snapshot_download(
            repo_id=HF_REPO,
            repo_type="dataset",
            local_dir=out_dir,
            resume_download=True,
        )
        print(f"\n✅ 下載完成：{path}")
        return path
    except Exception as e:
        print(f"❌ 下載失敗：{e}")
        print("\n可改用官方 SQLite：")
        print("  https://github.com/secureIT-project/CVEfixes")
        print("  下載後用 --db 參數指定路徑")
        return None


def inspect_db(db_path):
    """檢查 SQLite schema，確認欄位名稱後才能寫正確的查詢"""
    if not os.path.exists(db_path):
        print(f"❌ 找不到 {db_path}")
        return
    size_gb = os.path.getsize(db_path) / (1024 ** 3)
    print(f"資料庫：{db_path}（{size_gb:.1f} GB）\n")

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
    tables = [r[0] for r in cur.fetchall()]
    print(f"所有資料表（{len(tables)}）：{', '.join(tables)}\n")

    schema_info = {}
    print("=" * 70)
    print("重點資料表結構")
    print("=" * 70)
    for t in WANTED_TABLES:
        if t not in tables:
            print(f"\n⚠️ 找不到資料表 {t}")
            continue
        cur.execute(f"PRAGMA table_info({t})")
        cols = [(r[1], r[2]) for r in cur.fetchall()]
        try:
            cur.execute(f"SELECT COUNT(*) FROM {t}")
            n = cur.fetchone()[0]
        except Exception:
            n = "?"
        schema_info[t] = {"columns": [c[0] for c in cols], "rows": n}
        print(f"\n【{t}】{n} 筆")
        for name, typ in cols:
            print(f"    {name:<28} {typ}")

    # 語言分布（決定能拿到多少資料的關鍵）
    if "file_change" in tables:
        print("\n" + "=" * 70)
        print("程式語言分布（file_change）")
        print("=" * 70)
        try:
            cur.execute("""
                SELECT programming_language, COUNT(*) AS n
                FROM file_change
                GROUP BY programming_language
                ORDER BY n DESC
                LIMIT 20
            """)
            for lang, n in cur.fetchall():
                mark = "  ★" if str(lang).lower() in (
                    "python", "javascript", "php", "java", "typescript") else ""
                print(f"  {str(lang):<20} {n:>8}{mark}")
        except Exception as e:
            print(f"  查詢失敗：{e}")

    # method_change 的樣本
    if "method_change" in tables:
        print("\n" + "=" * 70)
        print("method_change 樣本（確認欄位內容）")
        print("=" * 70)
        try:
            cur.execute("SELECT * FROM method_change LIMIT 1")
            cols = [d[0] for d in cur.description]
            row = cur.fetchone()
            if row:
                for c, v in zip(cols, row):
                    s = str(v)
                    s = s[:100].replace("\n", "\\n") + ("..." if len(s) > 100 else "")
                    print(f"  {c:<24} = {s}")
        except Exception as e:
            print(f"  查詢失敗：{e}")

    conn.close()

    out = os.path.join(os.path.dirname(db_path) or ".", "cvefixes_schema.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(schema_info, f, ensure_ascii=False, indent=2)
    print(f"\n✅ schema 已存：{out}")
    print("   把這份內容貼給我，我就能寫出正確的篩選查詢")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hf", action="store_true", help="從 HuggingFace 下載完整版")
    ap.add_argument("--list", action="store_true", help="列出 HF 上的檔案")
    ap.add_argument("--out", default="cvefixes_full", help="下載目的地")
    ap.add_argument("--db", help="已下載的 CVEfixes.db 路徑（檢查 schema）")
    args = ap.parse_args()

    if args.list:
        list_hf_files()
    elif args.hf:
        download_hf(args.out)
    elif args.db:
        inspect_db(args.db)
    else:
        ap.print_help()
        print("\n建議流程：")
        print("  1. python fetch_cvefixes_full.py --list")
        print("     先看 HF 上有哪些檔案")
        print("  2. python fetch_cvefixes_full.py --hf --out D:/cvefixes_data")
        print("     下載到你的另一顆磁碟")
        print("  3. python fetch_cvefixes_full.py --db D:/cvefixes_data/CVEfixes.db")
        print("     檢查 schema，把結果貼給我")


if __name__ == "__main__":
    main()