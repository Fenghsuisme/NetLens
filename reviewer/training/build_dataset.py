# -*- coding: utf-8 -*-
"""
build_dataset.py — 訓練資料建置管線（一鍵跑完四個步驟）

依序執行：
  1. align_dataset.py          對齊合成資料（v1/v2/v3）→ dataset_aligned.csv
  2. download_cvefixes.py      下載並對齊 CVEfixes 真實資料 → cvefixes_aligned_*.csv
  3. integrate_teammate_data.py 整合組員 CWE 資料夾 → teammate_aligned.csv
  4. merge_17class.py          合併三批 + 剝註解 + 防洩漏 + 平衡切分 → train_17.csv / val_17.csv

用法：
  # 完整跑（組員資料路徑必填）
  python build_dataset.py --teammate ~/vulnerable_by_cwe

  # 跳過已完成的步驟（例如 CVEfixes 已下載過）
  python build_dataset.py --teammate ~/vulnerable_by_cwe --skip cvefixes

  # 只跑合併（前三步的 csv 都已存在）
  python build_dataset.py --only merge

  # 看每步會做什麼，不實際執行
  python build_dataset.py --teammate ~/data --dry-run

設計說明：
  每步驟執行前會檢查輸出檔是否已存在，存在時詢問是否重跑
  （加 --force 則一律重跑，加 --skip 可明確跳過）。
  任一步失敗會停止，避免用不完整的資料做後續合併。
"""
import argparse
import os
import subprocess
import sys
import time

STEPS = [
    {
        "key": "align",
        "script": "align_dataset.py",
        "desc": "對齊合成資料（v1/v2/v3）",
        "output": "dataset/dataset_aligned.csv",
        "args": [],
        "needs_teammate": False,
    },
    {
        "key": "cvefixes",
        "script": "download_cvefixes.py",
        "desc": "下載並對齊 CVEfixes 真實資料（需網路）",
        "output": "dataset/cvefixes/cvefixes_aligned_web.csv",
        "args": [],
        "needs_teammate": False,
    },
    {
        "key": "teammate",
        "script": "integrate_teammate_data.py",
        "desc": "整合組員 CWE 資料夾",
        "output": "dataset/teammate_aligned.csv",
        "args": [],          # 執行時填入 teammate 路徑
        "needs_teammate": True,
    },
    {
        "key": "merge",
        "script": "merge_17class.py",
        "desc": "合併三批 + 剝註解 + 防洩漏 + 平衡切分",
        "output": "dataset/train_17.csv",
        "args": [],
        "needs_teammate": False,
    },
]


def human_size(path):
    if not os.path.exists(path):
        return "—"
    n = os.path.getsize(path)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"


def count_rows(path):
    """快速數 CSV 行數（不載入 pandas）"""
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            return sum(1 for _ in f) - 1   # 扣表頭
    except Exception:
        return None


def run_step(step, teammate_path, dry_run=False):
    script = step["script"]
    if not os.path.exists(script):
        print(f"   ✗ 找不到 {script}")
        return False

    cmd = [sys.executable, script] + list(step["args"])
    if step["needs_teammate"]:
        if not teammate_path:
            print(f"   ✗ 此步驟需要組員資料路徑，請加 --teammate <路徑>")
            return False
        if not os.path.isdir(teammate_path):
            print(f"   ✗ 找不到組員資料夾：{teammate_path}")
            return False
        cmd.append(teammate_path)

    print(f"   $ {' '.join(cmd)}")
    if dry_run:
        print("   （dry-run，未實際執行）")
        return True

    t0 = time.time()
    try:
        proc = subprocess.run(cmd, text=True)
    except KeyboardInterrupt:
        print("\n   ⚠️ 使用者中斷")
        return False
    elapsed = time.time() - t0

    if proc.returncode != 0:
        print(f"   ✗ 執行失敗（returncode={proc.returncode}，耗時 {elapsed:.0f}s）")
        return False

    out = step["output"]
    rows = count_rows(out)
    print(f"   ✓ 完成（{elapsed:.0f}s）"
          f"　輸出 {out}　{human_size(out)}"
          f"{f'　{rows} 筆' if rows is not None else ''}")
    return True


def main():
    ap = argparse.ArgumentParser(
        description="訓練資料建置管線",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--teammate", help="組員 CWE 資料夾路徑")
    ap.add_argument("--skip", nargs="*", default=[],
                    choices=[s["key"] for s in STEPS],
                    help="跳過指定步驟")
    ap.add_argument("--only", nargs="*",
                    choices=[s["key"] for s in STEPS],
                    help="只跑指定步驟")
    ap.add_argument("--force", action="store_true",
                    help="輸出檔已存在時仍重跑，不詢問")
    ap.add_argument("--dry-run", action="store_true",
                    help="只顯示會執行什麼，不實際跑")
    args = ap.parse_args()

    # 決定要跑哪些步驟
    if args.only:
        todo = [s for s in STEPS if s["key"] in args.only]
    else:
        todo = [s for s in STEPS if s["key"] not in args.skip]

    print("=" * 70)
    print("訓練資料建置管線")
    print("=" * 70)
    print(f"\n將執行 {len(todo)} 個步驟：")
    for i, s in enumerate(todo, 1):
        exists = os.path.exists(s["output"])
        mark = f"（輸出已存在：{human_size(s['output'])}）" if exists else ""
        print(f"  {i}. {s['desc']} {mark}")
    if args.teammate:
        print(f"\n組員資料：{args.teammate}")
    print()

    results = []
    for i, step in enumerate(todo, 1):
        print("─" * 70)
        print(f"[{i}/{len(todo)}] {step['desc']}")
        print("─" * 70)

        # 輸出已存在時的處理
        if os.path.exists(step["output"]) and not args.force and not args.dry_run:
            rows = count_rows(step["output"])
            print(f"   輸出已存在：{step['output']}"
                  f"（{human_size(step['output'])}"
                  f"{f'，{rows} 筆' if rows is not None else ''}）")
            ans = input("   重新產生？[y/N] ").strip().lower()
            if ans != "y":
                print("   → 跳過")
                results.append((step["key"], "skipped"))
                continue

        ok = run_step(step, args.teammate, args.dry_run)
        results.append((step["key"], "ok" if ok else "failed"))
        if not ok:
            print(f"\n❌ 步驟 {step['key']} 失敗，停止管線")
            print("   （避免用不完整的資料進行後續合併）")
            break
        print()

    # 摘要
    print("=" * 70)
    print("執行摘要")
    print("=" * 70)
    icons = {"ok": "✓", "skipped": "→", "failed": "✗"}
    for key, status in results:
        step = next(s for s in STEPS if s["key"] == key)
        print(f"  {icons[status]} {key:<10} {step['desc']}")

    # 最終產物
    print("\n最終產物：")
    for p in ["dataset/dataset_aligned.csv",
              "dataset/cvefixes/cvefixes_aligned_web.csv",
              "dataset/teammate_aligned.csv",
              "dataset/train_17.csv",
              "dataset/val_17.csv"]:
        rows = count_rows(p)
        if rows is not None:
            print(f"  {p:<48} {rows:>7} 筆　{human_size(p)}")
        else:
            print(f"  {p:<48} {'（不存在）':>10}")

    failed = [k for k, s in results if s == "failed"]
    if failed:
        print(f"\n❌ 有步驟失敗：{failed}")
        return 1

    if any(s == "ok" for _, s in results):
        print("\n✅ 完成。合併報告見 dataset/merge_17_report.txt")
        print("   接著可執行訓練：python train_model_v6.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())