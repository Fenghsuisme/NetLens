# -*- coding: utf-8 -*-
"""
reorganize.py — 專案檔案結構重整

將根目錄下 60+ 個腳本依用途分類至子目錄，並自動修正因移動而失效的路徑。

分類原則：
  生產管道（會被反覆 import）留在根目錄，避免 import 路徑複雜化
  其餘依「訓練 / 評估 / 診斷 / 維運 / 應用 / 過時」分類
  用途不明者一律進 once/，之後確認再歸位

路徑自動修正：
  被移動的腳本中若有
      sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
  會改為
      sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
  使其仍能 import 到 reviewer/ 底下的 core、transport_layer 等模組。

  相對路徑（如 "rules/python.yml"、"dataset/xxx.csv"）不做修改，
  因這些腳本原本就設計為「在 reviewer/ 目錄下執行」，
  移動後執行方式為 python tools/show_missed.py，工作目錄仍是 reviewer/。

用法：
  python reorganize.py --dry-run     只顯示會怎麼移動
  python reorganize.py               實際執行
  python reorganize.py --undo        還原（依 reorganize_log.json）
"""
import argparse
import json
import os
import re
import shutil
import sys

LOG_FILE = "reorganize_log.json"

# ── 留在根目錄：生產管道，會被反覆 import ──
KEEP_ROOT = {
    "scan.py",                 # 主入口
    "transport_layer.py",      # 傳輸層
    "typosquat_detector.py",   # 惡意套件偵測
    "testset_parser.py",       # 測試集解析（多處共用）
    "obfuscate.py",            # 函式名去語意化（前處理，須與訓練一致）
    "label_map.py",            # config(22類) ↔ 模型(17類) 標籤對應
    "reorganize.py",           # 本腳本
}

# ── 分類表 ──
LAYOUT = {
    "training": [
        "build_dataset.py",
        "align_dataset.py",
        "download_cvefixes.py",
        "fetch_cvefixes_full.py",
        "integrate_teammate_data.py",
        "merge_17class.py",
        "merge_testsets.py",
        "train_model.py",
        "train_model_v6.py",
        "train_model_v7.py",
        "train_model_v7v8.py",
        "merge_17class_obfuscated.py",   # 變數/函式名混淆版的資料合併
    ],
    "eval": [
        "eval_e2e.py",
        "rule_experiment_v2.py",
        "eval_v6.py",
        "test_v4_real.py",
        "test_v5_real.py",
        "test_v6_real.py",
        "test_v6_2_full_real.py",
        "test_v7_real.py",
        "test_v7_full_real.py",
        "test_v7v8_full_real.py",
        "test_pipeline_gemini.py",
        "verify_labels.py",
    ],
    "tools": [
        "show_missed.py",
        "diagnose_hits.py",
        "confusion_analysis.py",
        "error_by_source.py",
        "confidence_analysis.py",
        "audit_comment_leak.py",
        "audit_dataset_quality.py",
        "audit_teammate_labels.py",
        "inspect_rules.py",
        "inspect_samples.py",
        "inspect_testset.py",
        "peek_samples.py",
        "peek_testfile.py",
    ],
    "scripts": [
        "check_env.py",
        "semgrep_health.py",
        "rules_cleanup.py",
        "run_all_tests.sh",
    ],
    "archive": [
        "code_analyzer.py",        # 舊分析器，含過時 LABEL_MAP
        "pipeline_v2.py",          # 已被 scan.py 取代
        "parse_and_test.py",       # 舊測試流程
        "rule_experiment.py",      # 已被 v2 取代
        "merge_training_data.py",  # 已被 merge_17class 取代
        "print.py",                # 臨時腳本
    ],
    # 用途待確認者
    "once": [
        "audit_labels.py",
        "batch_test.py",
        "semgrep_recall_bench_v2.py",
        "semgrep_solo_testing.py",
        "test_semgrep_dataset.py",
        "test_semgrep_only.py",
        "create_rules.py",
        "create_test_files.py",
        "debug_cwe.py",
        "integrate_ai_samples.py",
        "prepare_dataset.py",
        "prepare_dataset_v2.py",
        "reviewer_app.py",
        "test_mcp_client.py",
        "test_transport.py",
    ],
}

# ── 輸出檔移入 dataset/ ──
MOVE_TO_DATASET = ["bench_misses.csv", "bench_report.txt"]

# ── 直接刪除 ──
DELETE = ["__pycache__"]

# 需要修正的 sys.path 樣式
PATH_PATTERN_OLD = "sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))"
PATH_PATTERN_NEW = ("sys.path.insert(0, os.path.dirname("
                    "os.path.dirname(os.path.abspath(__file__))))")


def fix_sys_path(filepath):
    """修正移入子目錄後失效的 sys.path"""
    if not filepath.endswith(".py"):
        return False
    try:
        c = open(filepath, encoding="utf-8").read()
    except Exception:
        return False
    if PATH_PATTERN_OLD not in c:
        return False
    c = c.replace(
        PATH_PATTERN_OLD,
        "# 已移入子目錄，需往上一層才能 import 到 reviewer/ 下的模組\n"
        + PATH_PATTERN_NEW,
    )
    open(filepath, "w", encoding="utf-8").write(c)
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true", help="只顯示不執行")
    ap.add_argument("--undo", action="store_true", help="還原上次的移動")
    args = ap.parse_args()

    if args.undo:
        if not os.path.exists(LOG_FILE):
            print(f"❌ 找不到 {LOG_FILE}，無法還原")
            return 1
        log = json.load(open(LOG_FILE, encoding="utf-8"))
        n = 0
        for src, dst in log["moves"]:
            if os.path.exists(dst):
                shutil.move(dst, src)
                n += 1
        print(f"✅ 已還原 {n} 個檔案")
        print("   註：sys.path 的修改不會自動還原，若有需要請用 git 還原")
        return 0

    existing = set(os.listdir("."))
    moves = []
    missing = []
    fixed_paths = []

    print("=" * 72)
    print("專案結構重整" + ("（dry-run）" if args.dry_run else ""))
    print("=" * 72)

    # 建目錄並移動
    for folder, files in LAYOUT.items():
        present = [f for f in files if f in existing]
        absent = [f for f in files if f not in existing]
        missing.extend(absent)
        if not present:
            continue

        print(f"\n【{folder}/】{len(present)} 個檔案")
        if not args.dry_run:
            os.makedirs(folder, exist_ok=True)

        for f in present:
            dst = os.path.join(folder, f)
            print(f"   {f}")
            if args.dry_run:
                continue
            shutil.move(f, dst)
            moves.append((f, dst))
            if fix_sys_path(dst):
                fixed_paths.append(dst)

    # 輸出檔
    out_files = [f for f in MOVE_TO_DATASET if f in existing]
    if out_files:
        print(f"\n【dataset/】{len(out_files)} 個輸出檔")
        for f in out_files:
            print(f"   {f}")
            if not args.dry_run:
                os.makedirs("dataset", exist_ok=True)
                dst = os.path.join("dataset", f)
                shutil.move(f, dst)
                moves.append((f, dst))

    # 刪除
    to_del = [f for f in DELETE if f in existing]
    if to_del:
        print(f"\n【刪除】")
        for f in to_del:
            print(f"   {f}")
            if not args.dry_run:
                shutil.rmtree(f) if os.path.isdir(f) else os.remove(f)

    # 留在根目錄的
    print(f"\n【留在根目錄】生產管道，會被反覆 import")
    for f in sorted(KEEP_ROOT):
        mark = "" if f in existing else "  （不存在）"
        print(f"   {f}{mark}")

    if missing:
        print(f"\n【分類表中列出但不存在的檔案】{len(missing)} 個")
        for f in sorted(missing):
            print(f"   {f}")

    if fixed_paths:
        print(f"\n【已修正 sys.path】{len(fixed_paths)} 個檔案")
        for f in fixed_paths:
            print(f"   {f}")

    if args.dry_run:
        print(f"\n（dry-run，未實際執行。確認無誤後拿掉 --dry-run）")
        return 0

    # 記錄以便還原
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        json.dump({"moves": moves, "fixed": fixed_paths}, f,
                  ensure_ascii=False, indent=2)

    # 補上 .gitignore
    gi = ".gitignore"
    lines = []
    if os.path.exists(gi):
        lines = open(gi, encoding="utf-8").read().splitlines()
    added = []
    for entry in ["__pycache__/", "*.pyc", ".DS_Store", ".venv/",
                  "models/", "rules/*.yml.bak", "reorganize_log.json"]:
        if entry not in lines:
            lines.append(entry)
            added.append(entry)
    if added:
        open(gi, "w", encoding="utf-8").write("\n".join(lines) + "\n")
        print(f"\n【.gitignore】新增 {len(added)} 條：{', '.join(added)}")

    print(f"\n✅ 完成，共移動 {len(moves)} 個檔案")
    print(f"   還原：python reorganize.py --undo")
    print(f"\n之後的執行方式（工作目錄仍在 reviewer/）：")
    print(f"   python scan.py <檔案>")
    print(f"   python eval/eval_e2e.py -n 30")
    print(f"   python tools/show_missed.py sql_injection")
    print(f"   python scripts/semgrep_health.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())