#!/usr/bin/env bash
# run_model_eval.sh — 在有模型的機器上一鍵跑完整評估
# 用法：在 reviewer/ 根目錄執行  bash scripts/run_model_eval.sh
# 先看 TEST_STEPS.md 確認前置條件（模型、venv、obfuscate.py）

set -e
cd "$(dirname "$0")/.."   # 切到 reviewer/ 根目錄
PY=${PYTHON:-python}

echo "════════════════════════════════════════════════"
echo " 0. 環境與規則健檢（無模型）"
echo "════════════════════════════════════════════════"
$PY scripts/semgrep_health.py
$PY check_rules.py | tail -12

echo "════════════════════════════════════════════════"
echo " 1. 清掉舊的 clean 誤報快取（規則已改，必做）"
echo "════════════════════════════════════════════════"
if [ -f dataset/clean_fp_cache.json ]; then
  mv dataset/clean_fp_cache.json dataset/clean_fp_cache_prev.json
  echo "已備份舊快取 → dataset/clean_fp_cache_prev.json"
else
  echo "無舊快取，略過"
fi

echo "════════════════════════════════════════════════"
echo " 2. 召回評估（--with-b -n 30，約 30 分鐘）"
echo "════════════════════════════════════════════════"
$PY eval/eval_e2e.py --with-b -n 30

echo "════════════════════════════════════════════════"
echo " 3. 誤報評估（約 9 分鐘）"
echo "════════════════════════════════════════════════"
$PY eval_clean.py

echo "════════════════════════════════════════════════"
echo " 完成。報告："
echo "   召回  → dataset/e2e_report.txt"
echo "   誤報  → 見上方輸出（快取 dataset/clean_fp_cache.json）"
echo " 全量召回（約 160 分鐘）： python eval/eval_e2e.py --with-b"
echo "════════════════════════════════════════════════"
