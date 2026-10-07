#!/usr/bin/env bash
# run_all_tests.sh — NetLens Reviewer 完整測試流程
#
# 依序執行環境檢查、工具檢查、管道驗證、規則實驗。
# 任一步失敗即停止，避免後續測試建立在錯誤基礎上。
#
# 用法：
#   bash run_all_tests.sh          抽樣模式（快，每類 30 筆）
#   bash run_all_tests.sh --full   完整模式（慢，全部 1497 筆）

set -e

FULL=0
[ "$1" = "--full" ] && FULL=1

hr() { printf '%.0s─' {1..70}; echo; }
step() { echo; hr; echo "▶ $1"; hr; }

step "1/6 環境檢查"
python check_env.py

step "2/6 Semgrep 健康檢查"
python semgrep_health.py

step "3/6 測試集確認"
python testset_parser.py | head -30

step "4/6 建立示範檔並執行完整掃描"
cat > /tmp/netlens_demo.py << 'PYEOF'
import os
import sqlite3
import hashlib
from colourama import Fore

DB_PASSWORD = "SuperSecret123!"

def get_user(request):
    user_id = request.args.get('id')
    query = "SELECT * FROM users WHERE id=" + user_id
    cursor.execute(query)
    return cursor.fetchall()

def safe_get_user(request):
    user_id = request.args.get('id')
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchall()

def hash_pw(pwd):
    return hashlib.md5(pwd.encode()).hexdigest()

def run_cmd(request):
    cmd = request.args.get('cmd')
    os.system("ping " + cmd)

def deep_merge(target, source):
    for key, value in source.items():
        setattr(target, key, value)
PYEOF
python scan.py /tmp/netlens_demo.py

step "5/6 傳輸層片段抽取驗證"
python transport_layer.py /tmp/netlens_demo.py | head -40

step "6/6 規則對照實驗"
if [ $FULL -eq 1 ]; then
  echo "（完整模式：1497 筆 A 類，預計 30-60 分鐘）"
  python rule_experiment_v2.py
else
  echo "（抽樣模式：每類 30 筆。要跑完整版請加 --full）"
  python rule_experiment_v2.py -n 30
fi

hr
echo "✅ 全部測試完成"
echo
echo "產出報告："
echo "  dataset/rule_experiment_v2_report.txt   規則對照實驗"
echo "  dataset/testset_merge_report.txt        測試集組成"
hr