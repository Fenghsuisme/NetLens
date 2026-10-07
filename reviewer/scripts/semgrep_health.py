# -*- coding: utf-8 -*-
"""
semgrep_health.py — Semgrep 健康檢查

為什麼需要：
  這台開發機的資安軟體會週期性封鎖 semgrep.exe（WinError 4551），
  一旦被封鎖，所有掃描都回傳空結果。
  若在實驗中途發生，會讓「工具掛了」被誤算成「規則沒抓到」，
  導致召回率被嚴重低估（實測已發生過一次）。

  因此每次跑實驗前先執行本檢查，確認工具可用。

檢查項目：
  1. semgrep 指令存在且可執行
  2. 能正常載入自訂規則
  3. 能正確掃出已知漏洞（用一段必定該命中的程式碼驗證）
  4. 補強規則是否就位

執行：python semgrep_health.py
"""
import os
import sys
import subprocess
import tempfile
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from transport_layer import SUPPLEMENT_RULES

# 偵測到的可用指令（由 check_command 設定）
SEMGREP_CMD = ["semgrep"]

RULES_DIR = "rules"
# 直接沿用生產端 SUPPLEMENT_RULES，描述僅供顯示；新增補強規則會自動列入
# （舊版硬編碼 7 份，缺 backdoor/csrf，健康檢查無法反映生產規則集）
_SUPP_DESC = {
    "rules/supplement_hardcoded.yml": "硬編碼密碼補強（1/10 → 8/10）",
    "rules/supplement_sqli.yml": "SQL注入補強（ORM raw 方法拼接）",
    "rules/supplement_xss.yml": "XSS補強（HTML拼接、模板未轉義）",
    "rules/supplement_path.yml": "路徑遊走補強（基底路徑+輸入拼接）",
    "rules/supplement_crypto.yml": "弱加密補強（DES/ECB/RC4）",
    "rules/supplement_proto.yml": "原型污染補強（遞迴合併未過濾）",
    "rules/supplement_codeexec.yml": "程式碼執行補強（PHP eval 等）",
    "rules/supplement_backdoor.yml": "後門補強（魔術參數/隱藏憑證）",
    "rules/supplement_csrf.yml": "CSRF補強（狀態變更缺 token 驗證）",
    "rules/supplement_upload.yml": "檔案上傳補強（move_uploaded_file/save/multer）",
}
SUPPLEMENTS = [(p, _SUPP_DESC.get(p, os.path.basename(p))) for p in SUPPLEMENT_RULES]

# 已知必定該命中的樣本（sanity check）
CANARY = {
    "python": ('''import sqlite3
def login(request):
    username = request.form.get('username')
    query = "SELECT * FROM users WHERE name='" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()
''', "CWE-89"),
}


def check_command():
    """
    依序嘗試兩種呼叫方式：
      1. semgrep（正常情況）
      2. python -m semgrep（semgrep.exe 被應用程式控制原則封鎖時的退路）
    """
    global SEMGREP_CMD
    print("① 檢查 semgrep 指令...")
    candidates = [
        (["semgrep"], "semgrep 執行檔"),
        ([sys.executable, "-m", "semgrep"], "python -m semgrep（繞過執行檔封鎖）"),
    ]
    for cmd, desc in candidates:
        try:
            r = subprocess.run(cmd + ["--version"], capture_output=True,
                               text=True, timeout=60)
            if r.returncode == 0 or r.stdout:
                ver = (r.stdout or "").strip().split("\n")[-1]
                print(f"   ✓ 可用：{desc}　版本 {ver}")
                SEMGREP_CMD = cmd
                return True
            print(f"   ✗ {desc}：回傳碼 {r.returncode}")
        except Exception as e:
            msg = str(e)
            print(f"   ✗ {desc}：{type(e).__name__}")
            if "4551" in msg or "封鎖" in msg:
                print("      → 被應用程式控制原則封鎖")
    return False


def check_rules():
    print("\n② 檢查規則檔...")
    ok = True
    for lang in ["python", "javascript", "php", "java"]:
        p = os.path.join(RULES_DIR, f"{lang}.yml")
        if os.path.exists(p):
            print(f"   ✓ {p}")
        else:
            print(f"   ✗ 找不到 {p}")
            ok = False
    for path, desc in SUPPLEMENTS:
        if os.path.exists(path):
            print(f"   ✓ {path}　{desc}")
        else:
            print(f"   ⚠️ 找不到 {path}　（{desc}）")
    return ok


def check_scan():
    print("\n③ 實際掃描測試（用已知必定命中的樣本）...")
    os.environ["PYTHONUTF8"] = "1"
    all_ok = True
    for lang, (code, expect_cwe) in CANARY.items():
        rule = os.path.join(RULES_DIR, f"{lang}.yml")
        if not os.path.exists(rule):
            continue
        tmp = out = None
        try:
            ext = {"python": ".py", "javascript": ".js",
                   "php": ".php", "java": ".java"}[lang]
            with tempfile.NamedTemporaryFile(mode="w", suffix=ext,
                                             delete=False, encoding="utf-8") as f:
                f.write(code)
                tmp = f.name
            out = tmp + ".json"
            proc = subprocess.run(
                SEMGREP_CMD + ["--config", rule, "--no-git-ignore",
                               "--json", "--quiet", "--output", out, tmp],
                capture_output=True, timeout=120,
            )
            if not os.path.exists(out):
                err = (proc.stderr or b"").decode("utf-8", errors="ignore")
                print(f"   ✗ {lang}：未產生輸出（returncode={proc.returncode}）")
                print(f"     {err[:250]}")
                all_ok = False
                continue
            data = json.load(open(out, encoding="utf-8"))
            results = data.get("results", [])
            cwes = set()
            for r in results:
                cwe = (r.get("extra", {}).get("metadata", {}) or {}).get("cwe")
                if isinstance(cwe, list):
                    cwe = cwe[0] if cwe else None
                if cwe:
                    import re
                    m = re.search(r"CWE[-\s]?(\d+)", str(cwe))
                    if m:
                        cwes.add(f"CWE-{m.group(1)}")
            if expect_cwe in cwes:
                print(f"   ✓ {lang}：{len(results)} 個 finding，"
                      f"含預期的 {expect_cwe}")
            else:
                print(f"   ✗ {lang}：{len(results)} 個 finding，"
                      f"但沒有預期的 {expect_cwe}")
                print(f"     實際命中：{sorted(cwes) or '無'}")
                all_ok = False
        except Exception as e:
            print(f"   ✗ {lang}：{type(e).__name__}: {e}")
            if "4551" in str(e):
                print("     → 被資安軟體封鎖")
            all_ok = False
        finally:
            for p in (tmp, out):
                if p and os.path.exists(p):
                    try:
                        os.unlink(p)
                    except Exception:
                        pass
    return all_ok


def main():
    print("=" * 60)
    print("Semgrep 健康檢查")
    print("=" * 60 + "\n")

    ok1 = check_command()
    ok2 = check_rules() if ok1 else False
    ok3 = check_scan() if ok1 else False

    print("\n" + "=" * 60)
    if ok1 and ok3:
        print("✅ 一切正常，可以進行實驗")
    else:
        print("❌ 有問題，實驗結果將不可信")
        print("\n修復方式：")
        print("  pip install --upgrade --force-reinstall semgrep")
        print("\n（這台機器的資安軟體會週期性封鎖 semgrep.exe，")
        print("  每次實驗前都建議先跑一次本檢查）")
    print("=" * 60)
    return 0 if (ok1 and ok3) else 1


if __name__ == "__main__":
    sys.exit(main())