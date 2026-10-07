# -*- coding: utf-8 -*-
"""
check_env.py — 環境完整性檢查

確認訓練與掃描所需的環境都已就緒。
在 reviewer/ 目錄下執行：python check_env.py
"""
import importlib
import os
import platform
import subprocess
import sys

def ok(s):  print(f"  \033[32m✓\033[0m {s}")
def bad(s): print(f"  \033[31m✗\033[0m {s}")
def warn(s): print(f"  \033[33m!\033[0m {s}")

issues = []

print("=" * 62)
print("NetLens Reviewer 環境檢查")
print("=" * 62)

# ── 基本資訊 ──
print(f"\n【系統】")
print(f"  作業系統：{platform.system()} {platform.release()}")
print(f"  Python：{sys.version.split()[0]}")
print(f"  執行檔：{sys.executable}")
env = os.environ.get("CONDA_DEFAULT_ENV")
if env:
    ok(f"conda 環境：{env}")
else:
    warn("未偵測到 conda 環境（可能用 venv 或系統 Python）")

# ── 環境變數 ──
print(f"\n【環境變數】")
for var, why in [("PYTHONUTF8", "避免 Windows 讀中文規則檔的 cp950 錯誤"),
                 ("KMP_DUPLICATE_LIB_OK", "避免訓練時的 OpenMP 衝突")]:
    v = os.environ.get(var)
    if v:
        ok(f"{var}={v}")
    else:
        if platform.system() == "Windows":
            warn(f"{var} 未設定（{why}）")
            issues.append(f"設定 {var}")
        else:
            print(f"    {var} 未設定（非 Windows 可忽略）")

# ── 套件 ──
print(f"\n【套件】")
packages = [
    ("torch", "訓練與推論", True),
    ("transformers", "CodeBERT 模型", True),
    ("pandas", "資料處理", True),
    ("sklearn", "切分與評估指標", True),
    ("yaml", "讀取 Semgrep 規則", True),
    ("datasets", "訓練資料集（選用）", False),
    ("accelerate", "訓練加速（選用）", False),
]
for mod, desc, required in packages:
    try:
        m = importlib.import_module(mod)
        ver = getattr(m, "__version__", "?")
        ok(f"{mod:<14} {ver:<12} {desc}")
    except ImportError:
        if required:
            bad(f"{mod:<14} {'未安裝':<12} {desc}")
            issues.append(f"pip install {mod if mod != 'sklearn' else 'scikit-learn'}")
        else:
            warn(f"{mod:<14} {'未安裝':<12} {desc}")

# ── GPU ──
print(f"\n【GPU】")
try:
    import torch
    if torch.cuda.is_available():
        ok(f"CUDA 可用：{torch.cuda.get_device_name(0)}")
        print(f"    CUDA 版本：{torch.version.cuda}")
        print(f"    顯示記憶體：{torch.cuda.get_device_properties(0).total_memory/1024**3:.1f} GB")
    elif hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
        warn("CUDA 不可用，但 MPS（Apple Silicon）可用")
        print("    可用於推論，訓練會較慢")
    else:
        warn("無 GPU 加速，將使用 CPU")
        print("    推論可行，但訓練 3 萬筆資料會非常慢（數十小時）")
        issues.append("若要訓練，需 NVIDIA GPU + CUDA 版 torch")
except ImportError:
    bad("torch 未安裝，無法檢查 GPU")

# ── Semgrep ──
print(f"\n【Semgrep】")
try:
    r = subprocess.run(["semgrep", "--version"], capture_output=True,
                       text=True, timeout=60)
    if r.returncode == 0:
        ok(f"semgrep {r.stdout.strip()}")
    else:
        bad(f"semgrep 執行失敗（returncode={r.returncode}）")
        issues.append("修復 semgrep")
except FileNotFoundError:
    bad("找不到 semgrep 指令")
    issues.append("pip install semgrep")
except Exception as e:
    bad(f"semgrep 錯誤：{type(e).__name__}")
    if "4551" in str(e):
        print("    → 被應用程式控制原則（WDAC）封鎖")
        print("      訓練不受影響，但規則掃描無法執行")
    issues.append("semgrep 被封鎖，需另尋方案")

# ── 專案檔案 ──
print(f"\n【專案結構】")
required_paths = [
    ("core/config_loader.py", "CWE 對應模組", True),
    ("config/cwe_catalog.json", "CWE 百科", True),
    ("config/vuln_categories.json", "漏洞類別定義", True),
    ("rules/python.yml", "Semgrep 規則", True),
    ("transport_layer.py", "傳輸層", True),
    ("typosquat_detector.py", "惡意套件偵測", False),
    ("test_code/real_test/testset_merged.txt", "測試集", False),
]
for p, desc, required in required_paths:
    if os.path.exists(p):
        ok(f"{p:<44} {desc}")
    elif required:
        bad(f"{p:<44} {desc}")
        issues.append(f"缺少 {p}")
    else:
        warn(f"{p:<44} {desc}")

# 補強規則
sup = [f for f in os.listdir("rules") if f.startswith("supplement_")] \
      if os.path.isdir("rules") else []
if sup:
    ok(f"補強規則 {len(sup)} 份：{', '.join(sorted(sup))}")
else:
    warn("未找到補強規則（rules/supplement_*.yml）")

# 模型
print(f"\n【模型】")
if os.path.isdir("models"):
    found = False
    for d in sorted(os.listdir("models")):
        full = os.path.join("models", d)
        if not os.path.isdir(full):
            continue
        w = os.path.join(full, "model.safetensors")
        if os.path.exists(w):
            size = os.path.getsize(w) / 1024**2
            ok(f"{full:<32} {size:.0f} MB")
            found = True
        else:
            ck = [x for x in os.listdir(full) if x.startswith("checkpoint-")]
            if ck:
                warn(f"{full:<32} 僅有 checkpoint（{len(ck)} 個）")
                found = True
    if not found:
        bad("models/ 底下沒有可用的模型")
        issues.append("放入模型檔")
else:
    bad("找不到 models/ 目錄")

# ── 總結 ──
print("\n" + "=" * 62)
if issues:
    print("待處理項目：")
    for i in issues:
        print(f"  • {i}")
else:
    print("✅ 環境完整，可以開始使用")
    print("\n下一步：")
    print("  python semgrep_health.py       確認規則掃描正常")
    print("  python scan.py <檔案>          執行完整掃描")
print("=" * 62)