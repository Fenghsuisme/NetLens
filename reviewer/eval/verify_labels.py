# -*- coding: utf-8 -*-
"""
verify_labels.py — 驗證模型標籤順序是否與腳本假設一致

問題背景：
  v7v8_safe 的訓練驗證 F1 與端到端測試出現無法解釋的落差：

      類別              訓練驗證 F1    端到端整檔對照
      不受限檔案上傳        0.971    →     6.7%
      權限控制缺陷         0.888    →     0.0%
      資料外洩            0.947    →    30.0%
      後門               0.957    →    96.7%   （一致）

  「整檔對照」不經 Semgrep，純為模型能力。
  0.888 掉到 0.0% 不可能是正常的泛化差距。

兩種可能：
  A. 標籤順序不一致 —— 訓練時的 label 編號與本腳本的 LABEL_NAMES 對不上，
     模型判對卻被算成錯（曾發生過：code_analyzer.py 的過時 LABEL_MAP）
  B. 真實的泛化失敗 —— 訓練樣本樣板化，模型記住樣板而非概念，
     換一批測試資料就失效（後門的前例：合成資料 F1 0.957，真實 CVE 0/23）

本腳本的判別方式：
  對每個類別取數筆測試樣本，記錄模型「實際輸出的 label」。
  若某類別的預測穩定集中在另一個固定的 label，即為標籤錯位（可能 A）；
  若預測分散、或大量落在 label 0（正常程式碼），則為泛化失敗（可能 B）。

用法：
  python eval/verify_labels.py            每類 10 筆
  python eval/verify_labels.py -n 20      每類 20 筆
"""
import argparse
import glob
import os
import re
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from testset_parser import parse_testset
from label_map import config_to_model, MODEL_LABEL_NAMES

MODEL_DIR = "models/codebert_v7v8_safe"
BASE_MODEL = "microsoft/codebert-base"
STRIP_COMMENTS = True
OBFUSCATE_FUNCS = True

try:
    from obfuscate import obfuscate_functions
    HAS_OBF = True
except ImportError:
    HAS_OBF = False

LABEL_NAMES = MODEL_LABEL_NAMES


def _strip(code):
    s = str(code)
    s = re.sub(r'"""(.*?)"""', "", s, flags=re.DOTALL)
    s = re.sub(r"'''(.*?)'''", "", s, flags=re.DOTALL)
    s = re.sub(r"/\*.*?\*/", "", s, flags=re.DOTALL)
    s = re.sub(r"//.*", "", s)
    s = re.sub(r"#.*", "", s)
    return re.sub(r"\n\s*\n+", "\n", s).strip()


def _is_loadable(d):
    has_w = any(os.path.exists(os.path.join(d, f))
                for f in ("model.safetensors", "pytorch_model.bin"))
    return has_w and os.path.exists(os.path.join(d, "config.json"))


def _resolve(md):
    if _is_loadable(md):
        return md
    ck = [c for c in glob.glob(os.path.join(md, "checkpoint-*")) if _is_loadable(c)]
    if not ck:
        return None
    ck.sort(key=lambda p: int(p.split("-")[-1]))
    return ck[-1]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", "--sample", type=int, default=10)
    ap.add_argument("--no-obfuscate", action="store_true",
                    help="關閉函式名混淆（用於比對混淆是否造成影響）")
    args = ap.parse_args()

    use_obf = OBFUSCATE_FUNCS and HAS_OBF and not args.no_obfuscate

    path = _resolve(MODEL_DIR)
    if path is None:
        print(f"❌ 找不到模型：{MODEL_DIR}")
        return 1

    import torch
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    tok = AutoTokenizer.from_pretrained(BASE_MODEL)
    model = AutoModelForSequenceClassification.from_pretrained(path).to(device)
    model.eval()

    n_labels = model.config.num_labels
    print(f"模型：{path}")
    print(f"類別數：{n_labels}（腳本假設 {len(LABEL_NAMES)}）")
    if n_labels != len(LABEL_NAMES):
        print(f"⚠️ 類別數不符！模型 {n_labels} vs 腳本 {len(LABEL_NAMES)}")
    print(f"函式名混淆：{'開啟' if use_obf else '關閉'}")
    print(f"剝除註解：{'開啟' if STRIP_COMMENTS else '關閉'}\n")

    def classify(code, lang):
        c = _strip(code) if STRIP_COMMENTS else code
        if use_obf:
            c = obfuscate_functions(c, lang)
        enc = tok(c[:2000], max_length=512, padding="max_length",
                  truncation=True, return_tensors="pt").to(device)
        with torch.no_grad():
            p = torch.softmax(model(**enc).logits, dim=1)
            lb = int(torch.argmax(p, dim=1).item())
            return lb, float(p[0][lb].item())

    items = parse_testset()
    by_label = defaultdict(list)
    n_skip = 0
    for it in items:
        lb = config_to_model(it["label"])
        if lb is None:
            n_skip += 1
            continue
        by_label[lb].append(it)
    if n_skip:
        print(f"（{n_skip} 筆的類別不在模型 17 類範圍內，已排除）\n")

    print("=" * 78)
    print("各類別的模型實際輸出分布")
    print("=" * 78)
    print(f"  {'真實類別':<16} {'樣本':>4}  預測分布（label: 次數）")
    print("  " + "-" * 68)

    suspects = []
    for lb in sorted(by_label):
        group = by_label[lb][:args.sample]
        if not group:
            continue
        preds = Counter()
        confs = []
        for it in group:
            p, c = classify(it["code"], it["lang"])
            preds[p] += 1
            confs.append(c)

        correct = preds.get(lb, 0)
        top = preds.most_common(3)
        dist = "  ".join(
            f"{LABEL_NAMES.get(p, p)}({p}):{n}" for p, n in top)
        acc = correct / len(group)
        mark = ""
        if acc < 0.3:
            # 判別：預測是否集中在單一其他類別
            top_label, top_n = top[0]
            if top_label != lb and top_n / len(group) >= 0.6:
                mark = f"  ⚠️ 高度集中於 label {top_label}"
                suspects.append((lb, top_label, top_n / len(group)))
            elif top_label == 0:
                mark = "  ⚠️ 多判為正常程式碼"
            else:
                mark = "  ⚠️ 預測分散"
        print(f"  {LABEL_NAMES[lb]:<16} {len(group):>4}  {dist}{mark}")
        print(f"  {'':16} {'':>4}  正確率 {acc:.0%}　平均信心 "
              f"{sum(confs)/len(confs):.0%}")

    print("\n" + "=" * 78)
    print("判讀")
    print("=" * 78)
    if suspects:
        print("\n  以下類別的預測高度集中於另一固定 label，")
        print("  符合「標籤順序錯位」的特徵：\n")
        for true_lb, pred_lb, ratio in suspects:
            print(f"    真實 {LABEL_NAMES[true_lb]}(label {true_lb})"
                  f"  →  模型多輸出 {LABEL_NAMES.get(pred_lb, pred_lb)}"
                  f"(label {pred_lb})　{ratio:.0%}")
        print("\n  建議與訓練端確認 v7v8_safe 的 label 對應順序。")
    else:
        print("\n  未發現明顯的標籤錯位（預測未集中於單一其他類別）。")
        print("  若某些類別正確率仍低，較可能是泛化問題 ——")
        print("  訓練樣本樣板化，模型記住樣板而非概念，")
        print("  換一批測試資料即失效。")
        print("\n  驗證方式：以訓練集的樣本測試同一模型，")
        print("  若訓練集分數高而測試集低，即為泛化失敗。")

    print(f"\n  註：本腳本使用的標籤對應（若與訓練端不符須修正）")
    for i in range(len(LABEL_NAMES)):
        print(f"    {i:>2}  {LABEL_NAMES[i]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())