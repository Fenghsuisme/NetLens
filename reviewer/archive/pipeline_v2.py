# -*- coding: utf-8 -*-
"""
pipeline_v2.py — 完整兩階段管道：Semgrep → 傳輸層 → CodeBERT → 融合

流程：
  1. transport_layer 跑 Semgrep 並抽取 A 類片段
  2. 每個片段餵給 CodeBERT（v6, 17類）分類
  3. 融合 Semgrep 與 CodeBERT 的判定：
     - 兩者一致        → 高信心確認
     - CodeBERT 判正常 → Semgrep 誤報，過濾掉
     - 兩者不一致      → 標記存疑，並列兩個判定
  4. B 類（僅 Semgrep）直接列入報告

執行：python pipeline_v2.py <程式碼檔案>
"""
import os
import sys
import glob

import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

# 已移入子目錄，需往上一層才能 import 到 reviewer/ 下的模組
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from transport_layer import process, LANG_EXT
from core.config_loader import cwe_to_category, get_category, label_to_category

MODEL_DIR = "models/codebert_v6"
BASE_MODEL = "microsoft/codebert-base"
STRIP_COMMENTS = True   # 剝註解


LABEL_NAMES = {
    0: "正常程式碼", 1: "指令注入", 2: "SQL 注入", 3: "程式碼執行",
    4: "資料外洩", 5: "後門", 6: "弱加密", 7: "硬編碼密碼",
    8: "路徑遊走", 9: "不安全反序列化", 10: "跨站腳本", 11: "原型污染",
    12: "惡意套件", 13: "跨站請求偽造", 14: "SSRF",
    15: "不受限檔案上傳", 16: "權限控制缺陷",
}


def _resolve_model(model_dir):
    if os.path.exists(os.path.join(model_dir, "model.safetensors")):
        return model_dir
    ckpts = [c for c in glob.glob(os.path.join(model_dir, "checkpoint-*"))
             if os.path.exists(os.path.join(c, "model.safetensors"))]
    if not ckpts:
        return None
    ckpts.sort(key=lambda p: int(p.split("-")[-1]))
    return ckpts[-1]


def _strip_comments(code):
    import re
    s = str(code)
    s = re.sub(r'"""(.*?)"""', "", s, flags=re.DOTALL)
    s = re.sub(r"'''(.*?)'''", "", s, flags=re.DOTALL)
    s = re.sub(r"/\*.*?\*/", "", s, flags=re.DOTALL)
    s = re.sub(r"//.*", "", s)
    s = re.sub(r"#.*", "", s)
    return re.sub(r"\n\s*\n+", "\n", s).strip()


class Pipeline:
    def __init__(self):
        model_path = _resolve_model(MODEL_DIR)
        if model_path is None:
            raise RuntimeError(f"找不到模型：{MODEL_DIR}")
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.tok = AutoTokenizer.from_pretrained(BASE_MODEL)
        self.model = AutoModelForSequenceClassification.from_pretrained(
            model_path).to(self.device)
        self.model.eval()

    def classify(self, snippet):
        """CodeBERT 分類一個片段，回傳 (label, 中文名, 信心)"""
        code = _strip_comments(snippet) if STRIP_COMMENTS else snippet
        if len(code) < 10:
            code = snippet
        enc = self.tok(code[:2000], max_length=512, padding="max_length",
                       truncation=True, return_tensors="pt").to(self.device)
        with torch.no_grad():
            probs = torch.softmax(self.model(**enc).logits, dim=1)
            label = int(torch.argmax(probs, dim=1).item())
            conf = float(probs[0][label].item())
        return label, LABEL_NAMES[label], conf

    def scan(self, code, language):
        """完整掃描，回傳結構化結果"""
        transport = process(code, language)

        confirmed = []    # Semgrep + CodeBERT 一致
        filtered = []     # CodeBERT 判正常 → 過濾誤報
        disputed = []     # 兩者不一致

        for item in transport["to_codebert"]:
            cb_label, cb_name, cb_conf = self.classify(item["snippet"])
            sg_category = item["semgrep_category"]
            sg_cwe = item["semgrep_cwe"]

            # CodeBERT 對應到的 category
            cb_category = label_to_category(cb_label)

            record = {
                "hit_line": item["hit_line"],
                "snippet_start": item["snippet_start"],
                "snippet_end": item["snippet_end"],
                "semgrep_cwe": sg_cwe,
                "semgrep_category_zh": item["semgrep_category_zh"],
                "codebert_label": cb_label,
                "codebert_name": cb_name,
                "codebert_conf": cb_conf,
                "snippet": item["snippet"],
            }

            if cb_label == 0:
                # CodeBERT 判正常 → Semgrep 誤報
                filtered.append(record)
            elif cb_category == sg_category:
                # 一致 → 高信心確認
                confirmed.append(record)
            else:
                # 不一致 → 存疑
                disputed.append(record)

        return {
            "confirmed": confirmed,
            "filtered": filtered,
            "disputed": disputed,
            "semgrep_only": transport["semgrep_only"],
            "skipped": transport["skipped"],
        }


def _print_report(result, path, language):
    print("=" * 72)
    print(f"兩階段掃描報告：{path}（{language}）")
    print("=" * 72)

    print(f"\n✅ 【確認漏洞】Semgrep + CodeBERT 一致（{len(result['confirmed'])}）")
    for r in result["confirmed"]:
        print(f"  第 {r['hit_line']} 行　{r['codebert_name']}"
              f"（CWE + 模型一致，信心 {r['codebert_conf']:.0%}）")

    print(f"\n🔍 【存疑】兩引擎判定不同（{len(result['disputed'])}）")
    for r in result["disputed"]:
        print(f"  第 {r['hit_line']} 行　Semgrep:{r['semgrep_category_zh']}"
              f" vs CodeBERT:{r['codebert_name']}（信心 {r['codebert_conf']:.0%}）")

    print(f"\n⚪ 【已過濾誤報】CodeBERT 判為正常程式碼（{len(result['filtered'])}）")
    for r in result["filtered"]:
        print(f"  第 {r['hit_line']} 行　Semgrep 報 {r['semgrep_category_zh']}，"
              f"但 CodeBERT 判正常（信心 {r['codebert_conf']:.0%}）→ 過濾")

    print(f"\n📋 【僅 Semgrep 偵測】B類，未經模型深析（{len(result['semgrep_only'])}）")
    for r in result["semgrep_only"]:
        print(f"  第 {r['line']} 行　{r['category_zh']}（{r['cwe']}）")

    print("\n" + "=" * 72)
    total_real = len(result["confirmed"]) + len(result["disputed"])
    print(f"摘要：確認 {len(result['confirmed'])}　存疑 {len(result['disputed'])}"
          f"　過濾誤報 {len(result['filtered'])}　僅Semgrep {len(result['semgrep_only'])}")


def main():
    if len(sys.argv) < 2:
        print("用法：python pipeline_v2.py <程式碼檔案>")
        return
    path = sys.argv[1]
    if not os.path.exists(path):
        print(f"❌ 找不到 {path}")
        return
    ext = os.path.splitext(path)[1].lower()
    lang = next((l for l, e in LANG_EXT.items() if e == ext), None)
    if not lang:
        print(f"❌ 不支援的副檔名 {ext}")
        return

    code = open(path, encoding="utf-8").read()
    print("載入 CodeBERT v6...")
    pipe = Pipeline()
    result = pipe.scan(code, lang)
    _print_report(result, path, lang)


if __name__ == "__main__":
    main()