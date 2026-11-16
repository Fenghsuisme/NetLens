# -*- coding: utf-8 -*-
"""
ov_llm_explain.py — 本地 code LLM「漏洞解釋 + 修復 diff」POC（OpenVINO GenAI）

NetLens 第三階段（LLM Agent 複查/修復）的 on-prem 版本：
  輸入：一個已被 Semgrep 選點、CodeBERT 確認的 finding（類別 + 所在函式）
  輸出：漏洞解釋 + unified diff 修復建議
設計：
  - 依 CWE 注入內部修復準則（PLAYBOOK，等同企業內部的安全編碼規範；可替換為公司自有規範）
  - LLM 輸出「完整修正後程式碼」，diff 由 difflib 計算（小模型直接寫 diff 容易格式錯亂）
模型：OpenVINO/Qwen2.5-Coder-3B-Instruct-int4-ov（INT4 權重，~1.8 GB）
目標部署：與 CodeBERT INT8 同卡共置於 Arc Pro B70（32 GB）。本機以 Intel iGPU 驗證。

用法（只需 openvino-genai）：
  python ov_llm_explain.py --model <ov_model_dir> --device GPU --findings findings.json --out llm_outputs.json
"""
import argparse
import json
import os
import sys
import time

import openvino_genai as ov_genai

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from llm_prompt import SYSTEM, PLAYBOOK, PROMPT, cwe_of, make_diff


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--device", default="GPU")
    ap.add_argument("--findings", default="findings.json")
    ap.add_argument("--out", default="llm_outputs.json")
    ap.add_argument("--max-new-tokens", type=int, default=600)
    a = ap.parse_args()

    t = time.perf_counter()
    pipe = ov_genai.LLMPipeline(a.model, a.device)
    load_s = time.perf_counter() - t
    cfg = ov_genai.GenerationConfig()
    cfg.max_new_tokens = a.max_new_tokens
    cfg.do_sample = False

    findings = json.load(open(a.findings, encoding="utf-8"))
    outs = []
    for f in findings:
        pipe.start_chat(SYSTEM)
        prompt = PROMPT.format(guideline=PLAYBOOK.get(cwe_of(f["category"]), "OWASP best practice"), **f)
        res = pipe.generate([prompt], cfg)
        pipe.finish_chat()
        pm = res.perf_metrics
        text = res.texts[0]
        rec = {
            "id": f["id"], "category": f["category"], "device": a.device,
            "ttft_ms": round(pm.get_ttft().mean, 1),
            "tpot_ms": round(pm.get_tpot().mean, 1),
            "tokens_per_s": round(pm.get_throughput().mean, 1),
            "input_tokens": pm.get_num_input_tokens(),
            "output_tokens": pm.get_num_generated_tokens(),
            "total_s": round(pm.get_generate_duration().mean / 1000, 2),
            "output": text,
            "diff": make_diff(f, text),
        }
        outs.append(rec)
        print(f"== {f['id']} {f['category']} | TTFT {rec['ttft_ms']} ms, "
              f"{rec['tokens_per_s']} tok/s, {rec['output_tokens']} tok\n{text}\n--- diff ---\n{rec['diff']}\n")
    json.dump({"model": a.model, "device": a.device, "load_s": round(load_s, 1), "results": outs},
              open(a.out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)


if __name__ == "__main__":
    main()
