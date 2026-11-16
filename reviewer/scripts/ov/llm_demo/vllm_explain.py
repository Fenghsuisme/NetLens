# -*- coding: utf-8 -*-
"""
vllm_explain.py — 本地 LLM「漏洞解釋 + 修復 diff」（vLLM，OpenAI 相容 API）

與 ov_llm_explain.py 相同的第三階段，改呼叫已啟動的 vLLM 伺服器
（例如在兩張 Arc Pro B70 上以 tensor parallel 跑 Qwen3-14B）。
prompt / PLAYBOOK / diff 計算共用 llm_prompt.py，輸入（findings.json）與
輸出 JSON 格式與 ov_llm_explain.py 一致，可直接比較。

差異：
  - 不載入模型（伺服器已載入），load_s 為 null
  - device 欄位記錄伺服器 URL
  - 指標由串流回應計算：TTFT = 第一個內容 token 抵達時間；
    TPOT = (總時間 - TTFT) / (輸出 tokens - 1)；tokens_per_s = 1000 / TPOT（與 OV 的 throughput 定義對齊）
  - 預設關閉 Qwen3 思考模式（chat_template_kwargs.enable_thinking=false）；--thinking 可開啟，
    輸出中的 <think>…</think> 會被剝除後再解析 diff

用法（只需標準庫）：
  python vllm_explain.py --findings findings.json --out llm_outputs_vllm.json
  python vllm_explain.py --base-url http://localhost:8000/v1 --model Qwen/Qwen3-14B
"""
import argparse
import json
import os
import re
import sys
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from llm_prompt import SYSTEM, PLAYBOOK, PROMPT, cwe_of, make_diff

THINK_RE = re.compile(r"<think>.*?</think>\s*", re.DOTALL)


def _post_stream(url, body, api_key, timeout):
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        for raw in resp:
            line = raw.decode("utf-8").strip()
            if not line.startswith("data:"):
                continue
            data = line[5:].strip()
            if data == "[DONE]":
                return
            yield json.loads(data)


def generate(a, prompt):
    body = {
        "model": a.model,
        "messages": [{"role": "system", "content": SYSTEM},
                     {"role": "user", "content": prompt}],
        "max_tokens": a.max_new_tokens,
        "temperature": 0.0,                      # 對齊 ov_llm_explain 的 do_sample=False
        "stream": True,
        "stream_options": {"include_usage": True},
        "chat_template_kwargs": {"enable_thinking": a.thinking},
    }
    t0 = time.perf_counter()
    ttft = None
    parts, usage = [], {}
    for chunk in _post_stream(a.base_url.rstrip("/") + "/chat/completions", body, a.api_key, a.timeout):
        if chunk.get("usage"):
            usage = chunk["usage"]
        for ch in chunk.get("choices", []):
            delta = ch.get("delta", {})
            piece = delta.get("content") or delta.get("reasoning_content") or ""
            if piece:
                if ttft is None:
                    ttft = time.perf_counter() - t0
                if delta.get("content"):
                    parts.append(delta["content"])
    total = time.perf_counter() - t0
    return "".join(parts), ttft if ttft is not None else total, total, usage


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="http://localhost:8000/v1")
    ap.add_argument("--model", default="Qwen/Qwen3-14B")
    ap.add_argument("--api-key", default=os.environ.get("VLLM_API_KEY"),
                    help="vLLM 以 --api-key 啟動時需要（預設讀 VLLM_API_KEY）")
    ap.add_argument("--findings", default="findings.json")
    ap.add_argument("--out", default="llm_outputs_vllm.json")
    ap.add_argument("--max-new-tokens", type=int, default=600)
    ap.add_argument("--thinking", action="store_true", help="開啟 Qwen3 思考模式（預設關閉）")
    ap.add_argument("--timeout", type=float, default=300)
    a = ap.parse_args()

    device = f"vllm@{a.base_url}"
    findings = json.load(open(a.findings, encoding="utf-8"))
    outs = []
    for f in findings:
        prompt = PROMPT.format(guideline=PLAYBOOK.get(cwe_of(f["category"]), "OWASP best practice"), **f)
        raw, ttft, total, usage = generate(a, prompt)
        text = THINK_RE.sub("", raw).strip()
        n_out = usage.get("completion_tokens", 0)
        tpot = (total - ttft) / (n_out - 1) * 1000 if n_out > 1 else None
        rec = {
            "id": f["id"], "category": f["category"], "device": device,
            "ttft_ms": round(ttft * 1000, 1),
            "tpot_ms": round(tpot, 1) if tpot else None,
            "tokens_per_s": round(1000 / tpot, 1) if tpot else None,
            "input_tokens": usage.get("prompt_tokens"),
            "output_tokens": n_out,
            "total_s": round(total, 2),
            "output": text,
            "diff": make_diff(f, text),
        }
        outs.append(rec)
        print(f"== {f['id']} {f['category']} | TTFT {rec['ttft_ms']} ms, "
              f"{rec['tokens_per_s']} tok/s, {rec['output_tokens']} tok\n{text}\n--- diff ---\n{rec['diff']}\n")
    json.dump({"model": a.model, "device": device, "load_s": None, "results": outs},
              open(a.out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)


if __name__ == "__main__":
    main()
