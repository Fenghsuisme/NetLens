# -*- coding: utf-8 -*-
"""
ov_benchmark.py — CodeBERT 推論效能基準（512 token 固定長度，與 scan.py 一致）

只依賴 openvino + numpy（pytorch 後端才需要 torch），因此可直接在
Windows 原生 Python 上跑 Intel iGPU（WSL2 目前看不到 Intel GPU）。

量測：
  latency  : batch=1，同步推論，PERFORMANCE_HINT=LATENCY，暖機後取中位數 / p90（ms/函式）
  batch8   : batch=8，同步推論，回報 ms/batch 與 函式/秒
  thrpt    : batch=8，PERFORMANCE_HINT=THROUGHPUT + AsyncInferQueue（裝置建議的並行請求數），
             固定時長，回報 函式/秒（模擬 scan 大量 finding 排隊送審的情境）

用法：
  python ov_benchmark.py --backend openvino --model <dir>/openvino_model.xml --device CPU --tag ov_int8
  python ov_benchmark.py --backend pytorch  --model <hf_model_dir> --device cuda --tag pytorch
結果附加到 --out（JSON lines）
"""
import argparse
import json
import os
import platform
import statistics
import time

import numpy as np

SEQ = 512


def make_inputs(bs, seed=0):
    rng = np.random.default_rng(seed)
    ids = rng.integers(3, 50000, size=(bs, SEQ), dtype=np.int64)
    ids[:, 0], ids[:, -1] = 0, 2           # <s> ... </s>
    return {"input_ids": ids, "attention_mask": np.ones((bs, SEQ), dtype=np.int64)}


def timed(fn, warmup, iters):
    for _ in range(warmup):
        fn()
    ts = []
    for _ in range(iters):
        t = time.perf_counter()
        fn()
        ts.append((time.perf_counter() - t) * 1000)
    return statistics.median(ts), sorted(ts)[int(0.9 * len(ts)) - 1]


def bench_openvino(a):
    import openvino as ov
    core = ov.Core()
    dev_name = core.get_property(a.device, "FULL_DEVICE_NAME")
    model = core.read_model(a.model)
    res = {"device_name": dev_name, "ov_version": ov.__version__}

    t = time.perf_counter()
    cm = core.compile_model(model, a.device, {"PERFORMANCE_HINT": "LATENCY"})
    res["compile_s"] = round(time.perf_counter() - t, 2)
    try:
        res["inference_precision"] = str(cm.get_property("INFERENCE_PRECISION_HINT"))
    except Exception:
        pass
    req = cm.create_infer_request()
    for bs in (1, 8):
        x = make_inputs(bs)
        med, p90 = timed(lambda: req.infer(x), a.warmup, a.iters if bs == 1 else max(10, a.iters // 4))
        res[f"b{bs}_ms_median"] = round(med, 2)
        res[f"b{bs}_ms_p90"] = round(p90, 2)
        res[f"b{bs}_fps"] = round(bs * 1000 / med, 1)

    cm = core.compile_model(model, a.device, {"PERFORMANCE_HINT": "THROUGHPUT"})
    nreq = cm.get_property("OPTIMAL_NUMBER_OF_INFER_REQUESTS")
    q = ov.AsyncInferQueue(cm, nreq)
    x = make_inputs(8)
    for _ in range(nreq * 2):
        q.start_async(x)
    q.wait_all()
    n, t = 0, time.perf_counter()
    while time.perf_counter() - t < a.duration:
        q.start_async(x)
        n += 8
    q.wait_all()
    res["thrpt_nreq"] = int(nreq)
    res["thrpt_fps"] = round(n / (time.perf_counter() - t), 1)
    return res


def bench_pytorch(a):
    import torch
    from transformers import AutoModelForSequenceClassification
    dev = torch.device(a.device)
    m = AutoModelForSequenceClassification.from_pretrained(a.model).eval().to(dev)
    res = {"device_name": torch.cuda.get_device_name(0) if dev.type == "cuda" else platform.processor() or "cpu",
           "torch_version": torch.__version__, "torch_threads": torch.get_num_threads()}

    def run(x):
        with torch.no_grad():
            m(**x)
        if dev.type == "cuda":
            torch.cuda.synchronize()

    for bs in (1, 8):
        x = {k: torch.from_numpy(v).to(dev) for k, v in make_inputs(bs).items()}
        med, p90 = timed(lambda: run(x), a.warmup, a.iters if bs == 1 else max(10, a.iters // 4))
        res[f"b{bs}_ms_median"] = round(med, 2)
        res[f"b{bs}_ms_p90"] = round(p90, 2)
        res[f"b{bs}_fps"] = round(bs * 1000 / med, 1)
    res["thrpt_fps"] = res["b8_fps"]
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", choices=["openvino", "pytorch"], required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--device", default="CPU")
    ap.add_argument("--tag", required=True)
    ap.add_argument("--host", default=platform.system())
    ap.add_argument("--warmup", type=int, default=10)
    ap.add_argument("--iters", type=int, default=60)
    ap.add_argument("--duration", type=float, default=15.0)
    ap.add_argument("--out", default="bench.jsonl")
    a = ap.parse_args()

    res = bench_openvino(a) if a.backend == "openvino" else bench_pytorch(a)
    res = {"tag": a.tag, "backend": a.backend, "device": a.device, "host": a.host, **res}
    print(json.dumps(res, ensure_ascii=False))
    with open(a.out, "a", encoding="utf-8") as f:
        f.write(json.dumps(res, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()
