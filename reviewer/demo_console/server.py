# -*- coding: utf-8 -*-
"""
server.py — NetLens Command Center 後端（Windows 原生 Python，Intel CPU + Intel GPU）

提供給 static/index.html 的即時資料（全部是真實運算，沒有模擬）：
  GET /api/info                     裝置與版本
  GET /api/race?lane=<lane>&n=152   SSE：CodeBERT 逐筆判定（lane 見 LANES）
  GET /api/telemetry                SSE：CPU% 與 Intel GPU%（Windows 效能計數器，同工作管理員）
  GET /api/llm?id=F1                SSE：本地 code LLM（OpenVINO GenAI @ Intel GPU）逐字輸出 + diff
  其餘路徑                           static/ 與 data/ 靜態檔

也可錄製「各 lane 單獨執行」的逐筆時間戳記，供前端 replay 模式使用：
  python server.py --record         → data/race_replay.json

用法（Windows，模型放在 --models 目錄下）：
  python server.py --models %USERPROFILE%\\ov_models [--port 8765] [--no-llm]
  模型目錄需含：codebert_v7v8_safe/（PyTorch，含 tokenizer）、codebert_ov_int8/、
               codebert_ov_fp32/、qwen2.5-coder-3b-int4-ov/
"""
import argparse
import json
import os
import queue
import sys
import threading
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

BATCH = 8
MAX_LEN = 512

# 賽道定義：(顯示名稱, 後端, 裝置, IR 子目錄)
LANES = {
    "pytorch-cpu": ("PyTorch FP32 · CPU", "pytorch", "cpu", None),
    "ov-cpu-int8": ("OpenVINO INT8 · Intel CPU", "openvino", "CPU", "codebert_ov_int8"),
    "ov-gpu": ("OpenVINO FP16 · Intel GPU", "openvino", "GPU.0", "codebert_ov_fp32"),
    "ov-gpu-int8": ("OpenVINO INT8 · Intel GPU", "openvino", "GPU.0", "codebert_ov_int8"),
}


def strip_comments(code):
    """與 scan.py::_strip_comments 相同（前處理需與訓練/產品一致）"""
    import re
    s = str(code)
    s = re.sub(r'"""(.*?)"""', "", s, flags=re.DOTALL)
    s = re.sub(r"'''(.*?)'''", "", s, flags=re.DOTALL)
    s = re.sub(r"/\*.*?\*/", "", s, flags=re.DOTALL)
    s = re.sub(r"//.*", "", s)
    s = re.sub(r"#.*", "", s)
    return re.sub(r"\n\s*\n+", "\n", s).strip()


def softmax(x):
    e = np.exp(x - x.max(axis=1, keepdims=True))
    return e / e.sum(axis=1, keepdims=True)


# ─────────────────────────── CodeBERT 賽道 ───────────────────────────

class Engines:
    def __init__(self, models_dir, lanes):
        from transformers import AutoTokenizer
        import openvino as ov
        self.models_dir = models_dir
        self.core = ov.Core()
        self.ov = ov
        self.tok = AutoTokenizer.from_pretrained(os.path.join(models_dir, "codebert_v7v8_safe"))
        race_path = os.path.join(HERE, "data", "race_set.json")
        if not os.path.exists(race_path):
            raise SystemExit("找不到 data/race_set.json（測試集內容，未公開）。"
                             "請在有測試集的機器上執行 python demo_console/build_race_set.py")
        data = json.load(open(race_path, encoding="utf-8"))
        self.items = data["items"]
        codes = []
        for it in self.items:
            c = strip_comments(it["code"])
            codes.append((c if len(c) >= 10 else it["code"])[:2000])
        self.enc = self.tok(codes, max_length=MAX_LEN, padding="max_length",
                            truncation=True, return_tensors="np")
        self.compiled, self.pt = {}, None
        self.locks = {k: threading.Lock() for k in LANES}
        for lane in lanes:
            self.prepare(lane)

    def prepare(self, lane):
        _, backend, device, sub = LANES[lane]
        t = time.time()
        if backend == "pytorch":
            import torch
            from transformers import AutoModelForSequenceClassification
            self.torch = torch
            self.pt = AutoModelForSequenceClassification.from_pretrained(
                os.path.join(self.models_dir, "codebert_v7v8_safe")).eval()
        else:
            cm = self.core.compile_model(os.path.join(self.models_dir, sub, "openvino_model.xml"),
                                         device, {"PERFORMANCE_HINT": "THROUGHPUT"})
            self.compiled[lane] = cm
        # 暖機：讓比賽開始時沒有編譯/首次推論延遲
        for _ in range(2):
            for _ in self.run(lane, 8):
                pass
        print(f"  [ready] {lane:<12} {LANES[lane][0]:<28} {time.time() - t:5.1f}s", flush=True)

    def run(self, lane, n):
        """依序產生 (index, pred, conf)。OpenVINO 用 AsyncInferQueue 吃滿裝置。"""
        n = min(n, len(self.items))
        _, backend, _, _ = LANES[lane]
        batches = [(i, {k: self.enc[k][i:min(i + BATCH, n)] for k in ("input_ids", "attention_mask")})
                   for i in range(0, n, BATCH)]
        if backend == "pytorch":
            with self.torch.no_grad():
                for i, b in batches:
                    logits = self.pt(**{k: self.torch.from_numpy(v) for k, v in b.items()}).logits.numpy()
                    yield from self._emit(i, logits)
            return
        cm = self.compiled[lane]
        done = queue.Queue()
        aq = self.ov.AsyncInferQueue(cm, cm.get_property("OPTIMAL_NUMBER_OF_INFER_REQUESTS"))
        aq.set_callback(lambda req, i: done.put((i, req.get_output_tensor(0).data.copy())))
        for i, b in batches:
            aq.start_async(b, i)
            while not done.empty():
                yield from self._emit(*done.get())
        aq.wait_all()
        while not done.empty():
            yield from self._emit(*done.get())

    def _emit(self, start, logits):
        p = softmax(logits)
        for j in range(len(p)):
            k = int(p[j].argmax())
            yield start + j, k, float(p[j][k])


# ─────────────────────────── 遙測（同工作管理員） ───────────────────────────

class Telemetry:
    """以 Windows PDH 讀 GPU Engine 使用率；只計 Intel iGPU 的 LUID。"""

    def __init__(self, luid_hex):
        import psutil
        self.psutil = psutil
        self.luid = None
        if luid_hex:
            b = bytes.fromhex(luid_hex)
            low, high = int.from_bytes(b[:4], "little"), int.from_bytes(b[4:8], "little", signed=True)
            self.luid = f"luid_0x{high & 0xffffffff:08x}_0x{low:08x}"
        self.value = {"cpu": 0.0, "gpu": 0.0, "gpu_engine": ""}
        psutil.cpu_percent()
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self):
        import win32pdh
        q, handles, last_expand = None, {}, 0
        while True:
            try:
                if time.time() - last_expand > 2 or q is None:
                    if q:
                        win32pdh.CloseQuery(q)
                    q = win32pdh.OpenQuery()
                    paths = win32pdh.ExpandCounterPath(r"\GPU Engine(*)\Utilization Percentage")
                    handles = {p: win32pdh.AddCounter(q, p) for p in paths
                               if self.luid and self.luid in p.lower()}
                    win32pdh.CollectQueryData(q)
                    last_expand = time.time()
                    time.sleep(0.25)
                win32pdh.CollectQueryData(q)
                per_engine = {}
                for p, h in handles.items():
                    try:
                        v = win32pdh.GetFormattedCounterValue(h, win32pdh.PDH_FMT_DOUBLE)[1]
                    except Exception:
                        continue
                    inst = p[p.index("(") + 1:p.index(")")]
                    eng = inst.split("_phys_")[1]          # 例如 0_eng_0_engtype_3D
                    per_engine[eng] = per_engine.get(eng, 0.0) + v
                top = max(per_engine.items(), key=lambda kv: kv[1], default=("", 0.0))
                self.value = {"cpu": self.psutil.cpu_percent(), "gpu": min(100.0, top[1]),
                              "gpu_engine": top[0].split("engtype_")[-1]}
            except Exception as e:
                self.value = {"cpu": self.psutil.cpu_percent(), "gpu": 0.0, "gpu_engine": f"err:{e}"}
            time.sleep(0.25)


# ─────────────────────────── 本地 LLM ───────────────────────────

class LLM:
    def __init__(self, model_dir, device):
        import openvino_genai as ov_genai
        sys.path.insert(0, os.path.join(HERE, "..", "scripts", "ov", "llm_demo"))
        import ov_llm_explain as X
        self.X = X
        self.genai = ov_genai
        self.device = device
        self.findings = {f["id"]: f for f in json.load(
            open(os.path.join(HERE, "data", "llm_findings.json"), encoding="utf-8"))}
        t = time.time()
        self.pipe = ov_genai.LLMPipeline(model_dir, device)
        self.lock = threading.Lock()
        # 暖機一次，避免錄影時第一個請求慢
        cfg = ov_genai.GenerationConfig()
        cfg.max_new_tokens = 8
        self.pipe.generate("def add(a, b):", cfg)
        print(f"  [ready] llm          {os.path.basename(model_dir)} @ {device} {time.time() - t:5.1f}s", flush=True)

    def stream(self, fid, emit):
        f = self.findings[fid]
        prompt = self.X.PROMPT.format(guideline=self.X.PLAYBOOK.get(self.X.cwe_of(f["category"]),
                                                                     "OWASP best practice"), **f)
        cfg = self.genai.GenerationConfig()
        cfg.max_new_tokens = 600
        cfg.do_sample = False

        def streamer(sub):
            emit("token", {"t": sub})
            return self.genai.StreamingStatus.RUNNING

        with self.lock:
            history = self.genai.ChatHistory()
            history.append({"role": "system", "content": self.X.SYSTEM})
            history.append({"role": "user", "content": prompt})
            res = self.pipe.generate(history, cfg, streamer)
        text = res.texts[0]
        pm = res.perf_metrics
        emit("done", {
            "diff": self.X.make_diff(f, text),
            "ttft_ms": round(pm.get_ttft().mean, 1),
            "tokens_per_s": round(pm.get_throughput().mean, 1),
            "output_tokens": pm.get_num_generated_tokens(),
            "total_s": round(pm.get_generate_duration().mean / 1000, 2),
        })


# ─────────────────────────── HTTP ───────────────────────────

STATE = {}


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=HERE, **kw)

    def log_message(self, fmt, *args):
        pass

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def sse_start(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

    def sse(self, event, data):
        self.wfile.write(f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n".encode("utf-8"))
        self.wfile.flush()

    def do_GET(self):
        u = urlparse(self.path)
        qs = {k: v[0] for k, v in parse_qs(u.query).items()}
        try:
            if u.path == "/":
                self.send_response(302)
                self.send_header("Location", "/static/index.html")
                self.end_headers()
            elif u.path == "/api/info":
                self.json(STATE["info"])
            elif u.path == "/api/race":
                self.race(qs.get("lane", "ov-gpu"), int(qs.get("n", 152)))
            elif u.path == "/api/telemetry":
                self.sse_start()
                while True:
                    self.sse("t", STATE["telemetry"].value if STATE.get("telemetry") else {})
                    time.sleep(0.25)
            elif u.path == "/api/llm":
                self.llm(qs.get("id", "F1"))
            else:
                super().do_GET()
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass

    def json(self, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def race(self, lane, n):
        eng = STATE["engines"]
        if lane not in eng.locks or (LANES[lane][1] == "openvino" and lane not in eng.compiled) \
                or (LANES[lane][1] == "pytorch" and eng.pt is None):
            self.send_error(404, f"lane {lane} not loaded")
            return
        self.sse_start()
        with eng.locks[lane]:
            self.sse("start", {"lane": lane, "name": LANES[lane][0], "n": min(n, len(eng.items))})
            t0 = time.perf_counter()
            k = 0
            for i, pred, conf in eng.run(lane, n):
                k += 1
                self.sse("item", {"i": i, "pred": pred, "conf": round(conf, 3),
                                  "t": round((time.perf_counter() - t0) * 1000, 1)})
            el = time.perf_counter() - t0
            self.sse("done", {"elapsed_s": round(el, 2), "fps": round(k / el, 1), "n": k})

    def llm(self, fid):
        if not STATE.get("llm"):
            self.send_error(404, "LLM not loaded")
            return
        self.sse_start()
        STATE["llm"].stream(fid, self.sse)


def record(engines, lanes, out):
    """各 lane「單獨」執行（不互相搶資源），存逐筆時間戳記供 replay。"""
    rec = {"recorded_at": time.strftime("%Y-%m-%d %H:%M:%S"), "info": STATE["info"], "lanes": {}}
    for lane in lanes:
        time.sleep(3)
        t0, ev = time.perf_counter(), []
        for i, pred, conf in engines.run(lane, len(engines.items)):
            ev.append({"i": i, "pred": pred, "conf": round(conf, 3),
                       "t": round((time.perf_counter() - t0) * 1000, 1)})
        el = time.perf_counter() - t0
        rec["lanes"][lane] = {"name": LANES[lane][0], "elapsed_s": round(el, 2),
                              "fps": round(len(ev) / el, 1), "events": ev}
        print(f"  [record] {lane:<12} {len(ev)} items {el:6.2f}s {len(ev) / el:5.1f}/s", flush=True)
    json.dump(rec, open(out, "w", encoding="utf-8"), ensure_ascii=False)
    print(f"→ {out}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", required=True)
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--lanes", default="pytorch-cpu,ov-cpu-int8,ov-gpu")
    ap.add_argument("--llm", default="qwen2.5-coder-3b-int4-ov")
    ap.add_argument("--llm-device", default="GPU.0")
    ap.add_argument("--no-llm", action="store_true")
    ap.add_argument("--record", action="store_true")
    a = ap.parse_args()

    import openvino as ov
    core = ov.Core()
    lanes = [l for l in a.lanes.split(",") if l]
    print("NetLens Command Center — loading engines", flush=True)
    info = {"openvino": ov.__version__,
            "devices": {d: core.get_property(d, "FULL_DEVICE_NAME") for d in core.available_devices},
            "lanes": {l: LANES[l][0] for l in lanes}, "llm": None}
    STATE["info"] = info
    engines = Engines(a.models, lanes)
    STATE["engines"] = engines
    if a.record:
        record(engines, lanes, os.path.join(HERE, "data", "race_replay.json"))
        return
    luid = None
    try:
        luid = core.get_property("GPU.0", "DEVICE_LUID")
    except Exception:
        pass
    STATE["telemetry"] = Telemetry(luid)
    if not a.no_llm:
        STATE["llm"] = LLM(os.path.join(a.models, a.llm), a.llm_device)
        info["llm"] = f"{a.llm} @ {core.get_property(a.llm_device, 'FULL_DEVICE_NAME')}"
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), Handler)
    srv.daemon_threads = True
    print(f"\n  ▶ open http://127.0.0.1:{a.port}/  (keys 1-6 switch scenes, F11 fullscreen)\n", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
