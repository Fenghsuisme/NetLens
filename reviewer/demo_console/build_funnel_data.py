# -*- coding: utf-8 -*-
"""
build_funnel_data.py — 為 Command Center「掃描漏斗」場景產生真實掃描資料

對一個真實專案跑完整 NetLens 管道（Semgrep + CodeBERT，--backend openvino），
檔案篩選與 tools/bench_real_projects.py 相同（排除測試/文件/生成檔），
把每個 finding 的檔名、行號、規則、片段、模型判定寫成 JSON 給前端動畫使用。

用法（reviewer/ 下，需 semgrep 在 PATH）：
  python demo_console/build_funnel_data.py /path/to/healthchecks --name healthchecks
"""
import argparse
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))
os.chdir(ROOT)

from scan import Scanner, LABEL_NAMES
from bench_real_projects import collect, loc_of

# 模型 17 類 → 影片用英文名稱
LABEL_EN = {
    0: "Benign", 1: "Command Injection", 2: "SQL Injection", 3: "Code Execution",
    4: "Data Exposure", 5: "Backdoor", 6: "Weak Crypto", 7: "Hardcoded Secret",
    8: "Path Traversal", 9: "Insecure Deserialization", 10: "XSS",
    11: "Prototype Pollution", 12: "Malicious Package", 13: "CSRF", 14: "SSRF",
    15: "Unrestricted Upload", 16: "Broken Access Control",
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("project")
    ap.add_argument("--name", required=True)
    ap.add_argument("--max-files", type=int, default=800)
    ap.add_argument("--ov-device", default="CPU")
    a = ap.parse_args()

    files, total = collect(a.project, a.max_files)
    scanner = Scanner(use_model=True, with_official=False,
                      backend="openvino", ov_device=a.ov_device)
    findings, loc, t0 = [], 0, time.time()
    for i, (fp, lang) in enumerate(files, 1):
        loc += loc_of(fp)
        code = open(fp, encoding="utf-8", errors="ignore").read()
        rel = os.path.relpath(fp, a.project)
        r = scanner.scan_code(code, lang, rel)
        src_lines = code.splitlines()
        for verdict in ("confirmed", "disputed", "filtered"):
            for f in r.get(verdict, []):
                findings.append({
                    "file": rel, "line": f["line"], "lang": lang,
                    "rule": f["engine_rule"].split(".")[-1], "cwe": f.get("engine_cwe"),
                    "engine_category": f.get("engine_category"),
                    "snippet": f["snippet"][:1200],
                    "hit_code": src_lines[f["line"] - 1].strip()[:160] if 0 < f["line"] <= len(src_lines) else "",
                    "model_label": f.get("model_label"),
                    "model_name": LABEL_EN.get(f.get("model_label"), str(f.get("model_label"))),
                    "model_conf": round(f.get("model_conf") or 0, 3),
                    "verdict": verdict,
                })
        if i % 25 == 0:
            print(f"  {i}/{len(files)} 檔，finding {len(findings)}", flush=True)
    out = {
        "project": a.name, "files_scanned": len(files), "files_total": total, "loc": loc,
        "elapsed_s": round(time.time() - t0, 1), "backend": f"OpenVINO INT8 ({scanner.device})",
        "findings": findings,
    }
    path = os.path.join(ROOT, "demo_console", "data", f"funnel_{a.name}.json")
    json.dump(out, open(path, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    c = {v: sum(f["verdict"] == v for f in findings) for v in ("confirmed", "disputed", "filtered")}
    print(f"→ {path}\n  {len(files)}/{total} files, {loc} LOC, {c}")


if __name__ == "__main__":
    main()
