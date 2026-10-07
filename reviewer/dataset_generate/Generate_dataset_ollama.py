"""
NetLens Reviewer — Ollama 本地多模型 CWE 漏洞程式碼生成器（免費版）
================================================================
與 API 版的差異：
  - 改用本地 Ollama，跑多個開源 coder 模型混生（免費，只花電）→ 維持多來源、避免風格 overfit
  - code 下限拉高到 30 行以上（prompt 要求 + 驗證雙重把關）
  - 主檔仍是 JSONL；另外自動產一份「語言/CWE 分類」的人可讀檢視檔（HTML）
  - 輸出到新資料夾 data_ollama/，跟先前 API 生的 dataset_v4.jsonl 分開

前置：
  1. 裝 Ollama（https://ollama.com），確認 `ollama --version` 有反應
  2. 先 pull 這些模型（下面 MODELS 列的都要 pull）：
       ollama pull qwen2.5-coder:7b
       ollama pull deepseek-coder:6.7b
       ollama pull codellama:7b
       ollama pull codegemma:7b
  3. pip install ollama
執行： python generate_dataset_ollama.py
"""

import os
import re
import json
import time
import uuid
import random
import hashlib
import html
from collections import defaultdict

import ollama

# ── 本地模型設定（同學的做法：多個舊/開源模型混生）──────
# 想加減模型 → 改這個 list（記得先 ollama pull）。
# weight 控制各模型抽中的比例。
MODELS = [
    {"name": "qwen2.5-coder:7b",  "weight": 0.35},  # 目前開源 coder 較強
    {"name": "deepseek-coder:6.7b", "weight": 0.30},
    {"name": "codellama:7b",      "weight": 0.20},  # 同學原本用的
    {"name": "codegemma:7b",      "weight": 0.15},
]

# ── 規模與語言權重 ────────────────────────────────
TOTAL_TARGET = 20000           # 總「列」數（漏洞 + 修復合計）
LANGUAGE_WEIGHTS = {"python": 0.35, "java": 0.35, "javascript": 0.15, "php": 0.15}

MIN_LINES = 30                 # code 行數下限（低於此視為失敗）
MAX_RETRY_PER_PAIR = 3
SAVE_EVERY = 20

# ── 輸出（跟 API 版分開，避免混入）──────────────────
OUT_DIR = "data_ollama"
OUTPUT_FILE = os.path.join(OUT_DIR, "dataset_ollama.jsonl")
VIEW_FILE = os.path.join(OUT_DIR, "dataset_view.html")   # 人可讀檢視檔

# ── CWE 目標（與 API 版一致，剔除記憶體安全類）──────
CWES = [
    {"cwe": "CWE-79",   "cat": "xss",                      "owasp": "A03:2021", "sev": "HIGH",   "langs": ["python", "java", "javascript", "php"]},
    {"cwe": "CWE-89",   "cat": "sql_injection",            "owasp": "A03:2021", "sev": "HIGH",   "langs": ["python", "java", "javascript", "php"]},
    {"cwe": "CWE-78",   "cat": "command_injection",        "owasp": "A03:2021", "sev": "HIGH",   "langs": ["python", "java", "javascript", "php"]},
    {"cwe": "CWE-94",   "cat": "code_injection",           "owasp": "A03:2021", "sev": "HIGH",   "langs": ["python", "java", "javascript", "php"]},
    {"cwe": "CWE-22",   "cat": "path_traversal",           "owasp": "A01:2021", "sev": "HIGH",   "langs": ["python", "java", "javascript", "php"]},
    {"cwe": "CWE-502",  "cat": "insecure_deserialization", "owasp": "A08:2021", "sev": "HIGH",   "langs": ["python", "java", "php"]},
    {"cwe": "CWE-918",  "cat": "ssrf",                     "owasp": "A10:2021", "sev": "HIGH",   "langs": ["python", "java", "javascript", "php"]},
    {"cwe": "CWE-434",  "cat": "unrestricted_file_upload", "owasp": "A04:2021", "sev": "HIGH",   "langs": ["python", "java", "javascript", "php"]},
    {"cwe": "CWE-862",  "cat": "missing_authorization",    "owasp": "A01:2021", "sev": "HIGH",   "langs": ["python", "java", "javascript", "php"]},
    {"cwe": "CWE-639",  "cat": "idor",                     "owasp": "A01:2021", "sev": "HIGH",   "langs": ["python", "java", "javascript", "php"]},
    {"cwe": "CWE-200",  "cat": "info_exposure",            "owasp": "A01:2021", "sev": "MEDIUM", "langs": ["python", "java", "javascript", "php"]},
    {"cwe": "CWE-1321", "cat": "prototype_pollution",      "owasp": "A08:2021", "sev": "MEDIUM", "langs": ["javascript"]},
]

FRAMEWORKS = {
    "python":     ["Flask", "FastAPI", "Django"],
    "java":       ["Spring Boot", "Servlet/JSP", "Jakarta EE"],
    "javascript": ["Express", "Node.js http", "Koa"],
    "php":        ["Laravel", "plain PHP", "Symfony"],
}

SCENARIOS = [
    "user login / authentication", "file download by filename", "profile avatar upload",
    "order lookup by ID", "product search", "report export to file",
    "admin user management", "password reset flow", "comment posting and display",
    "fetching data from an external URL", "config / settings update", "invoice generation",
    "message inbox", "image thumbnail processing", "import data from uploaded file",
    "log viewer", "sending notification email", "shopping cart update",
]

SYSTEM = (
    "You are a security education dataset generator for training a vulnerability "
    "detector. You produce realistic, readable code samples that intentionally "
    "contain a specified weakness, plus a corrected version, for defensive research. "
    "Output strict JSON only — no markdown, no commentary."
)

# 下限提高到 30 行以上，並強調可讀排版
PROMPT_TEMPLATE = """Produce a <<LANG>> code sample using the <<FRAMEWORK>> framework, \
implementing this realistic feature: <<SCENARIO>>.

Requirements:
1. The code MUST be AT LEAST 40 lines long (this is a hard requirement — a short \
snippet will be rejected). Complete, with all imports, well-formatted and human-readable: \
proper indentation, blank lines between functions, meaningful names.
2. To reach that length, make the file substantial and realistic. INCLUDE ALL of these:
   - all necessary imports at the top
   - at least 3 helper functions (not just one big function)
   - input parameter parsing and validation
   - several logging statements
   - try/except error handling around the main logic
   - inline comments explaining each step
   Do NOT write a minimal example — write it like real production code.
3. Deliberately contain ONE <<CWE_ID>> (<<CWE_NAME>>) vulnerability, embedded inside \
the normal business logic so it is not glaringly obvious.
4. Also produce a FIXED version that fixes ONLY <<CWE_ID>> and keeps everything else \
(structure, length, naming) as close as possible.
5. Report the 1-based line numbers of the vulnerable lines.

Return ONLY this JSON object (no markdown fences):
{"vulnerable_code": "<full code string>", "fixed_code": "<full code string>", \
"vuln_lines": [<int>, ...], "cwe": "<<CWE_ID>>"}"""


# ── Ollama 呼叫 ───────────────────────────────────
def pick_model():
    names = [m["name"] for m in MODELS]
    weights = [m["weight"] for m in MODELS]
    return random.choices(names, weights=weights, k=1)[0]


def call_ollama(model, system, user, temperature):
    resp = ollama.chat(
        model=model,
        messages=[{"role": "system", "content": system},
                  {"role": "user", "content": user}],
        options={"temperature": temperature, "num_predict": 4096},
    )
    return resp["message"]["content"]


# ── 解析與工具 ────────────────────────────────────
def extract_json(text):
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n", "", text)
        text = re.sub(r"\n```$", "", text).strip()
    try:
        return json.loads(text)
    except Exception:
        pass
    s, e = text.find("{"), text.rfind("}")
    if s != -1 and e != -1 and e > s:
        return json.loads(text[s:e + 1])
    raise ValueError("回應中找不到 JSON")


def code_hash(code):
    norm = re.sub(r"\s+", "", code or "")
    return hashlib.md5(norm.encode("utf-8", "ignore")).hexdigest()


def line_count(code):
    return len([ln for ln in (code or "").splitlines() if ln.strip()])


# ── 進度重建（讀現有 JSONL）────────────────────────
def load_state():
    counts = defaultdict(int)
    hashes = set()
    rows = 0
    if os.path.exists(OUTPUT_FILE):
        with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except Exception:
                    continue
                rows += 1
                hashes.add(code_hash(r.get("code", "")))
                if r.get("is_vulnerable"):
                    counts[(r["language"], r["cwe_primary"])] += 1
    return counts, hashes, rows


def compute_targets():
    pairs_total = TOTAL_TARGET // 2
    targets = {}
    for lang, w in LANGUAGE_WEIGHTS.items():
        lang_pairs = round(pairs_total * w)
        cwes = [c for c in CWES if lang in c["langs"]]
        per = max(1, lang_pairs // len(cwes))
        for c in cwes:
            targets[(lang, c["cwe"])] = per
    return targets


# ── 生成一「對」──────────────────────────────────
def generate_pair(lang, cwe_def, model):
    framework = random.choice(FRAMEWORKS[lang])
    scenario = random.choice(SCENARIOS)
    temp = round(random.uniform(0.7, 1.0), 2)
    user = (PROMPT_TEMPLATE
            .replace("<<LANG>>", lang)
            .replace("<<FRAMEWORK>>", framework)
            .replace("<<SCENARIO>>", scenario)
            .replace("<<CWE_ID>>", cwe_def["cwe"])
            .replace("<<CWE_NAME>>", cwe_def["cat"].replace("_", " ")))
    raw = call_ollama(model, SYSTEM, user, temp)
    data = extract_json(raw)

    vuln = (data.get("vulnerable_code") or "").strip()
    fixed = (data.get("fixed_code") or "").strip()
    # 改成用「行數」把關（>= MIN_LINES 才收）
    if line_count(vuln) < MIN_LINES or line_count(fixed) < MIN_LINES:
        raise ValueError(f"行數不足（vuln={line_count(vuln)}, fixed={line_count(fixed)}）")

    pair_id = uuid.uuid4().hex[:12]
    meta = {
        "language": lang, "cwe_primary": cwe_def["cwe"],
        "category": cwe_def["cat"], "owasp": cwe_def["owasp"],
        "severity": cwe_def["sev"], "framework": framework,
        "scenario": scenario, "source_model": model, "pair_id": pair_id,
    }
    vuln_row = {**meta, "id": uuid.uuid4().hex[:12], "code": vuln,
                "is_vulnerable": True, "cwe_labels": [cwe_def["cwe"]],
                "vuln_lines": data.get("vuln_lines", [])}
    fixed_row = {**meta, "id": uuid.uuid4().hex[:12], "code": fixed,
                 "is_vulnerable": False, "cwe_labels": [], "vuln_lines": []}
    return vuln_row, fixed_row


def append_rows(rows):
    with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


# ── 人可讀檢視檔（HTML，語言 → CWE 分類）──────────
def build_view():
    """讀整個 JSONL，產一份 HTML：依 語言 → CWE 分組，成對顯示漏洞/修復。"""
    if not os.path.exists(OUTPUT_FILE):
        print("尚無資料，略過檢視檔")
        return

    # 依 pair_id 把漏洞/修復配對
    pairs = defaultdict(dict)
    order = []
    with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except Exception:
                continue
            pid = r["pair_id"]
            if pid not in pairs:
                order.append(pid)
            pairs[pid]["vuln" if r["is_vulnerable"] else "fixed"] = r

    # 依 語言 → CWE 分組
    tree = defaultdict(lambda: defaultdict(list))
    for pid in order:
        p = pairs[pid]
        ref = p.get("vuln") or p.get("fixed")
        tree[ref["language"]][ref["cwe_primary"]].append(p)

    parts = ["""<!DOCTYPE html><html lang="zh-Hant"><head><meta charset="utf-8">
<title>NetLens 資料集檢視</title><style>
body{font-family:system-ui,"Microsoft JhengHei",sans-serif;margin:0;background:#0d1117;color:#c9d1d9}
h1{padding:16px 24px;margin:0;background:#161b22;position:sticky;top:0;border-bottom:1px solid #30363d}
.lang{padding:8px 24px;font-size:20px;font-weight:700;color:#58a6ff;margin-top:24px}
.cwe{padding:6px 24px;font-size:16px;font-weight:600;color:#f0883e}
.pair{margin:12px 24px;border:1px solid #30363d;border-radius:8px;overflow:hidden}
.meta{background:#161b22;padding:6px 12px;font-size:12px;color:#8b949e}
.cols{display:flex;gap:0}
.col{flex:1;min-width:0}
.col h4{margin:0;padding:6px 12px;font-size:13px}
.vuln h4{background:#3d1f21;color:#ff7b72}
.fixed h4{background:#1f3d24;color:#7ee787}
pre{margin:0;padding:12px;overflow-x:auto;font-family:Consolas,monospace;font-size:12px;
line-height:1.5;white-space:pre;background:#0d1117;border-top:1px solid #30363d}
.vline{background:#3d1f21;display:block}
summary{cursor:pointer;padding:8px 24px;color:#8b949e}
</style></head><body>
<h1>NetLens 漏洞資料集檢視（語言 → CWE 分類）</h1>"""]

    total = sum(len(v) for lang in tree.values() for v in lang.values())
    parts.append(f'<div style="padding:8px 24px;color:#8b949e">共 {total} 對</div>')

    for lang in sorted(tree):
        parts.append(f'<div class="lang">🗂 {lang}（{sum(len(x) for x in tree[lang].values())} 對）</div>')
        for cwe in sorted(tree[lang]):
            plist = tree[lang][cwe]
            cat = (plist[0].get("vuln") or plist[0].get("fixed"))["category"]
            parts.append(f'<details><summary class="cwe">{cwe} · {cat}（{len(plist)} 對）</summary>')
            for p in plist:
                v = p.get("vuln"); fx = p.get("fixed")
                ref = v or fx
                vlines = set(v["vuln_lines"]) if v else set()
                parts.append('<div class="pair">')
                parts.append(f'<div class="meta">{ref["source_model"]} · {ref["framework"]} · '
                             f'{ref["scenario"]} · pair {ref["pair_id"]} · vuln_lines={sorted(vlines)}</div>')
                parts.append('<div class="cols">')
                # 漏洞欄（標紅問題行）
                parts.append('<div class="col vuln"><h4>❌ Vulnerable</h4><pre>')
                if v:
                    for i, ln in enumerate(v["code"].splitlines(), 1):
                        esc = html.escape(ln) or " "
                        parts.append(f'<span class="vline">{esc}</span>' if i in vlines else esc)
                        parts.append("\n")
                parts.append('</pre></div>')
                # 修復欄
                parts.append('<div class="col fixed"><h4>✅ Fixed</h4><pre>')
                if fx:
                    parts.append(html.escape(fx["code"]))
                parts.append('</pre></div>')
                parts.append('</div></div>')
            parts.append('</details>')

    parts.append("</body></html>")
    with open(VIEW_FILE, "w", encoding="utf-8") as f:
        f.write("".join(parts))
    print(f"→ 檢視檔已更新：{VIEW_FILE}（{total} 對）")


# ── 主程式 ────────────────────────────────────────
def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    targets = compute_targets()
    counts, hashes, existing_rows = load_state()

    total_pairs_target = sum(targets.values())
    print("啟用本地模型：", ", ".join(m["name"] for m in MODELS))
    print(f"目標總列數：約 {total_pairs_target * 2}（{total_pairs_target} 對）")
    print(f"現有列數：{existing_rows}（已完成 {sum(counts.values())} 對）")
    print(f"code 行數下限：{MIN_LINES}")
    print("=" * 56)

    todo = []
    for key, tgt in targets.items():
        need = tgt - counts.get(key, 0)
        if need > 0:
            todo.append([key, need])

    new_count = 0
    try:
        while todo:
            for item in todo:
                (lang, cwe), need = item[0], item[1]
                if need <= 0:
                    continue
                cwe_def = next(c for c in CWES if c["cwe"] == cwe and lang in c["langs"])
                for _ in range(MAX_RETRY_PER_PAIR):
                    model = pick_model()
                    try:
                        vrow, frow = generate_pair(lang, cwe_def, model)
                    except Exception as e:
                        print(f"    ✗ {lang}/{cwe}/{model} 失敗：{e}")
                        continue
                    h = code_hash(vrow["code"])
                    if h in hashes:
                        print(f"    ↻ {lang}/{cwe} 重複，重試")
                        continue
                    hashes.add(h)
                    append_rows([vrow, frow])
                    item[1] -= 1
                    counts[(lang, cwe)] += 1
                    new_count += 1
                    if new_count % SAVE_EVERY == 0:
                        cur = sum(counts.values())
                        print(f"  進度 {cur}/{total_pairs_target} 對"
                              f"（本次新增 {new_count}）｜剛生 {lang}/{cwe} via {model}")
                        build_view()   # 每 20 對更新一次檢視檔
                    break
            todo = [it for it in todo if it[1] > 0]
    except KeyboardInterrupt:
        print("\n⚠ 已中斷。資料即時寫入，重跑會自動接續。")
        build_view()
        return

    build_view()
    print(f"\n✅ 完成！本次新增 {new_count} 對")
    print(f"   主檔：{OUTPUT_FILE}")
    print(f"   檢視：{VIEW_FILE}")


if __name__ == "__main__":
    main()