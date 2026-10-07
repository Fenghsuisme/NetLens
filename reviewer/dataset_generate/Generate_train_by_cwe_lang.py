"""
NetLens Reviewer — Ollama 訓練集生成器（直接分類輸出版）
=========================================================
特點：
  - 生成當下就直接寫成「CWE → 語言」兩層資料夾的原始碼檔（不用事後整理）
  - 額外維護一份 index.jsonl 總表（訓練用）
  - 多本地模型混生，MODELS 可自由增減（見下方清單與 VRAM 註記）
  - 類別對齊 vuln_categories.json（17 個漏洞類，可個別開關）
  - 續傳：直接掃資料夾算各 (CWE, 語言) 已生幾筆，只補差額
  - 純漏洞碼、不要 JSON（直接吐 code）、行數下限可調

輸出結構：
  vuln_dataset/
    ├── CWE-89_sql_injection/
    │     ├── python/     xxxx.py
    │     ├── java/       xxxx.java
    │     ├── javascript/ xxxx.js
    │     └── php/        xxxx.php
    ├── CWE-79_xss/
    └── index.jsonl

前置： pip install ollama
      先 pull 你要用的模型（見 MODELS）
執行： python generate_train_by_cwe_lang.py
"""

import os
import re
import json
import uuid
import random
import hashlib
from collections import defaultdict, Counter

import ollama

# ── 模型清單（想加減就改這裡，記得先 ollama pull）──────────────
# 挑選原則：盡量選「不同團隊訓練」的，風格差異才大、才能打散腔調。
# 大小為約略值（Q4 量化），16GB VRAM 一次載一個都跑得動。
#
#   qwen2.5-coder:7b          阿里        ~4.7GB   目前開源 coder 較強
#   deepseek-coder-v2:16b-lite DeepSeek   ~8.9GB   MoE，比 6.7b 強不少
#   starcoder2:7b             BigCode     ~4.0GB   訓練來源很不同，風格差異最大
#   granite-code:8b           IBM         ~4.6GB   企業風格
#   yi-coder:9b               01.AI       ~5.0GB
#   opencoder:8b              開源社群     ~4.7GB
#   codellama:7b              Meta        ~3.8GB   同學原本用的
#   codegemma:7b              Google      ~5.0GB
#   magicoder:7b              OSS-Instruct ~4.0GB
#   codestral:22b             Mistral     ~13GB    品質好但吃滿 VRAM、慢
#
# 註：模型清單會更新，最新可用型號請看 ollama.com/library
MODELS = [
    {"name": "qwen2.5-coder:7b", "weight": 1}
    # {"name": "granite-code:8b",  "weight": 0.5},   # IBM 路線
]

PER_CWE_PER_LANG = 300         # 每個 (CWE, 語言) 目標筆數
MIN_LINES = 20                 # 行數下限
MAX_RETRY = 3

OUT_DIR = "vuln_dataset"
INDEX_FILE = os.path.join(OUT_DIR, "index.jsonl")

EXT = {"python": "py", "java": "java", "javascript": "js", "php": "php"}

# ── 漏洞類別（對齊 vuln_categories.json 的 label 1-17）──────────
# enabled: False 可暫時關掉某類
CWES = [
    {"label": 1,  "cat": "command_injection",        "cwe": "CWE-78",   "owasp": "A03:2021", "sev": "HIGH",
     "desc": "user input passed into an OS shell command (os.system / subprocess shell=True / Runtime.exec / shell_exec) without sanitization",
     "langs": ["python", "java", "javascript", "php"], "enabled": True},
    {"label": 2,  "cat": "sql_injection",            "cwe": "CWE-89",   "owasp": "A03:2021", "sev": "HIGH",
     "desc": "a SQL query built by concatenating or formatting user input directly into the query string instead of using parameters",
     "langs": ["python", "java", "javascript", "php"], "enabled": True},
    {"label": 3,  "cat": "code_execution",           "cwe": "CWE-94",   "owasp": "A03:2021", "sev": "HIGH",
     "desc": "user input evaluated as program code via eval() / exec() / new Function() / ScriptEngine",
     "langs": ["python", "java", "javascript", "php"], "enabled": True},
    {"label": 4,  "cat": "data_exfiltration",        "cwe": "CWE-200",  "owasp": "A01:2021", "sev": "MEDIUM",
     "desc": "sensitive data (credentials, tokens, personal data, full stack traces) exposed in a response, log, or sent to an external endpoint",
     "langs": ["python", "java", "javascript", "php"], "enabled": True},
    {"label": 5,  "cat": "backdoor",                 "cwe": "CWE-912",  "owasp": "A07:2021", "sev": "HIGH",
     "desc": "a hidden authentication bypass deliberately built in — a magic password, secret header, or debug flag that skips the normal checks",
     "langs": ["python", "java", "javascript", "php"], "enabled": True},
    {"label": 6,  "cat": "weak_cryptography",        "cwe": "CWE-328",  "owasp": "A02:2021", "sev": "MEDIUM",
     "desc": "a broken cryptographic choice — MD5/SHA1 for passwords, DES/ECB, base64 as 'encryption', or a non-cryptographic RNG for tokens",
     "langs": ["python", "java", "javascript", "php"], "enabled": True},
    {"label": 7,  "cat": "hardcoded_secret",         "cwe": "CWE-798",  "owasp": "A07:2021", "sev": "HIGH",
     "desc": "credentials or secrets (DB password, API key, AWS keys, JWT secret) written literally in the source code",
     "langs": ["python", "java", "javascript", "php"], "enabled": True},
    {"label": 8,  "cat": "path_traversal",           "cwe": "CWE-22",   "owasp": "A01:2021", "sev": "HIGH",
     "desc": "a file path built from user input and used without confining it to a base directory, so '../' can escape to arbitrary files",
     "langs": ["python", "java", "javascript", "php"], "enabled": True},
    {"label": 9,  "cat": "insecure_deserialization", "cwe": "CWE-502",  "owasp": "A08:2021", "sev": "HIGH",
     "desc": "untrusted user data deserialized with an unsafe mechanism (pickle.loads / ObjectInputStream / PHP unserialize / yaml.load)",
     "langs": ["python", "java", "php"], "enabled": True},
    {"label": 10, "cat": "xss",                      "cwe": "CWE-79",   "owasp": "A03:2021", "sev": "HIGH",
     "desc": "user input written into an HTML response or the DOM without escaping (string-built HTML, innerHTML, document.write)",
     "langs": ["python", "java", "javascript", "php"], "enabled": True},
    {"label": 11, "cat": "prototype_pollution",      "cwe": "CWE-1321", "owasp": "A08:2021", "sev": "MEDIUM",
     "desc": "a recursive merge / deep clone that copies user-controlled keys without blocking __proto__ / constructor / prototype",
     "langs": ["javascript"], "enabled": True},
    {"label": 12, "cat": "malicious_import",         "cwe": "CWE-829",  "owasp": "A08:2021", "sev": "HIGH",
     "desc": "importing a suspicious or typosquatted third-party package (e.g. 'colourama' instead of 'colorama') and using it in the app",
     "langs": ["python", "java", "javascript", "php"], "enabled": True},
    {"label": 13, "cat": "csrf",                     "cwe": "CWE-352",  "owasp": "A01:2021", "sev": "HIGH",
     "desc": "a state-changing endpoint authenticated only by session/cookie, with no CSRF token validation and no Origin/Referer check",
     "langs": ["python", "java", "javascript", "php"], "enabled": True},
    {"label": 14, "cat": "ssrf",                     "cwe": "CWE-918",  "owasp": "A10:2021", "sev": "HIGH",
     "desc": "the server makes an outbound HTTP request to a URL taken from user input, with no allowlist or host validation",
     "langs": ["python", "java", "javascript", "php"], "enabled": True},
    {"label": 15, "cat": "idor",                     "cwe": "CWE-639",  "owasp": "A01:2021", "sev": "HIGH",
     "desc": "an endpoint reads/updates a resource by an ID from user input but never checks the resource belongs to the current user",
     "langs": ["python", "java", "javascript", "php"], "enabled": True},
    {"label": 16, "cat": "file_upload",              "cwe": "CWE-434",  "owasp": "A04:2021", "sev": "HIGH",
     "desc": "an upload handler that saves a user file without validating its type, extension or content",
     "langs": ["python", "java", "javascript", "php"], "enabled": True},
    {"label": 17, "cat": "broken_access_control",    "cwe": "CWE-284",  "owasp": "A01:2021", "sev": "HIGH",
     "desc": "an admin-only action that checks the user is logged in but does not check their role or permission",
     "langs": ["python", "java", "javascript", "php"], "enabled": True},
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
    "You are a security education dataset generator. You write realistic, readable "
    "code samples that intentionally contain a specified weakness, for training a "
    "vulnerability detector (defensive research). Output ONLY code."
)

PROMPT = """Write a <<LANG>> code sample using the <<FRAMEWORK>> framework that \
implements this realistic feature: <<SCENARIO>>.

The code must deliberately contain ONE <<CWE_ID>> (<<CAT>>) vulnerability:
<<DESC>>

Rules:
- At least 20 lines (ideally 30-60). Write it like real production code, not a snippet.
- Include all imports, at least 2 helper functions, input parsing, some logging and
  error handling so the file is long enough and readable.
- Hide the vulnerability inside the normal business logic — not glaringly obvious.
- Do NOT add any other vulnerability type, and do NOT mention the vulnerability in comments.
- Output ONLY the raw code. No explanation, no markdown fences."""


# ── 工具 ──────────────────────────────────────────
def pick_model():
    return random.choices([m["name"] for m in MODELS],
                          weights=[m["weight"] for m in MODELS], k=1)[0]


def safe(s):
    return re.sub(r"[^A-Za-z0-9_.-]", "_", str(s))


def cwe_dirname(c):
    """資料夾名：CWE-89_sql_injection（編號 + 類別名，好認）"""
    return f"{c['cwe']}_{c['cat']}"


def clean_code(text):
    text = (text or "").strip()
    if "```" in text:
        m = re.search(r"```[a-zA-Z]*\n(.*?)```", text, re.DOTALL)
        if m:
            text = m.group(1)
        else:
            text = "\n".join(ln for ln in text.split("\n")
                             if not ln.strip().startswith("```"))
    return text.strip()


def line_count(code):
    return len([ln for ln in (code or "").splitlines() if ln.strip()])


def code_hash(code):
    return hashlib.md5(re.sub(r"\s+", "", code or "").encode("utf-8", "ignore")).hexdigest()


def call_ollama(model, user, temperature):
    resp = ollama.chat(
        model=model,
        messages=[{"role": "system", "content": SYSTEM},
                  {"role": "user", "content": user}],
        options={"temperature": temperature, "num_predict": 4096},
    )
    return resp["message"]["content"]


# ── 續傳：直接掃資料夾算已生幾筆 ────────────────────
def scan_progress():
    counts = Counter()
    hashes = set()
    if not os.path.isdir(OUT_DIR):
        return counts, hashes
    for c in CWES:
        d = os.path.join(OUT_DIR, cwe_dirname(c))
        if not os.path.isdir(d):
            continue
        for lang in c["langs"]:
            ld = os.path.join(d, lang)
            if not os.path.isdir(ld):
                continue
            files = [f for f in os.listdir(ld) if os.path.isfile(os.path.join(ld, f))]
            counts[(c["cwe"], lang)] = len(files)
            # 讀回內容做去重（檔案多時稍慢，但只在啟動時做一次）
            for fn in files:
                try:
                    with open(os.path.join(ld, fn), "r", encoding="utf-8") as f:
                        hashes.add(code_hash(f.read()))
                except Exception:
                    pass
    return counts, hashes


# ── 生成一筆並直接寫成分類檔 ────────────────────────
def generate_and_save(c, lang, model):
    framework = random.choice(FRAMEWORKS[lang])
    scenario = random.choice(SCENARIOS)
    temp = round(random.uniform(0.7, 1.0), 2)
    user = (PROMPT
            .replace("<<LANG>>", lang)
            .replace("<<FRAMEWORK>>", framework)
            .replace("<<SCENARIO>>", scenario)
            .replace("<<CWE_ID>>", c["cwe"])
            .replace("<<CAT>>", c["cat"].replace("_", " "))
            .replace("<<DESC>>", c["desc"]))
    raw = call_ollama(model, user, temp)
    code = clean_code(raw)
    if line_count(code) < MIN_LINES:
        raise ValueError(f"行數不足（{line_count(code)}）")

    sid = uuid.uuid4().hex[:12]
    ext = EXT.get(lang, "txt")
    model_tag = safe(model.split(":")[0])
    d = os.path.join(OUT_DIR, cwe_dirname(c), lang)
    os.makedirs(d, exist_ok=True)
    fname = f"{sid}_{model_tag}.{ext}"
    with open(os.path.join(d, fname), "w", encoding="utf-8") as f:
        f.write(code)

    rec = {
        "id": sid, "file": os.path.join(cwe_dirname(c), lang, fname).replace("\\", "/"),
        "code": code, "language": lang,
        "label": c["label"], "category": c["cat"],
        "cwe_primary": c["cwe"], "cwe_labels": [c["cwe"]],
        "owasp": c["owasp"], "severity": c["sev"],
        "framework": framework, "scenario": scenario,
        "source_model": model, "is_vulnerable": True,
    }
    with open(INDEX_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return code


# ── 主程式 ────────────────────────────────────────
def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    active = [c for c in CWES if c.get("enabled", True)]
    counts, hashes = scan_progress()

    # 待辦：每個 (CWE, 語言) 還缺幾筆
    todo = []
    total_target = 0
    for c in active:
        for lang in c["langs"]:
            total_target += PER_CWE_PER_LANG
            need = PER_CWE_PER_LANG - counts.get((c["cwe"], lang), 0)
            if need > 0:
                todo.append([c, lang, need])

    print("啟用模型：", ", ".join(m["name"] for m in MODELS))
    print(f"類別數：{len(active)}　每 (CWE,語言) 目標：{PER_CWE_PER_LANG}")
    print(f"總目標：{total_target} 筆　現有：{sum(counts.values())} 筆")
    print(f"輸出：{OUT_DIR}/<CWE>_<類別>/<語言>/")
    print("=" * 60)

    new_count = 0
    try:
        while todo:
            for item in todo:
                c, lang, need = item[0], item[1], item[2]
                if need <= 0:
                    continue
                for _ in range(MAX_RETRY):
                    model = pick_model()
                    try:
                        code = generate_and_save(c, lang, model)
                    except Exception as e:
                        print(f"    ✗ {c['cwe']}/{lang}/{model} 失敗：{e}")
                        continue
                    h = code_hash(code)
                    if h in hashes:
                        print(f"    ↻ {c['cwe']}/{lang} 重複")
                        continue
                    hashes.add(h)
                    item[2] -= 1
                    counts[(c["cwe"], lang)] += 1
                    new_count += 1
                    if new_count % 20 == 0:
                        print(f"  進度 {sum(counts.values())}/{total_target}"
                              f"（本次+{new_count}）｜剛生 {c['cwe']}/{lang} via {model}")
                    break
            todo = [it for it in todo if it[2] > 0]
    except KeyboardInterrupt:
        print(f"\n⚠ 已中斷。本次新增 {new_count} 筆，檔案已即時寫入，重跑會自動接續。")
        report(counts)
        return

    print(f"\n✅ 完成！本次新增 {new_count} 筆")
    report(counts)


def report(counts):
    print("\n各 CWE × 語言 分布：")
    by_cwe = defaultdict(dict)
    for (cwe, lang), n in counts.items():
        by_cwe[cwe][lang] = n
    for cwe in sorted(by_cwe):
        tot = sum(by_cwe[cwe].values())
        detail = "  ".join(f"{l}:{n}" for l, n in sorted(by_cwe[cwe].items()))
        print(f"  {cwe:10s} 共 {tot:5d}   {detail}")
    print(f"\n總表：{INDEX_FILE}")


if __name__ == "__main__":
    main()