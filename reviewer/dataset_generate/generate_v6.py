# -*- coding: utf-8 -*-
"""
NetLens Reviewer - 改良版漏洞碼生成器 v6（單一漏洞聚焦 + 禁止加防護）
=====================================================
針對先前資料集的問題所做的修正：
  1. 只用 qwen2.5-coder（實測污染率 2.6%，遠低於 granite 29% / starcoder 50%）
  2. temperature 0.5（原本 0.7-1.0 太高，導致偏離規格、混入其他漏洞）
  3. prompt 加強「單一漏洞聚焦 + 明確禁止其他漏洞類型」的排他規則
  4. 生成與驗證分離：這支只負責生成，驗證另用 clean_prose.py + semgrep_verify.py

輸出：CWE → 語言 兩層資料夾 + index.jsonl 總表
  vuln_dataset_v6/
    ├── CWE-89_sql_injection/python/  xxxx.py
    ├── CWE-79_xss/java/              xxxx.java
    └── index.jsonl

前置： pip install ollama ; ollama pull qwen2.5-coder:7b
執行： python generate_v6.py
"""

import os
import re
import json
import uuid
import random
import hashlib
from collections import defaultdict, Counter

import ollama

# ── 只用 qwen（實測污染最低、標籤最準、單模型最快）──────
MODELS = [
    {"name": "gpt-oss:20b", "weight": 1.0},
    # gpt-oss 是 OpenAI 開源的 21B MoE 模型（實際啟用 3.6B），
    # 16GB VRAM 在 Q4 下勉強可跑；若 OOM 可改回 qwen2.5-coder:7b
    # {"name": "qwen2.5-coder:7b", "weight": 1.0},
]

TOTAL_TARGET = 500             # ← 先試跑 500，滿意再調大
TEMPERATURE = 0.5             # ← 降低，讓輸出更貼規格
MIN_LINES = 20
MAX_RETRY = 3

LANGUAGE_WEIGHTS = {"python": 0.35, "java": 0.35, "javascript": 0.15, "php": 0.15}

OUT_DIR = "vuln_dataset_v6"    # 新資料夾，跟舊的分開
INDEX_FILE = os.path.join(OUT_DIR, "index.jsonl")
EXT = {"python": "py", "java": "java", "javascript": "js", "php": "php"}

# ── 漏洞類別（對齊 vuln_categories.json label 1-17）────────
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
     "langs": ["python", "java", "javascript", "php"], "enabled": False},
    {"label": 5,  "cat": "backdoor",                 "cwe": "CWE-912",  "owasp": "A07:2021", "sev": "HIGH",
     "desc": "a hidden authentication bypass deliberately built in — a magic password, secret header, or debug flag that skips the normal checks",
     "langs": ["python", "java", "javascript", "php"], "enabled": False},
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
     "langs": ["python", "java", "javascript", "php"], "enabled": False},
    {"label": 14, "cat": "ssrf",                     "cwe": "CWE-918",  "owasp": "A10:2021", "sev": "HIGH",
     "desc": "the server makes an outbound HTTP request to a URL taken from user input, with no allowlist or host validation",
     "langs": ["python", "java", "javascript", "php"], "enabled": False},
    {"label": 15, "cat": "idor",                     "cwe": "CWE-639",  "owasp": "A01:2021", "sev": "HIGH",
     "desc": "an endpoint reads/updates a resource by an ID from user input but never checks the resource belongs to the current user",
     "langs": ["python", "java", "javascript", "php"], "enabled": False},
    {"label": 16, "cat": "file_upload",              "cwe": "CWE-434",  "owasp": "A04:2021", "sev": "HIGH",
     "desc": "an upload handler that saves a user file without validating its type, extension or content",
     "langs": ["python", "java", "javascript", "php"], "enabled": False},
    {"label": 17, "cat": "broken_access_control",    "cwe": "CWE-284",  "owasp": "A01:2021", "sev": "HIGH",
     "desc": "an admin-only action that checks the user is logged in but does not check their role or permission",
     "langs": ["python", "java", "javascript", "php"], "enabled": False},
]

FRAMEWORKS = {
    "python":     ["Flask", "FastAPI", "Django"],
    "java":       ["Spring Boot", "Servlet/JSP", "Jakarta EE"],
    "javascript": ["Express", "Node.js http", "Koa"],
    "php":        ["Laravel", "plain PHP", "Symfony"],
}

# 通用後備情境（某類沒特別指定時用）
SCENARIOS = [
    "user login / authentication", "order lookup by ID", "product search",
    "admin user management", "config / settings update", "message inbox",
]

# 每個 CWE 專屬情境池：只配「天生會用到該漏洞」的情境，避免模型寫成別的漏洞。
# key 是 CWE 編號；生成時優先用這裡的，沒有才用通用 SCENARIOS。
CWE_SCENARIOS = {
    # SQL 注入：一定會下 DB query 的情境
    "CWE-89": ["order lookup by ID", "product search by keyword", "user login check",
               "filter reports by category", "find customer by email",
               "list posts by author", "search inventory by name"],
    # 命令注入：一定會呼叫系統指令的情境
    "CWE-78": ["ping a host for network diagnostics", "convert an uploaded image with a CLI tool",
               "compress files into an archive", "run a backup script",
               "check DNS for a domain", "generate a PDF via command-line tool"],
    # 程式碼執行：會動態算式/規則的情境
    "CWE-94": ["evaluate a user-defined formula", "run a custom filter expression",
               "apply a user-provided calculation rule", "dynamic templating of a report",
               "evaluate a math expression from user"],
    # 資料外洩：會回傳/記錄敏感資料的情境
    "CWE-200": ["return user profile details", "debug endpoint that dumps request info",
                "error handler that returns stack trace", "export account data",
                "admin view of user records"],
    # 後門：驗證/登入相關情境
    "CWE-912": ["user login", "admin authentication", "API key verification",
                "password check", "session validation"],
    # 弱加密：會雜湊/加密的情境
    "CWE-328": ["hash a user password on signup", "generate a password reset token",
                "encrypt stored user data", "create a session token",
                "sign a cookie value"],
    # 硬編碼密碼：會連外部服務/DB 的情境
    "CWE-798": ["connect to the database", "call a third-party payment API",
                "send email via SMTP", "authenticate to a cloud storage service",
                "sign JWT tokens"],
    # 路徑遊走：一定會用檔案路徑的情境
    "CWE-22": ["download a file by name", "read a report file from disk",
               "serve a user-requested document", "load a template by filename",
               "view a log file by name", "export data to a named file"],
    # 反序列化：會還原物件/session 的情境
    "CWE-502": ["load a saved session object", "restore user preferences from a blob",
                "import a serialized configuration", "process a cached object",
                "deserialize a message payload"],
    # XSS：會把輸入輸出到 HTML 的情境
    "CWE-79": ["display a search keyword on the results page", "show a user comment",
               "render a username in a greeting", "show a profile bio",
               "display an error message with user input"],
    # 原型污染：會合併/複製物件的情境（JS）
    "CWE-1321": ["merge user settings into config", "deep-clone a request body",
                 "update nested profile fields", "apply a JSON patch to an object"],
    # 惡意套件：一般功能，重點在 import
    "CWE-829": ["format terminal output with colors", "parse a date string",
                "make an HTTP request", "generate a slug from a title"],
    # CSRF：會改狀態的表單端點
    "CWE-352": ["change account password", "update email address", "transfer funds",
                "delete an account", "update profile settings", "add a shipping address"],
    # SSRF：會用使用者給的 URL 發請求的情境
    "CWE-918": ["fetch a remote image by URL", "import data from a user-supplied URL",
                "webhook that calls back a URL", "generate a link preview",
                "proxy a request to a user URL"],
    # IDOR：用 id 直接存取資源的情境
    "CWE-639": ["view an order by ID", "download an invoice by ID",
                "read a message by ID", "edit a document by ID",
                "access a user record by ID"],
    # 檔案上傳：一定是上傳的情境
    "CWE-434": ["upload a profile avatar", "upload a document attachment",
                "upload a CSV for import", "upload a product image",
                "attach a file to a support ticket"],
    # 權限控制：admin 專屬動作的情境
    "CWE-284": ["access the admin dashboard", "delete any user account",
                "change another user's role", "view all orders as admin",
                "modify system settings"],
}

SYSTEM = (
    "You are a security education dataset generator for training a vulnerability "
    "detector. Label accuracy is critical: each sample must contain EXACTLY ONE "
    "vulnerability class and nothing else. Output ONLY raw code — no explanations, "
    "no markdown fences, no leading sentences."
)

# 強化排他規則的 prompt
PROMPT = """Write a <<LANG>> code sample using the <<FRAMEWORK>> framework that \
implements this realistic feature: <<SCENARIO>>.

TARGET VULNERABILITY (the ONLY one allowed):
  <<CWE_ID>> — <<CAT>>: <<DESC>>

STRICT SINGLE-VULNERABILITY RULE:
- The code MUST contain this ONE vulnerability as its single, core, unambiguous problem.
- It MUST NOT contain ANY other vulnerability. In particular, unless it IS the target:
  do NOT hardcode credentials, do NOT use weak hashing (md5/sha1), do NOT build SQL by
  concatenation, do NOT use eval/exec, do NOT leave path traversal, do NOT skip auth.
- Everything OTHER than the target vulnerability must be written SECURELY and correctly
  (parameterized queries, escaped output, config-based secrets, permission checks, etc.),
  so the ONLY flaw a scanner could find is <<CWE_ID>>.

CRITICAL — THE TARGET VULNERABILITY MUST ACTUALLY BE PRESENT AND EXPLOITABLE:
- This is a DELIBERATE vulnerable sample. For the target <<CWE_ID>> ONLY, you must write
  the INSECURE version and add NO protection against it.
- Do NOT add any mitigation for the target. Specific banned "fixes" per target:
  * SQL injection (CWE-89): MUST use raw string concatenation / f-string. Do NOT use
    parameterized queries, prepared statements, bound params, or ORM.
  * Path traversal (CWE-22): use the user path directly. Do NOT check for '..', do NOT
    use realpath/abspath/canonical-path confinement, do NOT use basename().
  * Command injection (CWE-78): pass user input straight into the shell. Do NOT use
    escapeshellarg / escapeshellcmd (PHP), shlex.quote (Python), or an argument array —
    the user input MUST be concatenated into the command string.
  * Broken access control (CWE-284): the endpoint may check that the user is LOGGED IN,
    but MUST NOT check their role/permission. Do NOT call isAdmin(), hasRole(),
    @PreAuthorize, isGranted(), or any role comparison. A normal user must be able to
    perform the admin action.
  * CSRF (CWE-352): add NO token check, NO Origin/Referer check.
  * IDOR (CWE-639): fetch the object by the user-supplied id, but MUST NOT verify the
    object belongs to the current user.
  * Weak crypto (CWE-328): use md5/sha1/DES etc. Do NOT use bcrypt/argon2/password_hash.
- Do NOT "fix it halfway": no partial validation, no defensive if-checks. Comments may
  note the insecure line, but the code must remain genuinely vulnerable.
- INPUT MUST BE REAL: the malicious value MUST come from an actual request
  (request params / body / query / uploaded file), NOT be hard-coded as a literal like
  userInput = "../etc/passwd". A scanner must see untrusted input flowing to the sink.
- The vulnerability must be reachable from user-controlled input in the SAME function
  where it occurs (do not hide the sink several helper-calls away), so the flaw is real
  and traceable.

STYLE:
- At least 20 lines (ideally 30-50). Realistic production code: imports, input parsing,
  logging, error handling, and 1-2 small helper functions for UNRELATED concerns.
- Keep the vulnerable data-flow (user input reaching the sink) within a SINGLE function
  so the flaw is directly traceable; helper functions are only for unrelated setup.
- Put the vulnerability inside the normal business logic, not glaringly obvious.
- Do NOT rely on comments to convey the vulnerability; the code itself must be genuinely
  vulnerable whether or not any comment is present.

OUTPUT: raw code ONLY. No markdown, no ``` fences, no explanation before or after."""


# ── 工具 ─────────────────────────────────────────
def pick_model():
    return random.choices([m["name"] for m in MODELS],
                          weights=[m["weight"] for m in MODELS], k=1)[0]


def safe(s):
    return re.sub(r"[^A-Za-z0-9_.-]", "_", str(s))


def cwe_dirname(c):
    return f"{c['cwe']}_{c['cat']}"


# 強化版：不只剝 markdown 圍籬，也剝掉開頭的散文說明
CODE_START = {
    "python": re.compile(r"^\s*(import\s+\w|from\s+[\w.]+\s+import|def\s+\w|class\s+\w|@\w|#!|if\s+__name__|[A-Z_][A-Z0-9_]*\s*=|try:|with\s+)"),
    "java": re.compile(r"^\s*(package\s+[\w.]+;|import\s+[\w.]+;|public\s+|private\s+|protected\s+|abstract\s+|final\s+|@\w+|class\s+\w|interface\s+\w)"),
    "javascript": re.compile(r"^\s*(import\s+|export\s+|const\s+\w|let\s+\w|var\s+\w|function\s*\w*\s*\(|async\s+function|class\s+\w|require\s*\(|'use strict'|\"use strict\"|//|/\*|\(function)"),
    "php": re.compile(r"^\s*(<\?php|<\?=|namespace\s+|use\s+[\w\\]+;|//|/\*|#)"),
}


def clean_code(text, lang):
    text = (text or "").strip()
    # 1) markdown 圍籬優先
    m = re.search(r"```[a-zA-Z]*\s*\n(.*?)```", text, re.DOTALL)
    if m:
        text = m.group(1).strip()
    elif "```" in text:
        text = "\n".join(l for l in text.split("\n")
                         if not l.strip().startswith("```")).strip()
    # 2) 剝開頭散文：找第一行像程式碼的
    pat = CODE_START.get(lang)
    if pat:
        lines = text.split("\n")
        for i, ln in enumerate(lines):
            if ln.strip() and pat.match(ln):
                text = "\n".join(lines[i:])
                break
    return text.strip()


def line_count(code):
    return len([ln for ln in (code or "").splitlines() if ln.strip()])


def code_hash(code):
    return hashlib.md5(re.sub(r"\s+", "", code or "").encode("utf-8", "ignore")).hexdigest()


def call_ollama(model, user):
    resp = ollama.chat(
        model=model,
        messages=[{"role": "system", "content": SYSTEM},
                  {"role": "user", "content": user}],
        options={"temperature": TEMPERATURE, "num_predict": 4096},
    )
    return resp["message"]["content"]


# ── 續傳：掃資料夾算已生幾筆 ────────────────────────
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
            for fn in files:
                try:
                    with open(os.path.join(ld, fn), "r", encoding="utf-8") as f:
                        hashes.add(code_hash(f.read()))
                except Exception:
                    pass
    return counts, hashes


def generate_and_save(c, lang, model):
    framework = random.choice(FRAMEWORKS[lang])
    scenario = random.choice(CWE_SCENARIOS.get(c["cwe"], SCENARIOS))
    user = (PROMPT
            .replace("<<LANG>>", lang)
            .replace("<<FRAMEWORK>>", framework)
            .replace("<<SCENARIO>>", scenario)
            .replace("<<CWE_ID>>", c["cwe"])
            .replace("<<CAT>>", c["cat"].replace("_", " "))
            .replace("<<DESC>>", c["desc"]))
    raw = call_ollama(model, user)
    code = clean_code(raw, lang)
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

    rec = {"id": sid, "file": os.path.join(cwe_dirname(c), lang, fname).replace("\\", "/"),
           "code": code, "language": lang, "label": c["label"], "category": c["cat"],
           "cwe_primary": c["cwe"], "cwe_labels": [c["cwe"]], "owasp": c["owasp"],
           "severity": c["sev"], "framework": framework, "scenario": scenario,
           "source_model": model, "is_vulnerable": True}
    with open(INDEX_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return code


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    active = [c for c in CWES if c.get("enabled", True)]
    counts, hashes = scan_progress()

    # 平均分配 500 到各 (CWE, 語言) 組合
    combos = [(c, lang) for c in active for lang in c["langs"]]
    per_combo = max(1, TOTAL_TARGET // len(combos))

    todo = []
    for c, lang in combos:
        need = per_combo - counts.get((c["cwe"], lang), 0)
        if need > 0:
            todo.append([c, lang, need])

    print("啟用模型：", ", ".join(m["name"] for m in MODELS))
    print(f"temperature：{TEMPERATURE}　行數下限：{MIN_LINES}")
    print(f"目標：約 {per_combo * len(combos)} 筆（{len(combos)} 組 × {per_combo}）")
    print(f"現有：{sum(counts.values())} 筆")
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
                    if new_count % 10 == 0:
                        print(f"  進度 {sum(counts.values())}（本次+{new_count}）"
                              f"｜剛生 {c['cwe']}/{lang}")
                    break
            todo = [it for it in todo if it[2] > 0]
    except KeyboardInterrupt:
        print(f"\n⚠ 已中斷。本次新增 {new_count} 筆，檔案已即時寫入，重跑會自動接續。")
        return

    print(f"\n✅ 完成！本次新增 {new_count} 筆 → {OUT_DIR}/")
    print("下一步：先 clean_prose.py 清洗，再 semgrep_verify.py 驗證。")


if __name__ == "__main__":
    main()