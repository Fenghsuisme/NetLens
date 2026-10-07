"""
NetLens Reviewer — CWE-352 (CSRF) 專用生成器
==============================================
沿用「Ollama 快速版」的做法：
  - 本地兩模型混生（qwen + codellama）
  - 純漏洞碼、不要 JSON（直接吐 code，用 clean_code 剝 markdown）
  - 20 行下限、四語言（Python/Java 偏重）、可續傳
只生一個類別：CWE-352（CSRF，跨站請求偽造），目標 2500 筆。

CSRF 的漏洞長相（prompt 已針對性設計）：
  一個會改變伺服器狀態的端點（改密碼、轉帳、刪除、更新設定…），
  用 session/cookie 認證，但沒有驗證 CSRF token / 沒檢查 Origin/Referer，
  且允許簡單的表單 POST（甚至 GET）。

前置： ollama pull qwen2.5-coder:7b / ollama pull codellama:7b
       pip install ollama
執行： python generate_csrf.py
"""

import os
import re
import json
import uuid
import random
import hashlib
import html
from collections import defaultdict, Counter

import ollama

# ── 兩個本地模型 ──────────────────────────────────
MODELS = [
    {"name": "qwen2.5-coder:7b", "weight": 0.6},
    {"name": "codellama:7b",     "weight": 0.4},
]

TARGET = 2500                  # 目標筆數
LANGUAGE_WEIGHTS = {"python": 0.35, "java": 0.35, "javascript": 0.15, "php": 0.15}
MIN_LINES = 20
MAX_RETRY = 3

# ── 輸出（獨立檔，不跟現有混）──────────────────────
OUT_DIR = "data_csrf"
OUTPUT_FILE = os.path.join(OUT_DIR, "dataset_csrf.jsonl")
VIEW_FILE = os.path.join(OUT_DIR, "dataset_csrf_view.html")

# ── 這支只做 CWE-352 ─────────────────────────────
CWE = {"cwe": "CWE-352", "cat": "csrf", "owasp": "A01:2021", "sev": "HIGH",
       "langs": ["python", "java", "javascript", "php"]}

FRAMEWORKS = {
    "python":     ["Flask", "FastAPI", "Django"],
    "java":       ["Spring Boot", "Servlet/JSP", "Jakarta EE"],
    "javascript": ["Express", "Node.js http", "Koa"],
    "php":        ["Laravel", "plain PHP", "Symfony"],
}

# CSRF 專屬情境：都是「會改變狀態」的操作（CSRF 只對狀態變更有意義）
SCENARIOS = [
    "change account password", "update email address", "transfer money between accounts",
    "delete a user account", "update profile settings", "add a new shipping address",
    "change account role / permissions", "submit a new comment or post",
    "update billing information", "toggle two-factor authentication",
    "place an order / checkout", "unsubscribe from a service",
    "update notification preferences", "grant API access to a third party",
    "change privacy settings", "add a bank account",
]

SYSTEM = (
    "You are a security education dataset generator. You write realistic, readable "
    "code samples that intentionally contain a specified weakness, for training a "
    "vulnerability detector (defensive research). Output ONLY code."
)

# CSRF 專屬 prompt：講清楚「什麼樣的 code 才算 CSRF 漏洞」
PROMPT_TEMPLATE = """Write a <<LANG>> web endpoint using the <<FRAMEWORK>> framework that \
implements this state-changing feature: <<SCENARIO>>.

This sample must contain a CWE-352 (Cross-Site Request Forgery) vulnerability. To be a \
realistic CSRF vulnerability, the code MUST:
- be a POST (or GET) endpoint that CHANGES server-side state (writes to DB, updates a \
setting, performs an action).
- authenticate the user via SESSION or COOKIE only.
- have NO CSRF token validation, NO anti-CSRF middleware, and NO Origin/Referer check.
- accept a plain form submission so a forged cross-site request would succeed.

Rules:
- At least 20 lines (ideally 30-60). Write it like real production code: include imports, \
at least 2 helper functions, input parsing, some logging, and error handling.
- Do NOT add CSRF protection anywhere. Do NOT mention the vulnerability in comments.
- Output ONLY the raw code. No explanation, no markdown fences."""


def pick_model():
    return random.choices([m["name"] for m in MODELS],
                          weights=[m["weight"] for m in MODELS], k=1)[0]


def pick_language():
    return random.choices(list(LANGUAGE_WEIGHTS),
                          weights=list(LANGUAGE_WEIGHTS.values()), k=1)[0]


def call_ollama(model, system, user, temperature):
    resp = ollama.chat(
        model=model,
        messages=[{"role": "system", "content": system},
                  {"role": "user", "content": user}],
        options={"temperature": temperature, "num_predict": 4096},
    )
    return resp["message"]["content"]


def clean_code(text):
    text = (text or "").strip()
    if "```" in text:
        m = re.search(r"```[a-zA-Z]*\n(.*?)```", text, re.DOTALL)
        if m:
            text = m.group(1)
        else:
            text = "\n".join(ln for ln in text.split("\n") if not ln.strip().startswith("```"))
    return text.strip()


def line_count(code):
    return len([ln for ln in (code or "").splitlines() if ln.strip()])


def code_hash(code):
    return hashlib.md5(re.sub(r"\s+", "", code or "").encode("utf-8", "ignore")).hexdigest()


def load_state():
    hashes, rows, langs = set(), 0, Counter()
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
                langs[r.get("language")] += 1
    return hashes, rows, langs


def generate_one(model):
    lang = pick_language()
    framework = random.choice(FRAMEWORKS[lang])
    scenario = random.choice(SCENARIOS)
    temp = round(random.uniform(0.7, 1.0), 2)
    user = (PROMPT_TEMPLATE
            .replace("<<LANG>>", lang)
            .replace("<<FRAMEWORK>>", framework)
            .replace("<<SCENARIO>>", scenario))
    raw = call_ollama(model, SYSTEM, user, temp)
    code = clean_code(raw)
    if line_count(code) < MIN_LINES:
        raise ValueError(f"行數不足（{line_count(code)}）")
    return {
        "id": uuid.uuid4().hex[:12], "code": code,
        "language": lang, "cwe_primary": CWE["cwe"],
        "cwe_labels": [CWE["cwe"]], "category": CWE["cat"],
        "owasp": CWE["owasp"], "severity": CWE["sev"],
        "framework": framework, "scenario": scenario,
        "source_model": model, "is_vulnerable": True,
    }


def append_row(r):
    with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(r, ensure_ascii=False) + "\n")


def build_view():
    if not os.path.exists(OUTPUT_FILE):
        return
    rows = []
    with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except Exception:
                    pass
    by_lang = defaultdict(list)
    for r in rows:
        by_lang[r["language"]].append(r)
    parts = ["""<!DOCTYPE html><html lang="zh-Hant"><head><meta charset="utf-8">
<title>CWE-352 CSRF 檢視</title><style>
body{font-family:system-ui,"Microsoft JhengHei",sans-serif;margin:0;background:#0d1117;color:#c9d1d9}
h1{padding:16px 24px;margin:0;background:#161b22;border-bottom:1px solid #30363d}
.lang{padding:8px 24px;font-size:18px;font-weight:700;color:#58a6ff;cursor:pointer}
.item{margin:12px 24px;border:1px solid #30363d;border-radius:8px;overflow:hidden}
.meta{background:#161b22;padding:6px 12px;font-size:12px;color:#8b949e}
pre{margin:0;padding:12px;overflow-x:auto;font-family:Consolas,monospace;font-size:12px;
line-height:1.5;white-space:pre;background:#0d1117;border-top:1px solid #30363d}
</style></head><body><h1>CWE-352 CSRF 漏洞碼檢視</h1>"""]
    parts.append(f'<div style="padding:8px 24px;color:#8b949e">共 {len(rows)} 筆</div>')
    for lang in sorted(by_lang):
        items = by_lang[lang]
        parts.append(f'<details><summary class="lang">🗂 {lang}（{len(items)} 筆）</summary>')
        for r in items:
            parts.append('<div class="item">')
            parts.append(f'<div class="meta">{r["source_model"]} · {r["framework"]} · '
                         f'{r["scenario"]} · id {r["id"]}</div>')
            parts.append(f'<pre>{html.escape(r["code"])}</pre></div>')
        parts.append('</details>')
    parts.append("</body></html>")
    with open(VIEW_FILE, "w", encoding="utf-8") as f:
        f.write("".join(parts))
    print(f"→ 檢視檔已更新：{VIEW_FILE}（{len(rows)} 筆）")


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    hashes, existing, langs = load_state()
    print("啟用模型：", ", ".join(m["name"] for m in MODELS))
    print(f"目標：{TARGET} 筆 CWE-352（CSRF）純漏洞碼")
    print(f"現有：{existing} 筆　語言分布 {dict(langs)}")
    print(f"行數下限：{MIN_LINES}")
    print("=" * 56)

    new_count = 0
    try:
        while existing + new_count < TARGET:
            for _ in range(MAX_RETRY):
                model = pick_model()
                try:
                    row = generate_one(model)
                except Exception as e:
                    print(f"    ✗ {model} 失敗：{e}")
                    continue
                h = code_hash(row["code"])
                if h in hashes:
                    print("    ↻ 重複，重試")
                    continue
                hashes.add(h)
                append_row(row)
                new_count += 1
                if new_count % 20 == 0:
                    cur = existing + new_count
                    print(f"  進度 {cur}/{TARGET}（本次+{new_count}）｜{row['language']} via {model}")
                    build_view()
                break
    except KeyboardInterrupt:
        print("\n⚠ 已中斷。資料即時寫入，重跑會自動接續。")
        build_view()
        return

    build_view()
    print(f"\n✅ 完成！本次新增 {new_count} 筆，總計 {existing + new_count} 筆")
    print(f"   主檔：{OUTPUT_FILE}")
    print(f"   檢視：{VIEW_FILE}")


if __name__ == "__main__":
    main()