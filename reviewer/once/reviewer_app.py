import gradio as gr
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from reviewer.code_analyzer import analyze_code, format_results, LANGUAGE_MAP

# ── 語言選項 ──────────────────────────────────────
LANGUAGE_OPTIONS = {
    "Python": "test.py",
    "JavaScript": "test.js",
    "TypeScript": "test.ts",
    "PHP": "test.php",
    "Java": "test.java",
    "C# (.NET)": "test.cs",
    "Go": "test.go",
}

# ── 範例程式碼 ────────────────────────────────────
EXAMPLES = {
    "Python": '''import os
import requests
from utils import helper

def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)

def run(cmd):
    os.system(cmd)

password = "hardcoded_secret_123"
''',
    "JavaScript": '''const express = require('express');
const eval_code = require('eval');
const axios = require('axios');

app.get('/run', (req, res) => {
    eval(req.query.code);
});

const password = "admin123";
''',
}

# ── 分析函數 ──────────────────────────────────────
def analyze(code, language_name):
    if not code or not code.strip():
        return "請輸入程式碼", "", ""

    filename = LANGUAGE_OPTIONS.get(language_name, "test.py")
    result = analyze_code(code, filename)

    # 風險等級
    verdict = result["verdict"]
    s = result["summary"]

    # 高優先級問題
    high_text = ""
    if result["high_priority"]:
        lines = ["## 高優先級：需要立即處理\n"]
        for i, item in enumerate(result["high_priority"], 1):
            lines.append(f"**[{i}] {item['type']} — 第 {item['line']} 行**")
            lines.append(f"- 問題：{item['message']}")
            if item.get("cwe"):
                lines.append(f"- CWE：{', '.join(item['cwe'])}")
            lines.append(f"- 建議：{item['suggestion']}")
            lines.append("")
        high_text = "\n".join(lines)
    else:
        high_text = "✅ 未發現高優先級問題"

    # 低優先級問題
    low_text = ""
    if result["low_priority"]:
        lines = ["## 低優先級：建議確認的外部依賴\n"]
        for i, item in enumerate(result["low_priority"], 1):
            lines.append(f"**[{i}]** 第 {item['line']} 行 — {item['message']}")
        low_text = "\n".join(lines)
    else:
        low_text = "✅ 無外部依賴警告"

    # 摘要
    summary = f"""## 分析摘要

**結果：** {verdict}

| 項目 | 數量 |
|------|------|
| 高優先級問題 | {s['high_priority_count']} 個 |
| 低優先級提醒 | {s['low_priority_count']} 個 |
| 安全的標準函式庫 | {s['safe_imports']} 個 |
| 未知第三方套件 | {s['unknown_imports']} 個 |
| 本地模組 | {s['local_imports']} 個 |
| 惡意套件 | {s['blacklisted_imports']} 個 |
"""

    return summary, high_text, low_text


# ── Gradio 介面 ───────────────────────────────────
with gr.Blocks(title="NetLens Reviewer｜AI 程式碼安全掃描") as demo:
    gr.Markdown("""
    # 🔍 NetLens Reviewer｜AI 程式碼安全掃描
    將 AI 生成的程式碼貼入下方，系統將自動掃描安全風險，包含惡意套件、注入漏洞、資料外洩等。
    """)

    with gr.Row():
        with gr.Column(scale=1):
            language_select = gr.Dropdown(
                choices=list(LANGUAGE_OPTIONS.keys()),
                value="Python",
                label="程式語言"
            )
            code_input = gr.Code(
                language="python",
                label="貼入 AI 生成的程式碼",
                lines=20
            )
            with gr.Row():
                analyze_btn = gr.Button("開始分析", variant="primary")
                example_btn = gr.Button("載入範例", variant="secondary")

        with gr.Column(scale=1):
            summary_output = gr.Markdown(label="分析摘要")
            high_output = gr.Markdown(label="高優先級問題")
            low_output = gr.Markdown(label="低優先級提醒")

    def load_example(lang):
        code = EXAMPLES.get(lang, EXAMPLES["Python"])
        return code

    def update_language(lang):
        lang_map = {
            "Python": "python",
            "JavaScript": "javascript",
            "TypeScript": "javascript",
            "PHP": "php",
            "Java": "java",
            "C# (.NET)": "csharp",
            "Go": "go",
        }
        return gr.Code(language=lang_map.get(lang, "python"))

    analyze_btn.click(
        fn=analyze,
        inputs=[code_input, language_select],
        outputs=[summary_output, high_output, low_output]
    )

    example_btn.click(
        fn=load_example,
        inputs=[language_select],
        outputs=[code_input]
    )

    language_select.change(
        fn=update_language,
        inputs=[language_select],
        outputs=[code_input]
    )

    gr.Markdown("""
    ---
    ### 說明
    - **高優先級**：直接影響安全性的問題，需要立即處理
    - **低優先級**：外部依賴警告，建議確認來源
    - **支援語言**：Python、JavaScript、TypeScript、PHP、Java、C#、Go
    """)

if __name__ == "__main__":
    demo.launch(share=False)