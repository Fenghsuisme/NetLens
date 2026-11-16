# -*- coding: utf-8 -*-
"""
llm_prompt.py — LLM 解釋/修復階段的共用 prompt 與後處理

ov_llm_explain.py（OpenVINO GenAI）與 vllm_explain.py（vLLM, OpenAI 相容 API）共用，
確保兩個後端拿到完全相同的 prompt，結果才能直接比較。
"""
import difflib
import re

SYSTEM = ("You are a senior application-security engineer inside an on-prem code-review gateway. "
          "Be precise and concise. Never invent APIs.")

# 內部安全編碼規範（依 CWE），作為 LLM 的修復依據
PLAYBOOK = {
    "CWE-89": "Use parameterized queries / prepared statements: put placeholders in the SQL text and "
              "pass user input as a separate parameters argument to execute(). Never concatenate input into SQL.",
    "CWE-78": "Do not build shell command strings from input. Call the program directly with an argument "
              "array and no shell (e.g. execFile / spawn with args array in Node.js, subprocess.run([...]) in Python), "
              "and validate the input against a strict allow-list regex before use.",
    "CWE-502": "Never deserialize untrusted bytes with native object deserialization. In Java, if ObjectInputStream "
               "must be kept, install an allow-list ObjectInputFilter (ois.setObjectInputFilter) that accepts only the "
               "expected application classes and rejects everything else; otherwise switch to a data-only format such as JSON.",
    "CWE-79": "Never write user input into HTML unescaped. Use the framework's auto-escaping template rendering, or escape "
              "explicitly (html.escape in Python, htmlspecialchars in PHP, textContent instead of innerHTML in JS).",
    "CWE-22": "Never join user input directly into a file path. Resolve the final path (os.path.realpath / path.resolve) and "
              "verify it is still inside the intended base directory; reject otherwise. Prefer an allow-list of file names.",
}

PROMPT = """A static analyzer (Semgrep) flagged this code and a CodeBERT classifier confirmed it.

File: {file} (line {line})
Category: {category}
Rule: {semgrep_rule}
Company secure-coding guideline for this CWE: {guideline}

```{language}
{code}```

Respond in exactly this format:
### Explanation
(2-3 sentences: what the vulnerability is, a concrete malicious input an attacker would send, and the impact)
### Fixed code
```{language}
(the COMPLETE corrected version of the code above, following the guideline, keeping the same function names and behaviour)
```
"""


def cwe_of(category):
    m = re.search(r"CWE-\d+", category)
    return m.group(0) if m else ""


def make_diff(f, text):
    m = re.search(r"### Fixed code\s*```[^\n]*\n(.*?)```", text, re.DOTALL)
    if not m:
        return None
    return "".join(difflib.unified_diff(
        f["code"].splitlines(keepends=True), (m.group(1).rstrip() + "\n").splitlines(keepends=True),
        fromfile="a/" + f["file"], tofile="b/" + f["file"]))
