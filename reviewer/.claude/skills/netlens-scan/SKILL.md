---
name: netlens-scan
description: Scan source code for security vulnerabilities (SQL injection, command injection, code execution, XSS, path traversal, insecure deserialization, hardcoded secrets, weak crypto, prototype pollution, file upload, CSRF, SSRF, IDOR, broken access control, malicious packages) using the NetLens two-stage scanner (Semgrep rules + CodeBERT model). Use whenever the user asks to security-scan / audit / check code for vulnerabilities, AND after writing or modifying code to iteratively verify-and-fix it until it is clean.
---

# NetLens Security Scan

Two-stage vulnerability scanner: Semgrep locates suspicious functions (high recall),
CodeBERT classifies them (high precision), a fusion layer reconciles + de-dupes.

## IMPORTANT — use the maintained entry point
Always run **`scan.py`**. Do **NOT** use `core/mcp_api.py` or `core/analyzer.py` —
that is an old, divergent pipeline (model `codebert_v4`, separate semgrep/fusion code)
and does not include the current rules, model (`codebert_v7v8_safe`), or fixes.

## How to run
Run from the `reviewer/` directory:

- Full two-stage scan (needs the model at `models/codebert_v7v8_safe/` + a GPU/CPU):
  `python scan.py <file-or-dir>`
- Rules only, no model (fast; use when no model/GPU is available):
  `python scan.py <file-or-dir> --no-model`
- Machine-readable output (parse this when integrating):
  `python scan.py <file-or-dir> --json`
- Show the matched code snippet: add `--show-snippet`

Supported languages: Python, JavaScript, PHP, Java (`.py/.js/.php/.java`).
TypeScript/C#/C/C++ are currently disabled (rules not yet validated).

## How to read the report
- **✅ 確認漏洞 (confirmed)** — Semgrep and the model agree on the category. Highest confidence; report these first.
- **🔍 建議人工複查 (review)** — the two engines disagree, OR the category is inherently low-precision (CSRF / IDOR / 權限控制 / 資料外洩 / SSRF). Needs human judgement.
- **⚪ 已過濾 (filtered)** — the model judged the Semgrep hit as normal code (suppressed false positive). Not shown as a finding.
- **📋 僅規則偵測 (engine_only)** — memory-class CWEs not sent to the model.

Each finding gives: file, line, category, CWE, and model confidence.

## Iterative fix workflow (write → scan → fix → rescan)

When you have written or modified code for the user's goal, verify it with the loop
guard script — do **not** hand-roll the loop, and do **not** loop forever.

**Each round, run:**
```bash
# First round of a new goal (resets loop state):
python tools/netlens_loop_check.py --reset <changed-file> [more files...]
# Every subsequent round (no --reset):
python tools/netlens_loop_check.py <changed-file> [more files...]
```
Pass only the files you wrote/changed this task (not the whole repo).

**Act on the printed `verdict:` line — nothing else decides the loop:**
- `CLEAN` — no blocking (✅) vulnerabilities. Then run one safety-net scan of the
  affected module and finish:
  `python tools/netlens_loop_check.py --final <module-or-dir>`
  If that prints `FINAL_CLEAN`, you are done. If `FINAL_FINDINGS`, address them.
- `CONTINUE` — fix the listed **確認漏洞 (✅)**, then run the script again (no `--reset`).
- `STOP_NOPROGRESS` / `STOP_OSCILLATION` / `STOP_MAXITERS` — **STOP the loop and hand
  to the user.** This means your fixes did not reduce the findings (they may be false
  positives you cannot fix, or need human judgement). Report to the user: the remaining
  findings, and for each your assessment (real bug vs. suspected false positive) and why.

**Rules for the loop:**
- Only ✅-tier findings in non-low-precision categories block the loop. The 🔍 review
  list (CSRF/IDOR/權限/資料外洩/SSRF, or two-engine disagreements) is informational —
  judge each, but never let it drive the loop or trigger blind edits.
- **Never blindly edit code to silence a finding.** For each finding decide: real bug →
  fix it properly; false positive → do NOT change working code, note it. If NetLens keeps
  reporting something you have judged a false positive, that is exactly when the guard
  returns `STOP_*` — let it stop and defer to the user.
- The loop caps at 4 rounds regardless; it will not run indefinitely.

## Notes / caveats
- First run downloads the `microsoft/codebert-base` tokenizer from HuggingFace (needs network) unless cached.
- Real-world false-positive density is ~0.3–1 finding / KLOC; treat 🔍 review items as leads, not confirmed bugs.
- For large repos, `scan.py` caps at `MAX_FILES=500`; scan sub-directories separately if needed.
