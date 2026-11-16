# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Always reply in Traditional Chinese (zh-TW).

## Overview

NetLens is an on-prem AI security scanner that runs on Intel hardware. Source code is scanned in three stages: Semgrep selects candidate hits (high recall), a fine-tuned CodeBERT classifier filters false positives (17 classes = 16 CWE categories + normal), and a local LLM (OpenVINO GenAI) explains the confirmed findings and suggests fixes. All the code lives in `reviewer/`. The code comments, docs and report output are written in Traditional Chinese.

## Running things

**Run every command from `reviewer/`.** The scripts find `rules/`, `models/`, `dataset/` and `test_code/` through relative paths.

```bash
source ~/work/.venv/bin/activate         # on the B70 machine; see "This machine" below
cd reviewer

python scan.py <file-or-dir>                      # full pipeline (PyTorch backend)
python scan.py <path> --no-model                  # Semgrep only; no model weights needed
python scan.py <path> --json [--out r.json]       # machine-readable output
python scan.py <path> --show-snippet
python scan.py <path> --no-official               # skip Semgrep registry rules (p/security-audit needs network)
python scan.py <path> --backend openvino [--ov-device GPU]   # OpenVINO INT8 CodeBERT on Intel CPU/GPU

python transport_layer.py <file>          # debug: show the Semgrep hits and the function snippets extracted for the model
```

There is no unit-test suite, linter or build step. The available checks are:

```bash
python scripts/check_env.py           # environment check
python scripts/semgrep_health.py      # all supplement rule files load and the scan test passes
python check_rules.py                 # rule syntax: ④ and ⑤ must both be 0 (non-zero = rules silently invalid)
python eval/eval_e2e.py --with-b -n 30   # end-to-end recall, sampled (~30 min); report → dataset/e2e_report.txt
python eval_clean.py [--analyze-only]    # residual false-positive rate on clean code (Semgrep cache: dataset/clean_fp_cache.json)
```

- After changing any rule, delete or move `dataset/clean_fp_cache.json` before you run `eval_clean.py`. Otherwise it reports stale numbers.
- `reviewer/TEST_STEPS.md` holds the full validation procedure and the baseline numbers.
- `scripts/run_all_tests.sh` refers to old script locations (for example `check_env.py` and `rule_experiment_v2.py` at the top level), so it does not run as written.

### What is gitignored (and so missing from a fresh clone)

- `reviewer/models/`: CodeBERT weights `models/codebert_v7v8_safe/` and the OpenVINO IRs `models/codebert_ov_{fp32,int8,int8wo}/`.
- `reviewer/dataset/` and `reviewer/test_code/`.

Without these, only `--no-model` scans and the rule health checks work. The eval and OpenVINO scripts need the test sets.

On first run, the `microsoft/codebert-base` tokenizer is downloaded from HuggingFace.

### OpenVINO (`scripts/ov/`)

- `ov_export.py` turns the PyTorch model into FP32 and INT8 IR. It uses NNCF PTQ and calibrates on `test_code/real_test/security_training_dataset_v1.txt` plus `dataset/hard_negatives`. The export traces with TorchScript and needs `transformers<4.56`; use a separate env for it.
- `ov_benchmark.py`, `ov_eval_accuracy.py` and `ov_eval_device.py` measure throughput and accuracy. `ov_common.py` holds the shared paths and the test-set loader.
- `llm_demo/ov_llm_explain.py` is the local LLM explain/fix stage. It needs `openvino-genai`.
- Results are written to `docs/ov_results/`. The write-up is in `docs/hardware_openvino_report.md`.

## Architecture

The pipeline is `scan.py` → `transport_layer.py` → CodeBERT → verdict.

1. **`transport_layer.process_all`** runs Semgrep with the full rule set from `rule_paths(language)`: `rules/<lang>.yml`, every `rules/supplement_*.yml` listed in `SUPPLEMENT_RULES`, and `p/security-audit`. It also runs `typosquat_detector.py` to catch malicious package imports. It then routes each hit by CWE:
   - `to_codebert`: CWEs in `MODEL_ELIGIBLE_CWES`. For these it extracts the **whole enclosing function**, using indentation for Python and braces for other languages, and prepends up to 25 import lines.
   - `semgrep_only`: B-class CWEs. These are reported without going through the model.
   - `skipped`: orphan CWEs (20/400/770/476).

   `rule_paths` is the single source of truth for rules. Scanning and evaluation must load the same set. Adding a new supplement file means adding it to `SUPPLEMENT_RULES`.
2. **`Scanner.classify`** in `scan.py` runs on the device from `core/device.pick_device()` (XPU → CUDA → CPU). Use this helper in any new PyTorch code: a bare `torch.cuda.is_available()` check silently falls back to CPU on Intel GPUs. Older scripts (`archive/`, `once/`, `training/`, old `eval/test_v*` versions, `tools/`) still check CUDA only. It strips comments (`STRIP_COMMENTS=True`, matching the training preprocessing), truncates to 2000 chars/512 tokens, and returns label, name and confidence. Both backends (PyTorch, `core/ov_backend.OVCodeBERT`) return softmax probabilities through the same interface.
3. **`Scanner.scan_code`** assigns each verdict:
   - `confirmed`: the model label equals the Semgrep category mapped into the model's label system.
   - `filtered`: the model says label 0 (normal).
   - `incoherent`: the soft gate. The rule category can be judged from a single function, but the model answered with a category that needs cross-file context (a label outside `FRAGMENT_JUDGEABLE_LABELS`).
   - `low_confidence`: below `DISPUTE_CONF_MIN`.
   - `disputed`: everything else.

   The report also includes the transport layer's `engine_only` and `skipped` lists. Categories in `LOW_TRUST_CATEGORIES` (CSRF, IDOR, access control, …) are shown as review-only.

### Two label systems

- The config/test-set taxonomy has **22 classes**. It is defined in `config/vuln_categories.json` and `config/cwe_catalog.json` and loaded by `core/config_loader.py`.
- The model uses **17 classes**. They come from `training/merge_17class.py`.

Labels 0–14 are the same in both. From 15 on they differ: IDOR and access control collapse into model 16, and file upload becomes model 15. Memory-safety classes 18–21 have no model label. Always convert with `label_map.config_to_model` / `model_to_config` before comparing a Semgrep or test-set label with a model output.

### Legacy and non-production code

- `core/analyzer.py`, `core/mcp_api.py` and `core/fusion.py` are an **old, divergent pipeline**: model `codebert_v4`, with its own Semgrep and fusion logic. `scan.py` does not use them. Do not extend them, and do not use them for scanning.
- `archive/`, `once/`, `tmp_*.py` and most of `tools/` are one-off experiment and analysis scripts.
- `rules_baseline/` and `rules_snapshot_r5/` are frozen rule snapshots kept for comparison. The live rules are in `rules/`.
- `eval/test_v*_real.py` are per-model-version eval scripts. `test_v7v8_full_real.py` matches the current model and is imported by `scripts/ov/ov_common.py`.
- Training data generation is in `dataset_generate/`. Training is in `training/` (`train_model.py`).

### Known train/inference caveat

`obfuscate.py`, which de-semanticizes function names, is not in the repo, so `HAS_OBFUSCATE=False`. The current model (`v7v8_safe`) was trained without obfuscation (`OBFUSCATE_FUNCS=False`). Any preprocessing change in `classify` must also be made in training, or the eval numbers drift.

## Scope notes

- Supported scan languages are Python, JavaScript, PHP and Java. The TypeScript, C#, C and C++ rule files exist but are disabled (not validated).
- `scan.py` caps a run at `MAX_FILES=500` and skips `node_modules`, `venv`, etc.
- The `demo_console/` (Command Center UI for the demo video) runs on Windows only (`start_demo.bat`, pywin32). It does not run on the Linux B70 machine.
- `reviewer/.claude/skills/netlens-scan/` defines a scan skill with a bounded write→scan→fix loop (`tools/netlens_loop_check.py`, max 4 rounds). It is picked up only when Claude Code is started from `reviewer/`, not from the repo root.
- The GitHub repo is **public**. `.gitignore` deliberately excludes some private notes and `test_code/`, which contains fake test credentials. Never commit model weights, datasets or private notes.

## This machine (Intel Arc Pro B70 ×2, Ubuntu 26.04)

- **Python env:** `~/work/.venv`. It has XPU PyTorch (`pip install torch --index-url https://download.pytorch.org/whl/xpu`), `requirements.txt` and OpenVINO. Do **not** install into `~/idcenv`; that is the Jupyter environment. `ov_export.py` needs `transformers<4.56`, so run it from a separate venv.
- **Two GPUs:** PyTorch sees `xpu:0` and `xpu:1`, and `pick_device()` uses `xpu:0`. OpenVINO names them `GPU.0` and `GPU.1`. `--ov-device GPU` uses only the first one; pass `GPU.1` to target the second card.
- **Model weights and datasets** are not on this machine after a clone. Copy `reviewer/models/`, `reviewer/dataset/` and `reviewer/test_code/` over from the original machine, for example by JupyterLab upload or a private Hugging Face repo. Never push them to GitHub. Until then, only `--no-model` works.
- **LLM stage alternative:** besides `ov_llm_explain.py` (OpenVINO GenAI), a larger model can be served with vLLM across both cards (for example Qwen3-14B with tensor parallel 2) and called through its OpenAI-compatible API. This is not implemented yet.
