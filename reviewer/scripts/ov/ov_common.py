# -*- coding: utf-8 -*-
"""
ov_common.py — OpenVINO 部署管線共用工具

前處理必須與 scan.py 的 Scanner.classify 完全一致：
  剝除註解 → code[:2000] → tokenizer(max_length=512, padding="max_length")
否則量化校準與準確率比對都會失真。
"""
import glob
import os
import re
import sys

REVIEWER_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, REVIEWER_ROOT)

SRC_MODEL_DIR = os.path.join(REVIEWER_ROOT, "models", "codebert_v7v8_safe")
OV_FP32_DIR = os.path.join(REVIEWER_ROOT, "models", "codebert_ov_fp32")
OV_INT8_DIR = os.path.join(REVIEWER_ROOT, "models", "codebert_ov_int8")
BASE_MODEL = "microsoft/codebert-base"
MAX_LEN = 512
TEST_FILE = os.path.join(REVIEWER_ROOT, "test_code", "real_test", "testset_merged.txt")
# 校準集：與測試集不重疊（訓練側範例 + hard negatives），避免資料洩漏
CALIB_TXT = os.path.join(REVIEWER_ROOT, "test_code", "real_test", "security_training_dataset_v1.txt")
CALIB_HN_DIR = os.path.join(REVIEWER_ROOT, "dataset", "hard_negatives")


def strip_comments(code):
    """與 scan.py::_strip_comments 相同"""
    s = str(code)
    s = re.sub(r'"""(.*?)"""', "", s, flags=re.DOTALL)
    s = re.sub(r"'''(.*?)'''", "", s, flags=re.DOTALL)
    s = re.sub(r"/\*.*?\*/", "", s, flags=re.DOTALL)
    s = re.sub(r"//.*", "", s)
    s = re.sub(r"#.*", "", s)
    return re.sub(r"\n\s*\n+", "\n", s).strip()


def preprocess(snippet):
    """與 scan.py::Scanner.classify 相同的字串前處理"""
    code = strip_comments(snippet)
    if len(code) < 10:
        code = snippet
    return code[:2000]


def tokenize(tok, codes):
    return tok([preprocess(c) for c in codes], max_length=MAX_LEN,
               padding="max_length", truncation=True, return_tensors="np")


def load_testset(path=TEST_FILE):
    """沿用 eval/test_v7v8_full_real.py 的解析器（17 類標籤）"""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "t78", os.path.join(REVIEWER_ROOT, "eval", "test_v7v8_full_real.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.parse_test_file(path), mod.LABEL_NAMES


def load_calibration_codes():
    codes = []
    with open(CALIB_TXT, encoding="utf-8") as f:
        for block in f.read().split("---SPLIT---"):
            # 多數區塊沒有 ``` fence，程式碼直接接在 ###DESC 之後
            m = re.search(r"```[^\n]*\n(.*?)(?:```|\Z)", block, re.DOTALL)
            code = m.group(1) if m else "\n".join(
                l for l in block.splitlines() if not l.startswith("###"))
            if len(code.strip()) >= 30:
                codes.append(code.strip())
    for p in sorted(glob.glob(os.path.join(CALIB_HN_DIR, "**", "*.*"), recursive=True)):
        with open(p, encoding="utf-8", errors="ignore") as f:
            codes.append(f.read())
    return codes


def dir_size_mb(d, exts=(".bin", ".xml", ".safetensors")):
    total = sum(os.path.getsize(os.path.join(d, f)) for f in os.listdir(d)
                if f.endswith(exts))
    return total / 1024 / 1024
