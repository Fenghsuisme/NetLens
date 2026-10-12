# -*- coding: utf-8 -*-
"""
ov_export.py — CodeBERT（v7v8_safe, 17 類）→ OpenVINO IR

產出：
  models/codebert_ov_fp32/      FP32 IR（ov.convert_model 由 PyTorch 直接轉換）
  models/codebert_ov_int8/      INT8 全量化（NNCF PTQ，weights + activations，Transformer 模式）
  models/codebert_ov_int8wo/    INT8 權重量化（activations 維持浮點，作為備案）

校準集：security_training_dataset_v1.txt + dataset/hard_negatives（與測試集不重疊）

執行（reviewer/ 下）：
  python scripts/ov/ov_export.py [--skip-export]
"""
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ov_common as C

import nncf
import openvino as ov
import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

INT8WO_DIR = os.path.join(C.REVIEWER_ROOT, "models", "codebert_ov_int8wo")


def export_fp32():
    print(f"[1/3] 匯出 FP32 IR：{C.SRC_MODEL_DIR} → {C.OV_FP32_DIR}")
    tok = AutoTokenizer.from_pretrained(C.BASE_MODEL)
    pt = AutoModelForSequenceClassification.from_pretrained(
        C.SRC_MODEL_DIR, attn_implementation="eager").eval()

    class Wrapper(torch.nn.Module):
        """固定 (input_ids, attention_mask) → logits 介面，方便 TorchScript 追蹤"""
        def __init__(self, m):
            super().__init__()
            self.m = m

        def forward(self, input_ids, attention_mask):
            return self.m(input_ids=input_ids, attention_mask=attention_mask).logits

    enc = tok(["def f(x):\n    return x"], max_length=C.MAX_LEN,
              padding="max_length", truncation=True, return_tensors="pt")
    example = (enc["input_ids"], enc["attention_mask"])
    with torch.no_grad():
        model = ov.convert_model(Wrapper(pt), example_input=example,
                                 input=[("input_ids", [-1, C.MAX_LEN], ov.Type.i64),
                                        ("attention_mask", [-1, C.MAX_LEN], ov.Type.i64)])
    # 動態 batch、固定 512（與 scan.py 的 padding="max_length" 一致）
    for port, name in zip(model.inputs, ("input_ids", "attention_mask")):
        port.get_tensor().set_names({name})
    model.outputs[0].get_tensor().set_names({"logits"})
    os.makedirs(C.OV_FP32_DIR, exist_ok=True)
    # compress_to_fp16=False：保留真正的 FP32 權重作為比對基準
    ov.save_model(model, os.path.join(C.OV_FP32_DIR, "openvino_model.xml"),
                  compress_to_fp16=False)
    # scan.py 用的是 base tokenizer；一併存入，讓 IR 目錄可獨立使用
    tok.save_pretrained(C.OV_FP32_DIR)
    pt.config.save_pretrained(C.OV_FP32_DIR)


def copy_aux(dst):
    os.makedirs(dst, exist_ok=True)
    for f in os.listdir(C.OV_FP32_DIR):
        if not f.startswith("openvino_model"):
            shutil.copy(os.path.join(C.OV_FP32_DIR, f), dst)


def quantize_int8():
    print("[2/3] INT8 PTQ（NNCF）")
    core = ov.Core()
    model = core.read_model(os.path.join(C.OV_FP32_DIR, "openvino_model.xml"))
    input_names = [i.get_any_name() for i in model.inputs]
    tok = AutoTokenizer.from_pretrained(C.BASE_MODEL)
    codes = C.load_calibration_codes()
    print(f"  校準樣本：{len(codes)}，輸入：{input_names}")

    def transform(code):
        enc = C.tokenize(tok, [code])
        return {n: enc[n] for n in input_names}

    qmodel = nncf.quantize(
        model, nncf.Dataset(codes, transform),
        model_type=nncf.ModelType.TRANSFORMER,
        preset=nncf.QuantizationPreset.MIXED,
        subset_size=len(codes))
    copy_aux(C.OV_INT8_DIR)
    ov.save_model(qmodel, os.path.join(C.OV_INT8_DIR, "openvino_model.xml"))

    print("[3/3] INT8 weight-only（備案）")
    model = core.read_model(os.path.join(C.OV_FP32_DIR, "openvino_model.xml"))
    wmodel = nncf.compress_weights(model, mode=nncf.CompressWeightsMode.INT8_ASYM)
    copy_aux(INT8WO_DIR)
    ov.save_model(wmodel, os.path.join(INT8WO_DIR, "openvino_model.xml"))


if __name__ == "__main__":
    if "--skip-export" not in sys.argv:
        export_fp32()
    quantize_int8()
    for d in (C.OV_FP32_DIR, C.OV_INT8_DIR, INT8WO_DIR):
        print(f"  {os.path.basename(d):<22} {C.dir_size_mb(d):7.1f} MB")
    print(f"  {'pytorch safetensors':<22} {C.dir_size_mb(C.SRC_MODEL_DIR):7.1f} MB")
