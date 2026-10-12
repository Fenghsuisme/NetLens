# -*- coding: utf-8 -*-
"""
ov_backend.py — CodeBERT 的 OpenVINO 推論後端（scan.py --backend openvino）

載入 scripts/ov/ov_export.py 產出的 IR（預設 INT8），介面與 PyTorch 路徑對齊：
輸入 numpy 的 input_ids / attention_mask，輸出 softmax 機率。
目標裝置：Intel CPU / Intel GPU（iGPU、Arc Pro）。
"""
import os

import numpy as np


class OVCodeBERT:
    def __init__(self, model_dir, device="CPU"):
        import openvino as ov
        xml = os.path.join(model_dir, "openvino_model.xml")
        if not os.path.exists(xml):
            raise RuntimeError(
                f"找不到 OpenVINO IR：{xml}\n"
                f"　請先執行 python scripts/ov/ov_export.py")
        core = ov.Core()
        self.compiled = core.compile_model(xml, device, {"PERFORMANCE_HINT": "LATENCY"})
        self.request = self.compiled.create_infer_request()
        self.device = core.get_property(device, "FULL_DEVICE_NAME")
        self.path = model_dir

    def predict_proba(self, enc):
        logits = self.request.infer({"input_ids": enc["input_ids"],
                                     "attention_mask": enc["attention_mask"]})[self.compiled.output(0)]
        e = np.exp(logits - logits.max(axis=1, keepdims=True))
        return e / e.sum(axis=1, keepdims=True)
