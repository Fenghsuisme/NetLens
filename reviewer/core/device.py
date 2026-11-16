# -*- coding: utf-8 -*-
"""
device.py — PyTorch 推論裝置選擇

依序檢查 Intel XPU（Arc / Arc Pro，需 XPU 版 PyTorch）→ NVIDIA CUDA → CPU。
只檢查 cuda 的話，在 Intel GPU 機器上會默默退回 CPU。
多張 Intel GPU 時 torch.device("xpu") 即 xpu:0。
"""


def pick_device():
    import torch
    if hasattr(torch, "xpu") and torch.xpu.is_available():
        return torch.device("xpu")
    if torch.cuda.is_available():
        return torch.device("cuda")
    return torch.device("cpu")
