# -*- coding: utf-8 -*-
"""
proofread_narration.py — 旁白音檔 vs 逐字稿 自動校對（Whisper @ OpenVINO GenAI，本機離線）

檢查：
  1. 漏唸 / 多唸 / 唸錯的字（與 SCRIPT_narration.txt 逐字對齊）
  2. 專有名詞是否被正確辨識（辨識錯通常代表發音不清楚）
  3. 每個場景的實際長度 vs 分鏡時間、總長是否 ≤ 3:00、語速、過長停頓
不能判斷：語氣、口音自然度（需人耳）。

用法（Windows）：
  python proofread_narration.py narration.mp3 [--device GPU.0] [--model %USERPROFILE%\\ov_models\\whisper-small-int8-ov]
輸出：螢幕 + 音檔旁的 <音檔名>_proofread.md
"""
import argparse
import difflib
import os
import re
import subprocess
import sys

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "SCRIPT_narration.txt")
KEY_TERMS = ["NetLens", "OpenVINO", "Semgrep", "CodeBERT", "PyTorch", "INT8", "Qwen", "macro-F1",
             "Arc Pro B70", "healthchecks", "ASUS", "on-premises"]
# 分鏡時間窗（秒），與 SCRIPT.md 一致
WINDOWS = [(0, 24), (24, 31), (31, 68), (68, 112), (112, 145), (145, 164), (164, 175)]
ONES = "zero one two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen " \
       "sixteen seventeen eighteen nineteen".split()
TENS = "_ _ twenty thirty forty fifty sixty seventy eighty ninety".split()


def num_words(n):
    """整數 → 英文字（與旁白唸法一致，不加 and）"""
    if n < 20:
        return ONES[n]
    if n < 100:
        return TENS[n // 10] + ("" if n % 10 == 0 else " " + ONES[n % 10])
    if n < 1000:
        return ONES[n // 100] + " hundred" + ("" if n % 100 == 0 else " " + num_words(n % 100))
    if n < 1_000_000:
        return num_words(n // 1000) + " thousand" + ("" if n % 1000 == 0 else " " + num_words(n % 1000))
    return str(n)


def norm_tokens(text):
    t = text.lower().replace("—", " ").replace("–", " ")
    t = re.sub(r"\[optional\]", " ", t)
    t = re.sub(r"\b1st\b", "first", t); t = re.sub(r"\b2nd\b", "second", t); t = re.sub(r"\b3rd\b", "third", t)
    t = re.sub(r"(\d),(\d{3})", r"\1\2", t)                    # 2,742 → 2742
    t = re.sub(r"(\d+)%", r"\1 percent", t)
    t = re.sub(r"\b(\d+)\b(?![.\d])", lambda m: num_words(int(m.group(1))), t)
    t = t.replace("-", " ").replace("'", "")
    t = re.sub(r"[^a-z0-9.\s]", " ", t)
    t = re.sub(r"(?<![0-9])\.|\.(?![0-9])", " ", t)
    return t.split()


def load_script():
    scenes = []
    for block in open(SCRIPT, encoding="utf-8").read().strip().split("\n\n"):
        head, body = block.split("\n", 1)
        scenes.append((head.strip("[]"), body.strip()))
    return scenes


def decode(path):
    import imageio_ffmpeg
    exe = imageio_ffmpeg.get_ffmpeg_exe()
    raw = subprocess.run([exe, "-v", "error", "-i", path, "-ac", "1", "-ar", "16000", "-f", "f32le", "-"],
                         capture_output=True, check=True).stdout
    return np.frombuffer(raw, dtype=np.float32)


def transcribe(audio, model, device):
    import openvino_genai as ov_genai
    pipe = ov_genai.WhisperPipeline(model, device)
    cfg = pipe.get_generation_config()
    cfg.language = "<|en|>"
    cfg.task = "transcribe"
    cfg.return_timestamps = True
    res = pipe.generate(audio.tolist(), cfg)
    return [(c.start_ts, c.end_ts, c.text.strip()) for c in res.chunks]


def fmt(t):
    return f"{int(t // 60)}:{t % 60:04.1f}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("audio")
    ap.add_argument("--device", default="GPU.0")
    ap.add_argument("--model", default=os.path.join(os.path.expanduser("~"), "ov_models", "whisper-small-int8-ov"))
    a = ap.parse_args()

    audio = decode(a.audio)
    dur = len(audio) / 16000
    print(f"音檔長度 {fmt(dur)}，轉錄中（Whisper @ {a.device}）…", flush=True)
    chunks = transcribe(audio, a.model, a.device)

    # 轉錄字 → 時間（chunk 內線性內插）
    hyp, hyp_t = [], []
    for s, e, txt in chunks:
        toks = norm_tokens(txt)
        for i, tok in enumerate(toks):
            hyp.append(tok)
            hyp_t.append(s + (e - s) * (i + .5) / max(1, len(toks)))
    scenes = load_script()
    ref, ref_scene, optional = [], [], set()
    for k, (_, body) in enumerate(scenes):
        is_opt = False
        for piece in re.split(r"(\[optional\])", body):
            if piece == "[optional]":
                is_opt = True
                continue
            for tok in norm_tokens(piece):
                if is_opt:
                    optional.add(len(ref))
                ref.append(tok)
                ref_scene.append(k)

    sm = difflib.SequenceMatcher(a=ref, b=hyp, autojunk=False)
    ref2hyp = {}
    issues = []
    for op, i1, i2, j1, j2 in sm.get_opcodes():
        if op == "equal":
            for d in range(i2 - i1):
                ref2hyp[i1 + d] = j1 + d
            continue
        said = " ".join(hyp[j1:j2]); want = " ".join(ref[i1:i2])
        if op == "replace" and said.replace(" ", "") == want.replace(" ", ""):
            continue                                            # 只差空格（open vino / openvino、it s / its）
        if op == "delete" and all(i in optional for i in range(i1, i2)):
            continue                                            # 略過的 [optional] 句
        t = hyp_t[min(j1, len(hyp_t) - 1)] if hyp_t else 0
        ctx = " ".join(ref[max(0, i1 - 4):i1])
        sc = scenes[ref_scene[min(i1, len(ref) - 1)]][0]
        kind = {"replace": "唸錯/聽錯", "delete": "漏唸", "insert": "多唸"}[op]
        issues.append((t, sc, kind, ctx, want, said))

    lines = [f"# 旁白校對報告：{os.path.basename(a.audio)}", ""]
    total_words = len(hyp)
    lines += [f"- 音檔總長：**{fmt(dur)}**（上限 3:00 → {'✅ OK' if dur <= 180 else '❌ 超時 ' + fmt(dur - 180)}）",
              f"- 語速：約 **{total_words / (dur / 60):.0f} 字/分**（建議 140–165）",
              f"- 逐字比對：{sum(1 for i in range(len(ref)) if i in ref2hyp)}/{len(ref)} 字一致，{len(issues)} 處差異", ""]

    lines += ["## 各場景長度", "", "| 場景 | 實際 | 分鏡 | 狀態 |", "|---|---|---|---|"]
    for k, (name, _) in enumerate(scenes):
        idx = [ref2hyp[i] for i in range(len(ref)) if ref_scene[i] == k and i in ref2hyp]
        if not idx:
            lines.append(f"| {name} | 未偵測到 | — | ❌ |")
            continue
        s, e = hyp_t[min(idx)], hyp_t[max(idx)]
        ws, we = WINDOWS[k] if k < len(WINDOWS) else (0, 0)
        ok = (e - s) <= (we - ws) + 2
        lines.append(f"| {name} | {fmt(s)}–{fmt(e)}（{e - s:.0f}s） | {fmt(ws)}–{fmt(we)}（{we - ws}s） | "
                     f"{'✅' if ok else '⚠️ 比畫面長，剪輯時延長該段或刪 [optional]'} |")

    lines += ["", "## 專有名詞辨識", "", "| 詞 | 結果 |", "|---|---|"]
    hyp_text = "".join(hyp)                                      # 去空格比對（health checks = healthchecks）
    for term in KEY_TERMS:
        want = "".join(norm_tokens(term))
        lines.append(f"| {term} | {'✅' if want in hyp_text else '⚠️ 未被正確辨識，可能發音不清（或 Whisper 拼法不同，請人工確認）'} |")

    lines += ["", "## 差異明細（依時間）", ""]
    if not issues:
        lines.append("沒有差異 🎉")
    else:
        lines += ["| 時間 | 場景 | 類型 | 前文 | 稿子 | 實際聽到 |", "|---|---|---|---|---|---|"]
        for t, sc, kind, ctx, want, said in sorted(issues):
            lines.append(f"| {fmt(t)} | {sc.split('｜')[0]} | {kind} | …{ctx} | {want or '—'} | {said or '—'} |")
        lines += ["", "> 註：「唸錯/聽錯」也可能是 Whisper 辨識誤差（例如專有名詞拼法）。請對照時間點回聽確認。"]

    gaps = [(chunks[i][1], chunks[i + 1][0]) for i in range(len(chunks) - 1) if chunks[i + 1][0] - chunks[i][1] > 1.5]
    lines += ["", "## 超過 1.5 秒的停頓", ""]
    lines += [f"- {fmt(s)} → {fmt(e)}（{e - s:.1f}s）" for s, e in gaps] or ["無"]
    lines += ["", "## Whisper 原始轉錄", ""] + [f"- `{fmt(s)}–{fmt(e)}` {t}" for s, e, t in chunks]

    report = "\n".join(lines)
    out = os.path.splitext(a.audio)[0] + "_proofread.md"
    open(out, "w", encoding="utf-8").write(report)
    print(report)
    print(f"\n→ {out}")


if __name__ == "__main__":
    sys.exit(main())
