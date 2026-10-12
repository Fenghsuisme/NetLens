# -*- coding: utf-8 -*-
"""
build_captions.py — 由各場景旁白片段產生字幕與自動動作時間點（Whisper @ OpenVINO GenAI）

輸入：narration_out/scene_*.wav（narration_align.py 產生）、SCRIPT_narration.txt
輸出：
  narration/scene_<N>.wav          頁面播放用（場景 1 = 1a + 停頓 + 1b）
  data/narration.json              每場景：音檔、字幕 cues、自動動作（起跑、翻卡…）
  narration_out/narration_full.srt 完整音軌字幕（給剪輯軟體）

字幕文字一律取自逐字稿（不是 Whisper 的轉錄），Whisper 只用來決定時間。

用法（Windows）：python build_captions.py
"""
import difflib
import json
import os
import re
import shutil
import sys

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import narration_align as A
import proofread_narration as P

OUT = os.path.join(os.path.dirname(HERE), "narration_out")
MODEL = os.path.join(os.path.expanduser("~"), "ov_models", "whisper-small-int8-ov")
GAP = 0.7
CLIPS = ["1a_opening", "1b_title", "2_funnel", "3_race", "4_llm", "5_numbers", "6_closing"]
PAGE_SCENE = {"1a_opening": 1, "1b_title": 1, "2_funnel": 2, "3_race": 3, "4_llm": 4, "5_numbers": 5, "6_closing": 6}
# 自動動作：(場景, 錨點片語 或 秒數, 動作)；錨點片語在逐字稿中找，取該處的旁白時間
ACTIONS = [
    (2, 1.0, "start"),
    (3, 0.2, "start"),
    (4, 1.0, "start"),                      # 進場 1 秒後跑 F1（只跑一個）
    (5, "macro f1 is identical", "next"),   # 模型大小卡停留到這句（前面已插 2 秒停頓）
    (5, "on an intel arc pro b70", "next"),
    (5, "ten thousand findings", "next"),
]
MAX_CHARS = 78
# 字幕顯示用：拼寫數字 → 阿拉伯數字（對齊仍用原文）
DISPLAY = [("nine hundred fifty-three", "953"), ("just ten open-source", "just 10 open-source"),
           ("twenty-one thousand", "21,000"), ("Fifty-one", "51"), ("thirty-seven", "37"),
           ("ten projects", "10 projects"), ("six hundred forty thousand", "640,000"),
           ("eighty-four percent", "84%"), ("eight-bit", "8-bit"), ("thirty-two-bit", "32-bit"),
           ("one hundred fifty-two", "152"), ("fifteen tokens", "15 tokens"), ("four bits", "4 bits"),
           ("two thousand seven hundred forty-two", "2,742"), ("three to five milliseconds", "3–5 milliseconds"),
           ("ten thousand findings", "10,000 findings"), ("thirty-two-gigabyte", "32 GB"),
           ("four times", "4×"), ("zero bytes", "0 bytes")]


def display(text):
    for a, b in DISPLAY:
        text = text.replace(a, b)
    return text


def phrases(text):
    """逐字稿 → 字幕句：先依句號切，過長再於逗號／破折號處切"""
    out = []
    for sent in re.split(r"(?<=[.?!:;])\s+", text.strip()):
        parts = [sent]
        while any(len(p) > MAX_CHARS for p in parts):
            p = max(parts, key=len); i = parts.index(p)
            cuts = [m.end() for m in re.finditer(r",\s|\s—\s", p) if 20 <= m.end() <= len(p) - 20]   # 兩邊都 ≥ 20 字元
            if not cuts:
                break
            c = min(cuts, key=lambda k: abs(k - len(p) / 2))
            parts[i:i + 1] = [p[:c].strip(), p[c:].strip()]
        out += [p.strip(" —") for p in parts if p.strip(" —")]
    return out


def word_times(wav):
    audio = P.decode(wav)
    chunks = P.transcribe(audio, MODEL, "GPU.0")
    hyp, ht = [], []
    for s, e, txt in chunks:
        toks = P.norm_tokens(txt)
        for i, t in enumerate(toks):
            hyp.append(t); ht.append(s + (e - s) * i / max(1, len(toks)))
    return hyp, ht, len(audio) / 16000


def align(ref, hyp, ht, dur):
    """每個逐字稿字 → 時間（對不上的字以前後已知字線性內插）"""
    t = [None] * len(ref)
    for a, b, n in difflib.SequenceMatcher(a=ref, b=hyp, autojunk=False).get_matching_blocks():
        for k in range(n):
            t[a + k] = ht[b + k]
    known = [(i, v) for i, v in enumerate(t) if v is not None]
    if not known:
        return list(np.linspace(0, dur, len(ref)))
    xs, ys = zip(*known)
    return list(np.interp(range(len(ref)), xs, ys))


def main():
    scenes = [body for _, body in A_script()]
    os.makedirs(os.path.join(HERE, "narration"), exist_ok=True)
    page = {}
    srt, offset = [], 0.0
    clip_audio = {}
    for k, name in enumerate(CLIPS):
        wav = os.path.join(OUT, f"scene_{name}.wav")
        hyp, ht, dur = word_times(wav)
        ph = phrases(scenes[k])
        ref, owner = [], []
        for j, p in enumerate(ph):
            toks = P.norm_tokens(p)
            ref += toks; owner += [j] * len(toks)
        t = align(ref, hyp, ht, dur)
        cues = []
        for j, p in enumerate(ph):
            idx = [i for i, o in enumerate(owner) if o == j]
            cues.append({"s": round(max(0, t[idx[0]] - 0.15), 2), "e": None, "text": display(p)})
        for j in range(len(cues)):
            cues[j]["e"] = round(cues[j + 1]["s"] - 0.05, 2) if j + 1 < len(cues) else round(dur, 2)
        clip_audio[name] = (A.read(wav), dur, cues, ref, t)
        for c in cues:
            srt.append((offset + c["s"], offset + c["e"], c["text"]))
        offset += dur + GAP
        print(f"  {name:<12} {dur:5.1f}s  {len(cues)} 句字幕")

    # 頁面用：場景 1 = 1a + 停頓 + 1b
    for n in range(1, 7):
        parts = [c for c in CLIPS if PAGE_SCENE[c] == n]
        audio, cues, off, refs = [], [], 0.0, []
        for i, c in enumerate(parts):
            x, d, cc, ref, t = clip_audio[c]
            if i:
                audio.append(np.zeros(int(GAP * A.SR), dtype=np.float32)); off += GAP
            audio.append(x)
            cues += [{"s": round(q["s"] + off, 2), "e": round(q["e"] + off, 2), "text": q["text"]} for q in cc]
            refs.append((ref, [v + off for v in t]))
            off += d
        fn = f"narration/scene_{n}.wav"
        A.write(os.path.join(HERE, fn), np.concatenate(audio))
        acts = []
        for sc, anchor, do in ACTIONS:
            if sc != n:
                continue
            if isinstance(anchor, (int, float)):
                acts.append({"t": anchor, "do": do}); continue
            at = P.norm_tokens(anchor)
            for ref, t in refs:
                hit = next((i for i in range(len(ref) - len(at) + 1) if ref[i:i + len(at)] == at), None)
                if hit is not None:
                    acts.append({"t": round(float(t[hit]), 2), "do": do}); break
            else:
                print(f"  ⚠ 找不到錨點：{anchor}")
        page[str(n)] = {"audio": "/" + fn, "dur": round(off, 2), "cues": cues, "actions": acts}

    json.dump({"generated_from": "narration_out/scene_*.wav + SCRIPT_narration.txt", "scenes": page},
              open(os.path.join(HERE, "data", "narration.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)

    def ts(x):
        ms = int(round(x * 1000)); h, ms = divmod(ms, 3600000); m, ms = divmod(ms, 60000); s, ms = divmod(ms, 1000)
        return f"{h:02}:{m:02}:{s:02},{ms:03}"
    with open(os.path.join(OUT, "narration_full.srt"), "w", encoding="utf-8") as f:
        for i, (s, e, txt) in enumerate(srt, 1):
            f.write(f"{i}\n{ts(s)} --> {ts(e)}\n{txt}\n\n")
    for n, v in page.items():
        print(f"  scene {n}: {v['dur']:5.1f}s  actions {v['actions']}")
    print("→ data/narration.json, narration/scene_*.wav, narration_out/narration_full.srt")


def A_script():
    return P.load_script()


if __name__ == "__main__":
    main()
