# -*- coding: utf-8 -*-
"""
narration_align.py — 把旁白錄音切成各場景片段、修頭尾靜音、統一場景間停頓，再接成完整音軌

切點選在「句子之間的靜音」：先由 Whisper 時間戳估出場景邊界的大概位置，
再在附近 ±1.5 秒內找最長的一段靜音，切在靜音正中間，避免切到字。

用法（Windows）：
  python narration_align.py --out <輸出資料夾>
輸出：
  scene_1a_opening.wav … scene_6_closing.wav   各場景片段
  narration_full.wav                           完整音軌（場景間停頓 --gap 秒）
  cue_sheet.md                                 對時表：每段在完整音軌的起訖、對應畫面操作
"""
import argparse
import os
import wave

import numpy as np

SR = 16000

# 原始旁白錄音（未納入版控）：預設 demo_console/narration_src/，可用環境變數 NETLENS_NARRATION_SRC 指定
SRC_DIR = os.environ.get("NETLENS_NARRATION_SRC",
                         os.path.join(os.path.dirname(os.path.abspath(__file__)), "narration_src"))
# (來源檔, 場景代號, 檔名, 該段開頭大約秒數)；開頭秒數由 Whisper 時間戳推得，僅作為找靜音的起點
PART1 = os.path.join(SRC_DIR, "Text to Speech.wav")              # 場景 1–3
PART2 = os.path.join(SRC_DIR, "Finding a vulnerabil.wav")         # 場景 4–6
SCENES = [
    (PART1, "1a", "opening", 0.0, "按 `1` 後不用操作：三行字與標題卡的出現時間已對齊旁白（標題卡在 22.5 秒），1a+1b 可錄成一段連續畫面"),
    (PART1, "1b", "title", 22.4, "（接續上一段，標題卡停留）"),
    (PART1, "2", "funnel", 30.5, "按 `2`，旁白開始約 1 秒後按 `Enter`"),
    (PART1, "3", "race", 67.1, "按 `3`，**旁白一開始就按 `Enter`**（live 模式下兩條 OpenVINO 約 26 秒跑完，正好對上 \"When both OpenVINO engines finish\"）"),
    (PART2, "4", "llm", 0.0, "按 `4`（旁白模式 1 秒後自動跑 F1）"),
    (PART2, "5", "numbers", 29.6, "按 `5`（旁白模式自動翻卡：\"macro-F1\" → 準確率卡、\"Arc Pro B70\" → 延遲卡、\"ten thousand findings\" → 1 萬筆卡）"),
    (PART2, "6", "closing", 49.3, "按 `6`"),
]


# 重錄句替換：場景代號 → [(來源中舊句「之前」靜音的大約秒數, 舊句「之後」靜音的大約秒數, 新錄音檔)]
REPLACE = {
    "6": [(51.4, 57.2, os.path.join(SRC_DIR, "CodeBERT and the fix.wav"))],   # "one thirty-two" → "a single thirty-two"
}


# 刪除片段：場景代號 → [(來源中起點附近秒數, 終點附近秒數)]；起訖各自對齊到 ±0.6 s 內最長的靜音
CUT = {
    "4": [(18.07, 22.24)],   # 刪 "and a shell command built from user input becomes a safe argument list."（畫面只跑 F1）
}

# 插入停頓：場景代號 → [(來源中大約秒數, 停頓秒數)]；在該處附近 ±0.6 s 最長的靜音插入
PAUSE = {
    "5": [(32.24, 2.0)],   # "four times smaller" 之後：讓模型大小那張卡停留久一點
}


def read(path):
    with wave.open(path) as w:
        assert w.getframerate() == SR and w.getnchannels() == 1 and w.getsampwidth() == 2, "需 16 kHz mono 16-bit"
        return np.frombuffer(w.readframes(w.getnframes()), dtype=np.int16).astype(np.float32) / 32768


def write(path, x):
    y = np.clip(x * 32768, -32768, 32767).astype(np.int16)
    with wave.open(path, "wb") as w:
        w.setnchannels(1); w.setsampwidth(2); w.setframerate(SR); w.writeframes(y.tobytes())


def silences(x, frame=0.02, min_len=0.12):
    """回傳 [(start, end)] 靜音區間；門檻 = 語音能量中位數的 6%（約 -24 dB）"""
    n = int(frame * SR)
    rms = np.sqrt(np.mean(x[: len(x) // n * n].reshape(-1, n) ** 2, axis=1))
    thr = max(1e-4, np.median(rms[rms > np.percentile(rms, 30)]) * 0.06)
    quiet = rms < thr
    out, start = [], None
    for i, q in enumerate(np.append(quiet, False)):
        if q and start is None:
            start = i
        elif not q and start is not None:
            if (i - start) * frame >= min_len:
                out.append((start * frame, i * frame))
            start = None
    return out


def best_cut(sil, t, win=1.5):
    cands = [(e - s, (s + e) / 2) for s, e in sil if abs((s + e) / 2 - t) <= win]
    return max(cands)[1] if cands else t


def trim(x, pad=0.12):
    """修掉頭尾靜音，保留 pad 秒，並加 10 ms 淡入淡出避免爆音"""
    sil = silences(x)
    s = sil[0][1] if sil and sil[0][0] <= 0.02 else 0.0
    e = sil[-1][0] if sil and sil[-1][1] >= len(x) / SR - 0.05 else len(x) / SR
    y = x[max(0, int((s - pad) * SR)): min(len(x), int((e + pad) * SR))].copy()
    f = int(0.01 * SR)
    y[:f] *= np.linspace(0, 1, f); y[-f:] *= np.linspace(1, 0, f)
    return y


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "narration_out"))
    ap.add_argument("--gap", type=float, default=0.7, help="場景間停頓秒數")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)

    src = {p: read(p) for p in (PART1, PART2)}
    sil = {p: silences(x) for p, x in src.items()}
    clips = []
    for k, (p, sid, name, t0, cue) in enumerate(SCENES):
        start = 0.0 if t0 == 0 else best_cut(sil[p], t0)
        nxt = next((s for s in SCENES[k + 1:] if s[0] == p), None)
        end = best_cut(sil[p], nxt[3]) if nxt else len(src[p]) / SR
        seg = src[p][int(start * SR): int(end * SR)]
        for a0, b0, rep in REPLACE.get(sid, []):
            ca, cb = best_cut(sil[p], a0) - start, best_cut(sil[p], b0) - start
            r = trim(read(rep), pad=0.15)
            seg = np.concatenate([seg[: int(ca * SR)], r, seg[int(cb * SR):]])
        for c0, c1 in sorted(CUT.get(sid, []), reverse=True):
            a_, b_ = best_cut(sil[p], c0, win=0.6) - start, best_cut(sil[p], c1, win=0.6) - start
            seg = np.concatenate([seg[: int(a_ * SR)], seg[int(b_ * SR):]])
        for t0p, secs in sorted(PAUSE.get(sid, []), reverse=True):
            c = best_cut(sil[p], t0p, win=0.6) - start
            seg = np.concatenate([seg[: int(c * SR)], np.zeros(int(secs * SR), dtype=np.float32), seg[int(c * SR):]])
        clip = trim(seg)
        fn = f"scene_{sid}_{name}.wav"
        write(os.path.join(a.out, fn), clip)
        clips.append((sid, name, fn, clip, cue, start, end))

    gap = np.zeros(int(a.gap * SR), dtype=np.float32)
    full, t, rows = [], 0.0, []
    for i, (sid, name, fn, clip, cue, s, e) in enumerate(clips):
        if i:
            full.append(gap); t += a.gap
        d = len(clip) / SR
        rows.append(f"| {sid} | {name} | {int(t // 60)}:{t % 60:05.2f} | {int((t + d) // 60)}:{(t + d) % 60:05.2f} | {d:5.1f}s | {cue} |")
        full.append(clip); t += d
    write(os.path.join(a.out, "narration_full.wav"), np.concatenate(full))

    sheet = [f"# 旁白對時表（完整音軌 {int(t // 60)}:{t % 60:04.1f}，{'✅ ≤ 3:00' if t <= 180 else '❌ 超過 3:00'}）", "",
             f"場景間停頓 {a.gap}s。剪輯時把每段錄影長度設成 ≥ 該段旁白長度，旁白開始時間對齊下表即可。", "",
             "| 場景 | 名稱 | 開始 | 結束 | 長度 | 畫面操作 |", "|---|---|---|---|---|---|"] + rows
    open(os.path.join(a.out, "cue_sheet.md"), "w", encoding="utf-8").write("\n".join(sheet))
    print("\n".join(sheet))
    for sid, name, fn, clip, cue, s, e in clips:
        print(f"  {fn:<26} 來源 {s:6.2f}–{e:6.2f}s")


if __name__ == "__main__":
    main()
