# NetLens Command Center — 比賽影片用展示介面

1920×1080 的單頁「指揮中心」，6 個場景，**每個畫面都是真實運算或真實數據**：
CodeBERT 在 Intel CPU / Intel GPU 上即時分類、本地 LLM 在 Intel GPU 上即時生成修復、
GPU 使用率來自 Windows 效能計數器（與工作管理員同源）。

## 1. 啟動（Windows 原生，Intel GPU 只在 Windows 可見）

需要的東西都放在使用者目錄底下：

| 位置 | 內容 |
|---|---|
| `%USERPROFILE%\ovwin\` | Python 環境（見下方建立方式） |
| `%USERPROFILE%\ov_models\` | `codebert_v7v8_safe/`（PyTorch＋tokenizer）、`codebert_ov_int8/`、`codebert_ov_fp32/`、`qwen2.5-coder-3b-int4-ov/`；校對工具另需 `whisper-small-int8-ov/` |
| `data/race_set.json` | 賽跑用測試集樣本（**未公開**），在有測試集的機器上執行 `python demo_console/build_race_set.py` 產生 |

模型來源：CodeBERT IR 由 `scripts/ov/ov_export.py` 產生；LLM 與 Whisper 從 Hugging Face 下載
`OpenVINO/Qwen2.5-Coder-3B-Instruct-int4-ov`、`OpenVINO/whisper-small-int8-ov`。

建立 Python 環境：
```powershell
python -m venv %USERPROFILE%\ovwin
%USERPROFILE%\ovwin\Scripts\pip install openvino==2026.4.1 openvino-genai numpy pywin32 psutil imageio-ffmpeg "transformers>=4.50,<4.56"
%USERPROFILE%\ovwin\Scripts\pip install torch --index-url https://download.pytorch.org/whl/cpu
```

**雙擊 `demo_console\start_demo.bat`**：啟動伺服器（約 30 秒載入 PyTorch／OpenVINO CPU／OpenVINO Intel GPU／LLM），
35 秒後自動以全螢幕開 Edge。看到 `▶ open http://127.0.0.1:8765/` 就是好了；關掉黑色視窗即結束。

## 2. 操作

**旁白模式（預設開）**：按 `1`–`6` 換場景時，自動播放該場景旁白（`narration/scene_N.wav`）、
底部顯示同步字幕，並在旁白對應時間自動執行動作——**錄影時只需要依序按 `1` → `6`，等每段旁白講完再按下一個**：

| 場景 | 自動動作 | 旁白長度 |
|---|---|---|
| 1 | 三行字、標題卡依旁白時間出現 | 30.0 s |
| 2 | 1 秒後漏斗開始跑 | 35.5 s |
| 3 | 立刻起跑（live 模式兩條 OpenVINO 約 26 秒完成，對上 "When both OpenVINO engines finish"） | 39.8 s |
| 4 | 進場 1 秒後跑 F1（只跑一個修復） | 24.6 s |
| 5 | 說到 "macro-F1" / "Arc Pro B70" / "ten thousand findings" 時自動翻卡（"four times smaller" 後有 2 秒停頓） | 21.2 s |
| 6 | — | 15.3 s |

| 鍵 | 功能 |
|---|---|
| `1`–`6` | 切換場景（並播放該場景旁白） |
| `N` | 開關旁白模式（關掉後回到手動操作） |
| `C` | 開關字幕 |
| `Enter` | 手動開始（漏斗／賽跑／LLM；開場跳到標題卡） |
| `Space` / `→` | 下一步（數據卡下一張） |
| `←` `→` | 場景 4 選擇 finding（F1–F5） |
| `R` | 重設目前場景（會重播旁白） |
| `H` | 隱藏右下角操作提示（**錄影前按一次**） |

OBS 要加「桌面音訊」來源才會錄到旁白聲音；若想在剪輯軟體自己配音／上字幕，用 `?narrate=0` 關掉，
並使用 `narration_out/narration_full.wav` 與 `narration_full.srt`。

URL 參數：`?race=live|replay`、`?lanes=pytorch-cpu,ov-gpu`、`?finding=F2`、`?scene=3`、`?narrate=0`、`?captions=0`

旁白重製流程（換錄音時）：
```powershell
cd reviewer\demo_console
# 原始錄音放在 narration_src\（未納入版控），或用 NETLENS_NARRATION_SRC 指定資料夾
python narration_align.py                       # 切段、修靜音、替換重錄句 → ..\narration_out\
python build_captions.py                                                       # 字幕、自動動作時間、SRT
python proofread_narration.py ..\narration_out\narration_full.wav   # 校對
```

## 3. 分鏡與英文旁白（總長 ≈ 2:55）

| 時間 | 場景 | 畫面操作 | 旁白（英文） |
|---|---|---|---|
| 0:00–0:18 | **1 開場** | 按 `1`，等告警洪水＋三行字出現，標題卡自動浮現 | "Every security scan floods developers with alerts — most of them false positives. And for most companies, sending source code to a cloud AI is simply not allowed." |
| 0:18–0:25 | 1 標題卡 | （自動） | "Meet NetLens: an on-prem AI security gateway, built on Intel hardware with OpenVINO." |
| 0:25–1:00 | **2 漏斗** | 按 `2` → `Enter` | "Stage one: Semgrep rules cast a wide net. Stage two: our fine-tuned CodeBERT model reviews every hit. Here it is on healthchecks, a real open-source project — nearly three quarters of the alerts are filtered out as noise, only real vulnerabilities reach the developer. Across ten open-source projects and 640,000 lines of code, alert density drops by 84 percent." |
| 1:00–1:45 | **3 賽跑** | 按 `3` → `Enter`（畫面旁可並排工作管理員 GPU 頁） | "Same model, same 152 functions — three engines. PyTorch on the CPU is our baseline. With OpenVINO and INT8 quantization, the same Intel CPU is almost four times faster. And on the Intel GPU, NetLens runs at full speed while the CPU stays free for Semgrep — look at the GPU load climbing in real time." |
| 1:45–2:25 | **4 LLM** | 按 `4`（預設 F1）→ `Enter`；需要時 `→` 換 F2 再 `Enter` | "For every confirmed vulnerability, a local code LLM — running on the very same Intel GPU — explains the attack and writes the patch. Around fifteen tokens per second on a laptop's integrated graphics. Zero bytes leave the machine." |
| 2:25–2:45 | **5 數據卡** | 按 `5`，每 4–5 秒按 `Space` | "INT8 makes the model four times smaller, accuracy is unchanged — macro-F1 0.7159 versus 0.7160 on 2,742 test functions. On an Intel Arc Pro B70, we project three to five milliseconds per function: ten thousand findings reviewed in under half a minute." |
| 2:45–2:55 | **6 架構** | 按 `6` | "Semgrep on the CPU, CodeBERT and the fix-writing LLM sharing one 32-gigabyte Arc Pro B70 — the whole pipeline in a single ASUS workstation. Your code never leaves. Your vulnerabilities do." |

## 4. 錄影建議（OBS）

- **畫布 1920×1080、60 fps**；來源用「視窗擷取」或「顯示器擷取」+ 瀏覽器 F11。
- 錄影前按 `H` 隱藏提示；每個場景**分開錄**，剪輯時再接（每段都可 `R` 重錄）。
- 場景 3 的硬體證據鏡頭：OBS 再加一個來源擷取「工作管理員 → 效能 → GPU 0（Intel Graphics）」，
  放在畫面角落或剪成分割畫面，與頁面下方的遙測圖互相印證。
- 場景 3、4 是**即時運算**：錄之前先各跑一次熱身；關掉其他吃 CPU 的程式（瀏覽器分頁、WSL 裡的工作）。
- 場景 3 若想要「理想條件」的乾淨數字，用 `?race=replay`（畫面會自動標示「each engine measured alone · replayed」）。

## 5. 數據誠實性（簡報被問到時）

| 畫面上的數字 | 來源 |
|---|---|
| 開場 953 alerts | `dataset/bench_real_projects_20260927_2322.md`：10 個專案送進模型的規則告警總數（217+131+605） |
| 漏斗 healthchecks | `data/funnel_healthchecks.json`：2026-10-12 用 `build_funnel_data.py`（`--backend openvino`）實際掃描 |
| 3.6 → 0.56 /KLOC、−84% | 團隊既有 10 專案基準（HANDOFF 一頁 context） |
| 賽跑 live | 當下即時運算；三引擎同時跑會互搶 CPU（實測 iGPU 14.7 s、OV CPU 25.8 s、PyTorch 66.9 s） |
| 賽跑 replay | `data/race_replay.json`：各引擎單獨跑（iGPU 13.6 s、OV CPU 13.0 s、PyTorch 49.9 s） |
| LLM tok/s、TTFT | OpenVINO GenAI `perf_metrics` 即時回報 |
| 數據卡 | `docs/hardware_openvino_report.md` 實測；**Arc Pro B70 數字為估算**，畫面以虛線＋PROJECTED 標示 |

LLM 範例品質：**F1（SQL 注入）、F2（指令注入）修復正確，建議影片使用**。
F3（反序列化）API 簽章錯誤、F4（XSS）用了 Flask 2.3 已移除的 `escape`、
F5（路徑遊走）`startsWith` 少了結尾分隔符——三者僅供展示「需人工複核」，不建議放進影片。

## 6. 檔案

| 路徑 | 用途 |
|---|---|
| `server.py` | 後端：賽跑 SSE、遙測 SSE、LLM 串流 SSE、靜態檔；`--record` 錄製 replay |
| `static/index.html` `style.css` `app.js` | 前端（6 場景） |
| `build_funnel_data.py` | 對真實專案跑完整管道（OpenVINO 後端）產生漏斗資料 |
| `data/funnel_healthchecks.json` | healthchecks 掃描結果（418 檔、21.6K LOC、51 告警） |
| `data/race_set.json` | 賽跑用 152 個測試集函式（分層抽樣，seed 42） |
| `data/race_replay.json` | 各引擎單獨量測的逐筆時間戳記 |
| `data/llm_findings.json` | LLM 場景的 5 個 finding |
