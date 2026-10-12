# NetLens 比賽影片逐字稿（英文旁白，目標 2:45–2:55）

- 語速以每分鐘約 150 字估算，全稿約 425 字（約 2:50）。超時就刪掉 **[可刪]** 標記的句子，每句約省 4–6 秒。
- 場景 3 請用 **live 模式**錄（預設），因為旁白提到「GPU 使用率即時上升」。
  live 模式下 PyTorch 要跑 67 秒，**兩條 OpenVINO 跑完後（約 26 秒）就可以剪掉**，旁白也是照這個寫的。
- 畫面上的每個數字都有來源，見 `README.md` 第 5 節。

---

## 場景 1｜開場：告警洪水（0:00–0:24）
**畫面**：按 `1`，紅色告警往下掉，數字跳到 953，三行字依序出現。

> Every time a company scans its code for security flaws, developers get buried in alerts — nine hundred fifty-three across just ten open-source projects. Most are false alarms, so people stop reading, and real vulnerabilities slip through. AI could help — but for banks, hospitals and manufacturers, uploading private source code to a cloud AI is not an option.

中文意思：企業每次掃描程式碼，開發者就被告警淹沒，光 10 個開源專案就有 953 個。大部分是誤報，所以大家乾脆不看，真正的漏洞就漏掉了。AI 可以幫忙，但對銀行、醫院、製造業來說，把私有原始碼上傳到雲端 AI 不可行。

## 場景 1｜標題卡（0:24–0:31）
**畫面**：標題卡浮現（等它自己出現，或按 `Enter`）。

> This is NetLens: an AI security gateway that runs entirely on-premises — on Intel hardware, powered by OpenVINO.

中文意思：這是 NetLens，一個完全在企業內部運行的 AI 資安閘道，跑在 Intel 硬體上，由 OpenVINO 驅動。

## 場景 2｜兩階段掃描漏斗（0:31–1:08）
**畫面**：按 `2` → `Enter`，卡片一張張經過中間的 CodeBERT，分到右邊三個區塊。

> NetLens works in two stages. First, Semgrep rules sweep the entire codebase and flag anything that might be dangerous — fast and thorough, but noisy. Then every flagged function goes to our fine-tuned CodeBERT model, which actually reads the code and decides: real vulnerability, or false alarm? Here it is on healthchecks, a real open-source project of twenty-one thousand lines. Fifty-one alerts go in; thirty-seven are thrown out as noise. **[可刪]** Across ten projects and six hundred forty thousand lines, the alerts a developer has to read drop by eighty-four percent.

中文意思：NetLens 分兩個階段。第一階段用 Semgrep 規則掃過整個程式庫，把所有可能危險的地方標出來，快又全面，但雜訊多。第二階段把每個被標出的函式交給我們微調過的 CodeBERT，由它真正讀懂程式碼，判斷是真漏洞還是誤報。這是在真實開源專案 healthchecks（兩萬一千行）上的結果：51 個告警進去，37 個被當成雜訊濾掉。在 10 個專案、64 萬行程式碼上，開發者要看的告警減少了 84%。

## 場景 3｜硬體賽跑（1:08–1:52）
**畫面**：按 `3` → `Enter`。兩條 OpenVINO 跑完、PyTorch 還在跑時就可以剪掉。
（可並排工作管理員的 GPU 頁面）

> To run on-premises, NetLens must be fast on hardware companies already own. So we converted our model to OpenVINO and quantized it to INT8 — eight-bit integers instead of thirty-two-bit floats. Same model, same one hundred fifty-two functions, three engines: PyTorch on the CPU, OpenVINO INT8 on the same Intel CPU, and OpenVINO on the Intel integrated GPU — watch its load climb in real time. When both OpenVINO engines finish, PyTorch is still less than halfway. **[可刪]** In our benchmarks, that's nearly four times the throughput on the same chip — and the GPU keeps the CPU free for Semgrep.

中文意思：要在企業內部跑，NetLens 必須在企業現有的硬體上夠快。所以我們把模型轉成 OpenVINO，並量化成 INT8，也就是用 8 位元整數取代 32 位元浮點數。同一個模型、同樣 152 個函式、三種引擎：PyTorch 跑在 CPU、OpenVINO INT8 跑在同一顆 Intel CPU、OpenVINO 跑在 Intel 內顯，看它的使用率即時上升。兩條 OpenVINO 都跑完時，PyTorch 還不到一半。我們的測試中，同一顆晶片的吞吐量提升將近 4 倍，而且 GPU 把 CPU 讓給 Semgrep 用。

## 場景 4｜本地 LLM 修漏洞（1:52–2:25）
**畫面**：按 `4` → `Enter`（F1 SQL 注入）。若改錄 F2，換用括號裡的句子。

> Finding a vulnerability is only half the job. So on the same Intel GPU, NetLens runs a local code model, Qwen2.5-Coder, compressed to four bits. It explains how an attacker would exploit the bug, then writes the patch — here, a SQL injection becomes a parameterized query. *(F2：here, a shell command built from user input becomes a safe argument list.)* About fifteen tokens per second on laptop integrated graphics — and zero bytes of source code leave the machine.

中文意思：找到漏洞只是一半的工作。所以 NetLens 在同一顆 Intel GPU 上跑一個本地程式碼模型 Qwen2.5-Coder，壓縮到 4 位元。它會解釋攻擊者怎麼利用這個漏洞，然後寫出修補程式。這裡 SQL 注入被改成參數化查詢（F2：用使用者輸入拼出的 shell 指令被改成安全的參數陣列）。在筆電內顯上每秒約 15 個 token，而且沒有任何一個位元組的原始碼離開這台電腦。

## 場景 5｜數據卡（2:25–2:44）
**畫面**：按 `5`，每 4–5 秒按一次空白鍵。

> Quantization makes the model four times smaller — with no loss in accuracy: macro-F1 is identical to the third decimal place across two thousand seven hundred forty-two test functions. **[可刪]** And on an Intel Arc Pro B70, we project three to five milliseconds per function — ten thousand findings reviewed in under half a minute.

中文意思：量化讓模型小了 4 倍，而且準確率沒有下降：在 2,742 個測試函式上，macro-F1 到小數點後第三位都一樣。在 Intel Arc Pro B70 上，我們推估每個函式只要 3 到 5 毫秒，一萬個 finding 不到半分鐘就能審完。

## 場景 6｜架構收尾（2:44–2:55）
**畫面**：按 `6`。

> Semgrep on the CPU. CodeBERT and the fix-writing model sharing a single thirty-two-gigabyte Arc Pro B70. The whole pipeline, in a single ASUS workstation. Your code never leaves. Your vulnerabilities do.

中文意思：Semgrep 跑在 CPU，CodeBERT 和寫修補的模型共用一張 32GB 的 Arc Pro B70。整條管道放進一台 ASUS 工作站。你的程式碼不會離開，你的漏洞會。

---

## 唸法提示
| 詞 | 唸法 |
|---|---|
| OpenVINO | open-VEE-no |
| Semgrep | SEM-grep |
| Qwen | chwen（近似「圈」） |
| INT8 | int-eight |
| macro-F1 | MAK-roh eff-one |
| on-premises | on-PREM-ih-sez |

## 數字核對（旁白 ↔ 實測）
| 旁白 | 實際數據 |
|---|---|
| 953 alerts, 10 projects | 217 + 131 + 605（`dataset/bench_real_projects_20260927_2322.md`） |
| 51 in, 37 thrown out | healthchecks 掃描：confirmed 9、needs review 5、filtered 37 |
| drop by 84% | 3.6 → 0.56 alerts/KLOC（團隊 10 專案基準） |
| PyTorch less than halfway | live：OpenVINO 最慢 25.8 s 時 PyTorch 約 39%；replay：13.6 s 時約 27% |
| nearly four times the throughput | 3.0 → 11.8 functions/s（CPU，benchmark） |
| four bits / fifteen tokens per second | Qwen2.5-Coder-3B INT4，iGPU 實測 13.4–15.5 tok/s |
| four times smaller | 476 MB → 121 MB（3.9×） |
| identical to the third decimal | macro-F1 0.7159 → 0.7160（皆為 0.716） |
| 3–5 ms, 10,000 in under half a minute | **估算**：96.6 GOP ÷ (367 TOPS × 5–25%)；10,000 ÷ 400–900/s = 11–25 s |
