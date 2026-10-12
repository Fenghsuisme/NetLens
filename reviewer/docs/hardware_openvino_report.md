# NetLens on Intel — OpenVINO 部署報告

> CodeBERT（17 類漏洞分類器）由 PyTorch 轉為 OpenVINO IR、INT8 量化，在 Intel CPU 與 Intel GPU 上實測；
> 並在同一顆 Intel GPU 上以 OpenVINO GenAI 跑本地 code LLM 產生「漏洞解釋＋修復 diff」。
> 所有數字皆為本機實測，除第 4 節 Arc Pro B70 為**估算**（已標明）。

## 0. 測試環境

| 項目 | 內容 |
|---|---|
| CPU | Intel Core 5 210H（8C/12T，筆電） |
| Intel GPU | Intel Graphics（210H 內建 iGPU，無 XMX），Windows 驅動 32.0.101.7084 |
| 參考 GPU | NVIDIA GeForce RTX 3050（僅作 PyTorch CUDA 參考） |
| OS | Windows 11 + WSL2 Ubuntu 22.04 |
| OpenVINO | 2026.4.1（WSL 與 Windows 同版）、openvino-genai 2026.4.1、NNCF 3.4.0 |
| PyTorch | 2.14.1+cpu（CPU 基準）／2.13.0+cu130（CUDA 參考） |
| 模型 | `models/codebert_v7v8_safe`（microsoft/codebert-base 微調，~125M 參數，17 類，512 token） |
| 基底 commit | `40680b3`（semgrep-round6）→ 分支 `feat/openvino-intel` |

> WSL2 只看得到 Intel `CPU`（Intel GPU 未對 WSL 暴露 compute runtime），因此 Intel GPU 的數字在 Windows 原生 Python 上量測；
> 同一份 IR、同一支 `ov_benchmark.py`。

## 1. 效能（512 token 固定長度，與 `scan.py` 前處理一致）

量測方式：`scripts/ov/ov_benchmark.py`。暖機 10 次後取中位數；`batch=1` 用 `PERFORMANCE_HINT=LATENCY`；
吞吐用 `PERFORMANCE_HINT=THROUGHPUT` + `AsyncInferQueue`（batch=8，裝置建議並行數）持續 15 秒。

| 後端 | 精度 | 裝置 | 單筆延遲 ms (p90) | batch=8 ms | 吞吐 函式/秒 | 模型大小 |
|---|---|---|---|---|---|---|
| PyTorch | FP32 | CPU (WSL) | 336 (353) | 2,681 | 3.0 | 475.6 MB |
| OpenVINO | FP32 | CPU (WSL) | 351 (359) | 2,384 | 4.1 | 475.9 MB |
| **OpenVINO** | **INT8** | **CPU (WSL)** | **141 (151)** | **922** | **11.8** | **120.7 MB** |
| OpenVINO | INT8-WO | CPU (WSL) | 218 (230) | 1,339 | 7.9 | 120.2 MB |
| OpenVINO | INT8 | CPU (Windows) | 139 (147) | 1,070 | 10.7 | 120.7 MB |
| **OpenVINO** | FP32 IR → FP16 執行 | **Intel iGPU** | **93 (98)** | 723 | 11.3 | 475.9 MB |
| OpenVINO | INT8 | Intel iGPU | 104 (106) | 870 | 9.1 | 120.7 MB |
| OpenVINO | INT8-WO | Intel iGPU | 93 (94) | 744 | 10.8 | 120.2 MB |
| PyTorch（參考） | FP32 | RTX 3050 CUDA | 34 (35) | 276 | 28.9 | 475.6 MB |

重點：
- **Intel CPU 上 OpenVINO INT8 比 PyTorch：延遲 2.4× 快、吞吐 3.9× 高、模型 3.9× 小。**
  完整 2,742 筆準確率評估的實際耗時也印證：PyTorch 962 s vs OV-INT8 324 s（3.0×）。
- **Intel iGPU：93 ms/函式，比 CPU PyTorch 快 3.6×**，且把 CPU 留給 Semgrep。
- iGPU 上 INT8 不比 FP16 快：210H 的 iGPU 沒有 XMX 矩陣引擎，INT8 只省記憶體不省算力。
  Arc Pro B70（Xe2）有 XMX INT8 引擎，INT8 的加速要在該卡上才會兌現 → 見第 4 節。
- INT8-WO（只量化權重、activation 保持浮點）是備案：準確率更貼近原始，CPU 上速度介於 FP32 與 INT8 之間。

原始資料：`docs/ov_results/bench.jsonl`（WSL）、`docs/ov_results/bench_win.jsonl`（Windows／iGPU）。

## 2. 準確率（量化不掉分）

測試集：`test_code/real_test/testset_merged.txt`，2,742 筆，17 類（與 `eval/test_v7v8_full_real.py` 同解析器），
前處理與 `scan.py::Scanner.classify` 完全一致（剝註解 → `code[:2000]` → 512 token）。
INT8 校準集：`security_training_dataset_v1.txt` + `dataset/hard_negatives`，共 143 筆，**與測試集不重疊**。

| 版本 | Accuracy | Macro-F1 | 與 PyTorch top-1 一致 | 過濾決策一致（label==0） |
|---|---|---|---|---|
| PyTorch FP32 | 0.6947 | 0.7159 | — | — |
| OV FP32 | 0.6947 | 0.7159 | 100.0% | 100.0% |
| **OV INT8** | **0.6937** | **0.7160** | 98.5% | **99.4%** |
| OV INT8-WO | 0.6944 | 0.7157 | 99.0% | 99.6% |

**INT8 macro-F1 差距 +0.01pp、accuracy −0.1pp，遠低於 1–2pp 的門檻。**

逐類別召回（PyTorch → OV-INT8）：

| # | 類別 | PyTorch | OV-INT8 | Δpp |
|---|---|---|---|---|
| 0 | 正常程式碼 | 60.0 | 59.3 | −0.7 |
| 1 | 指令注入 | 97.3 | 96.7 | −0.7 |
| 2 | SQL 注入 | 84.7 | 84.7 | 0.0 |
| 3 | 程式碼執行 | 93.3 | 92.0 | −1.3 |
| 4 | 資料外洩 | 23.0 | 24.3 | +1.4 |
| 5 | 後門 | 96.6 | 96.6 | 0.0 |
| 6 | 弱加密 | 81.3 | 80.7 | −0.7 |
| 7 | 硬編碼密碼 | 71.3 | 71.3 | 0.0 |
| 8 | 路徑遊走 | 80.0 | 78.7 | −1.3 |
| 9 | 不安全反序列化 | 96.0 | 96.7 | +0.7 |
| 10 | 跨站腳本 | 85.7 | 85.7 | 0.0 |
| 11 | 原型污染 | 98.7 | 98.7 | 0.0 |
| 12 | 惡意套件 | 48.0 | 48.0 | 0.0 |
| 13 | CSRF | 35.8 | 35.8 | 0.0 |
| 14 | SSRF | 75.5 | 74.8 | −0.6 |
| 15 | 不受限檔案上傳 | 55.0 | 56.2 | +1.2 |
| 16 | 權限控制缺陷 | 37.5 | 37.5 | 0.0 |

> 註：此表為「CodeBERT 單獨分類」的召回，非 NetLens 端到端（Semgrep 選點後）召回；
> 低分類別（資料外洩、CSRF、權限控制）是需跨檔上下文的類別，與量化無關，PyTorch 原模型即如此。

**Intel iGPU 上的準確率**（549 筆分層抽樣，每 5 筆取 1，GPU 以 FP16 執行）：

| 版本 | Macro-F1 | 與 PyTorch 一致 |
|---|---|---|
| PyTorch | 0.7436 | — |
| OV FP32→FP16 @iGPU | 0.7426 | 99.8% |
| OV INT8 @iGPU | 0.7395 | 98.2% |
| OV INT8-WO @iGPU | 0.7431 | 98.9% |

**端到端（`scan.py` 全管道，Semgrep 相同、只換 CodeBERT 後端）**：4 個測試檔共 274 個 finding，
`--backend openvino`（INT8, CPU）與 PyTorch 的「模型標籤＋分級結果」**272/274 一致（99.3%）**。
差異明細見 `docs/ov_results/scan_backend_parity.txt`。

原始資料：`docs/ov_results/accuracy_cpu.json`、`accuracy_cpu.log`、`accuracy_igpu_subset.json`。

## 3. 已整合進產品管道（不只是離線 benchmark）

`scan.py` 新增可選後端，預設行為不變：

```bash
python scan.py path/to/project/                                   # 原本：PyTorch
python scan.py path/to/project/ --backend openvino                # OpenVINO INT8 @ Intel CPU
python scan.py path/to/project/ --backend openvino --ov-device GPU # OpenVINO INT8 @ Intel GPU（iGPU / Arc）
```

實作：`core/ov_backend.py`（`OVCodeBERT`，載入 `models/codebert_ov_int8` IR），`scan.py` 只在 `--backend openvino` 時走新路徑。

## 4. Arc Pro B70 投影（**估算**）

**計算依據**
- CodeBERT 每個函式（512 token）運算量：12 層 × [線性層 2×7.08M×512 + 注意力 4×512²×768] ≈ **96.6 GOP**。
- 本機 iGPU 實測：96.6 GOP / 93 ms ≈ **1.0 TOPS 有效算力**。
- Arc Pro B70：**367 TOPS INT8（峰值，XMX）**、32 GB。
- Transformer 推論在 GPU 上的有效利用率，保守取：batch=1 約 5–10%，大批次 10–25%。

| 指標 | 本機 Intel 實測（最佳） | Arc Pro B70 估算 | 推算 |
|---|---|---|---|
| 單筆延遲 | 93 ms（iGPU） | **~3–5 ms** | 96.6 GOP ÷ (367 TOPS × 5–10%)，+~1 ms 呼叫開銷 |
| 吞吐 | 11.8 函式/秒（CPU INT8） | **~400–900 函式/秒** | 367 TOPS × 10–25% ÷ 96.6 GOP |
| 1 萬個 finding 複查 | ~14 分鐘（CPU INT8） | **~11–25 秒** | 10,000 ÷ 吞吐 |

> 以上為依算力比例的估算，尚未在實機量測；B70 實機到手後以同一支 `ov_benchmark.py --device GPU` 驗證。

**32 GB 顯存預算（同卡共置）**

| 元件 | 佔用 |
|---|---|
| CodeBERT INT8 | 121 MB 權重（+ 執行期 buffer，<1 GB） |
| Qwen2.5-Coder-3B INT4（本 POC 實際使用） | 1.8 GB |
| Qwen2.5-Coder-7B INT4（升級選項，HF 上 OpenVINO 官方 IR） | 4.5 GB |
| 剩餘（KV cache、並行請求） | > 20 GB |

**結論**：CodeBERT 只有 ~125M 參數、512 token，INT8 後模型推論在 B70 上不再是瓶頸（每檔個位數毫秒）；
現況 2.7 s/檔的瓶頸是 CPU 上逐檔執行 Semgrep。因此在單一 ASUS 工作站上的分工是：
**Semgrep 跑 CPU、CodeBERT INT8 和 code LLM 同在 Arc Pro B70 上**，整條管道 on-prem 跑完，原始碼不出內網。

```
┌──────────────────────── ASUS 工作站（on-prem，原始碼不出內網）────────────────────────┐
│                                                                                       │
│  原始碼 ──► [Intel CPU] Semgrep 選點 ──► 傳輸層抽函式 ──┐                               │
│                                                        ▼                               │
│                              ┌──────── Intel Arc Pro B70（32 GB）────────┐             │
│                              │  CodeBERT INT8 (OpenVINO)  121 MB          │             │
│                              │    17 類判定 → 確認 / 存疑 / 過濾誤報        │             │
│                              │                 │                          │             │
│                              │                 ▼ 確認的 finding            │             │
│                              │  Code LLM INT4 (OpenVINO GenAI) 1.8–4.5 GB │             │
│                              │    漏洞解釋 + 修復 diff                     │             │
│                              └────────────────────────────────────────────┘             │
│                                                        ▼                               │
│                                         掃描報告 + 修復建議（PR comment）                │
└───────────────────────────────────────────────────────────────────────────────────────┘
```

## 5. 本地 LLM「漏洞解釋＋修復」POC

- 模型：`OpenVINO/Qwen2.5-Coder-3B-Instruct-int4-ov`，OpenVINO GenAI `LLMPipeline`，**Intel iGPU（GPU.0）**，greedy decoding。
- 設計：依 CWE 注入企業內部的安全編碼準則（`PLAYBOOK`，可換成公司自己的規範）；
  LLM 輸出完整修正後程式碼，再由 `difflib` 產生 diff（小模型直接寫 diff 容易格式錯亂）。
- 效能（iGPU 實測）：**14.3 tok/s**，首 token 1.2–1.5 s，每個 finding 12–20 s。

| Finding | 首 token | 速度 | 輸出 token | 修復評估 |
|---|---|---|---|---|
| F1 SQL 注入（Python） | 1,366 ms | 14.4 tok/s | 177 | ✅ 正確：參數化查詢 |
| F2 指令注入（Node.js） | 1,215 ms | 14.3 tok/s | 173 | ✅ 正確：`execFile` + 參數陣列 |
| F3 不安全反序列化（Java） | 1,485 ms | 14.3 tok/s | 262 | ⚠️ 方向正確（allow-list 過濾），但 API 簽章錯誤，需人工複核 |

**F1 — SQL Injection (CWE-89)**

> The vulnerability is SQL Injection. An attacker could send a malicious input for the `invoice_id` parameter … For example, an attacker could send `invoice_id=' OR 1=1--` which would return all records from the `invoices` table.

```diff
--- a/billing/invoices.py
+++ b/billing/invoices.py
@@ -5,8 +5,8 @@
     invoice_id = request.args.get('id', '')
     conn = sqlite3.connect('invoices.db')
     cursor = conn.cursor()
-    query = "SELECT * FROM invoices WHERE invoice_id = '" + invoice_id + "'"
-    cursor.execute(query)
+    query = "SELECT * FROM invoices WHERE invoice_id = ?"
+    cursor.execute(query, (invoice_id,))
     result = cursor.fetchall()
     conn.close()
     return jsonify(result)
```

**F2 — OS Command Injection (CWE-78)**

> An attacker could send a malicious username that includes shell metacharacters, such as `;`, `&&`, or `|` … For example, an attacker could send `; rm -rf /` to delete all files on the system.

```diff
--- a/admin/users.js
+++ b/admin/users.js
@@ -1,8 +1,9 @@
-const { exec } = require('child_process');
+const { execFile } = require('child_process');
 
 function deleteUserAccount(username) {
-  const command = `userdel -r ${username}`;
-  exec(command, (error, stdout, stderr) => {
+  const command = 'userdel';
+  const args = ['-r', username];
+  execFile(command, args, (error, stdout, stderr) => {
     if (error) {
       console.error(`Failed to delete user: ${error.message}`);
       return;
```

**F3 — Insecure Deserialization (CWE-502)**（需人工複核）

```diff
--- a/src/main/java/billing/InvoiceService.java
+++ b/src/main/java/billing/InvoiceService.java
@@ -4,6 +4,12 @@
         ObjectInputStream ois = new ObjectInputStream(bis);
+        ois.setObjectInputFilter(new ObjectInputFilter() {
+            public boolean isAllowed(ObjectStreamClass desc) {
+                // Allow only the expected application classes
+                return desc.getName().equals("com.example.Invoice");
+            }
+        });
         Invoice invoice = (Invoice) ois.readObject();
```

> 方向正確（只允許預期類別），但 `ObjectInputFilter` 的實際介面是 `Status checkInput(FilterInfo)`，此段無法編譯。
> 這正是設計上 LLM 修復走「建議 + 人工確認 / 編譯驗證」的原因；換 7B INT4（4.5 GB，同卡放得下）可預期改善。

完整輸出：`docs/ov_results/llm_outputs_igpu.json`。

## 6. 重現步驟

```bash
# ── WSL/Linux：匯出、量化、準確率、CPU benchmark ──
python -m venv ~/.ovenv && source ~/.ovenv/bin/activate
pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install openvino==2026.4.1 nncf "transformers>=4.50,<4.56" scikit-learn numpy
# 注意：transformers 5.x 的 masking_utils 會讓 TorchScript tracing 失敗，需用 4.x 匯出；
#       若裝了 optimum-intel 連帶的 torchvision 與 CPU torch 不相容，需 pip uninstall torchvision

cd reviewer
python scripts/ov/ov_export.py               # → models/codebert_ov_{fp32,int8,int8wo}/
python scripts/ov/ov_eval_accuracy.py        # → docs/ov_results/accuracy_cpu.json（約 45 分鐘）
for v in fp32 int8 int8wo; do
  python scripts/ov/ov_benchmark.py --backend openvino --model models/codebert_ov_$v/openvino_model.xml \
         --device CPU --tag ov_$v --out docs/ov_results/bench.jsonl
done
python scripts/ov/ov_benchmark.py --backend pytorch --model models/codebert_v7v8_safe --device cpu \
       --tag pytorch_fp32 --out docs/ov_results/bench.jsonl

# ── Windows 原生 Python（Intel GPU）──
python -m venv C:\ovwin ; C:\ovwin\Scripts\pip install openvino==2026.4.1 openvino-genai numpy
python ov_benchmark.py --backend openvino --model codebert_ov_int8\openvino_model.xml --device GPU.0 --tag ov_int8
python ov_eval_device.py --npz subset.npz --device GPU.0 --models codebert_ov_fp32 codebert_ov_int8
#   subset.npz 由 WSL 端產生：python scripts/ov/ov_make_subset.py --out subset.npz（549 筆）
huggingface-cli download OpenVINO/Qwen2.5-Coder-3B-Instruct-int4-ov --local-dir qwen2.5-coder-3b-int4-ov
python ov_llm_explain.py --model qwen2.5-coder-3b-int4-ov --device GPU.0 --findings findings.json

# ── 產品管道 ──
python scan.py <path> --backend openvino [--ov-device GPU]
```

檔案：

| 路徑 | 用途 |
|---|---|
| `scripts/ov/ov_common.py` | 前處理（與 scan.py 一致）、測試集／校準集載入 |
| `scripts/ov/ov_export.py` | PyTorch → OV FP32 IR、NNCF INT8 PTQ、INT8 weight-only |
| `scripts/ov/ov_eval_accuracy.py` | 2,742 筆完整準確率對照 |
| `scripts/ov/ov_eval_device.py` | 任意 OV 裝置（iGPU）準確率驗證，只需 openvino + numpy |
| `scripts/ov/ov_make_subset.py` | 產生 iGPU 驗證用的 subset.npz |
| `scripts/ov/ov_benchmark.py` | 延遲／吞吐量測（OV 與 PyTorch） |
| `scripts/ov/llm_demo/` | LLM 解釋＋修復 POC 與輸入 findings |
| `core/ov_backend.py` | `scan.py --backend openvino` 的推論後端 |
| `models/codebert_ov_*/openvino_model.xml` | IR 結構（`.bin` 權重未推，用 `ov_export.py` 重新產生） |

## 7. Slide-ready conclusions

1. **NetLens's CodeBERT detector now runs natively on Intel via OpenVINO: INT8 quantization cuts the model 3.9× (476 → 121 MB) and speeds Intel-CPU inference 2.4× in latency and 3.9× in throughput versus PyTorch.**
2. **Quantization is accuracy-neutral: macro-F1 0.7159 → 0.7160 on 2,742 labeled samples, every class within ±1.4 pp, and 99.3% identical verdicts end-to-end in the production scanner.**
3. **On a laptop Intel iGPU the detector already runs at 93 ms per function; Arc Pro B70's 367 INT8 TOPS projects to ~3–5 ms and ~400–900 functions/s (estimate), so model inference stops being the bottleneck.**
4. **The same Intel GPU also hosts a local INT4 code LLM (Qwen2.5-Coder-3B, 14 tok/s on iGPU) that explains each confirmed vulnerability and proposes a fix diff — no source code ever leaves the building.**
5. **The full pipeline — Semgrep on CPU, CodeBERT INT8 and the fix-suggesting LLM sharing one 32 GB Arc Pro B70 — fits on a single on-prem ASUS workstation.**
