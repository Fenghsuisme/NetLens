# 模型機測試步驟（驗證本輪 Semgrep 規則改動）

本輪在**無模型**環境下改了規則、並用 Semgrep 層驗證過召回天花板與 clean 誤報。
以下步驟在**有模型**的機器上跑完整兩階段管道，確認：

1. 召回改善是否延續到「片段管道」（模型能否確認新抓到的樣本）
2. 放寬的規則是否在模型過濾後仍未推高殘留誤報

---

## 0. 前置條件（模型機）

- [ ] 取得本分支程式碼（**本輪改動尚未 commit**；先在開發機 commit + push，模型機再 pull；或直接複製 `reviewer/`）
- [ ] 模型在 `models/codebert_v7v8_safe/`（含 `model.safetensors` + `config.json`）
- [ ] venv 已裝 `torch`、`transformers`、`semgrep`、`pyyaml`
- [ ] 可連 HuggingFace（首次會下載 `microsoft/codebert-base` tokenizer；或事先備好離線快取）
- [ ] **所有指令都在 `reviewer/` 根目錄執行**（腳本用相對路徑找 `rules/`、`models/`、`dataset/`）

> ⚠️ **注意 `obfuscate.py` 不在 repo 內** → `HAS_OBFUSCATE=False`，推論時**不做函式名去語意化**。
> scan.py 與 eval 都優雅降級（一致），但若模型訓練時有做去語意化，這是 train/inference 不一致，
> 會壓低所有數字。若你手上有 `obfuscate.py`，放回 `reviewer/` 再測，數字才對得上訓練條件。

---

## 1. 環境與規則健檢（無模型，數秒）

```bash
python scripts/semgrep_health.py      # 應：10 份補強全部 ✓、掃描測試通過
python check_rules.py                 # 應：④=0、⑤=0（規則語法全有效）
```

⑤ 若非 0 表示有規則語法錯誤靜默失效，先修再往下。

---

## 2. 清掉舊快取（規則已改，必做！）

`eval_clean.py` 有 Semgrep 快取；規則變了必須重建，否則誤報數字是舊的。

```bash
[ -f dataset/clean_fp_cache.json ] && mv dataset/clean_fp_cache.json dataset/clean_fp_cache_prev.json
```

---

## 3. 召回評估（約 30 分鐘）

```bash
python eval/eval_e2e.py --with-b -n 30      # 每類抽 30 筆，A+B 全類
# 報告輸出：dataset/e2e_report.txt
```

**看什麼**（對照下方基線）：
- `Semgrep` 欄：本輪拉高的四類應明顯上升（指令注入、SQL、反序列化、原型污染、檔案上傳）
- `片段管道` 欄：關鍵問題——模型能否**確認**新抓到的樣本？若 Semgrep 大漲但片段管道沒跟上，代表模型判不出來（模型瓶頸，非規則問題）
- `整檔對照` 欄：模型看整檔的上限

跑完整版（約 160 分鐘，數字更穩）：
```bash
python eval/eval_e2e.py --with-b
```

---

## 4. 誤報評估（約 9 分鐘）

```bash
python eval_clean.py                    # 150 筆 clean，三級閘門殘留誤報
python eval_clean.py --analyze-only     # 之後只重算指標（讀快取，秒級）
```

**看什麼**：殘留誤報率不應比基線（軟閘門後 ~12.7%）明顯上升。
本輪放寬了反序列化 / 指令注入 / SQL / 檔案上傳的 sink，Semgrep 層 FP 有增加，
此步驟確認模型是否把它們過濾掉了。

---

## 5.（選用）閘門策略召回代價

```bash
python eval_gate_recall.py -n 30
```

---

## 6.（選用）真實檔案冒煙測試

```bash
python scan.py <某個真實 .py/.js/.php/.java 檔>
python scan.py <檔> --no-model          # 只跑規則，快
```

---

## 對照基線（本輪改動「前」，來自交接文件，-n 30）

僅列本輪動過的類別，看 Semgrep 欄的變化即可（本地 Semgrep 天花板實測值）：

| 類別 | 改動前 Semgrep | 本輪後（本地實測天花板） |
|---|---|---|
| 指令注入 | 76.7% | ~100% |
| SQL 注入 | 86.7% | ~99% |
| 反序列化 | 76.7% | ~95% |
| 原型污染 | 60.0% | ~96% |
| 檔案上傳 | 23.3% | ~95% |

> 上表右欄是**本地規則**天花板（離線，不含官方 `p/security-audit`）。
> eval_e2e 會**加上**官方規則，故實際 Semgrep 欄可能再高一些。
> 重點觀察：**片段管道**欄是否隨 Semgrep 一起上升。

---

## 本輪改動的檔案（供 review / commit）

規則：
- `rules/php.yml`（反序列化、指令注入、SQL 放寬；weak-hash、command-cwe77 精確化）
- `rules/python.yml`（subprocess shell=True 尾端 `...`）
- `rules/supplement_proto.yml`（java map-merge 新規則 + 死規則修復；php/python 合併形態）
- `rules/supplement_upload.yml`（**新檔**，CWE-434 檔案上傳）
- `rules/typescript.yml`、`rules/csharp.yml`（語意化 metavariable 缺陷修正）

工具 / 一致性：
- `check_rules.py`（新增 ⑤ Semgrep 驗證）
- `transport_layer.py`（SUPPLEMENT_RULES 加入 supplement_upload）
- `eval/eval_e2e.py`（SUPPLEMENTS 改為匯入 SUPPLEMENT_RULES，杜絕漂移）
- `eval_clean.py`（修 import 路徑，補 `eval/` 到 sys.path）
- `scripts/semgrep_health.py`、`tools/show_missed.py`（補強清單統一）

---

# 真實專案測試（完整管道 Semgrep + CodeBERT）

合成測試集會量召回，但**規則是照測試集盲區補的，貼合測試集的風險是內建的**。
真實專案沒有標籤、**量不了召回**，但能量使用者實際會看到的東西：
**每千行幾個 finding（噪音密度）**、模型在真實碼上到底濾不濾得掉放寬的規則。

工具：`tools/real_fp_test.py`（跑 `scan.py` → 彙總 verdict × 類別 × 規則 × 每 KLOC 密度）

## 用兩組專案，一次展示兩階段的兩個賣點

### A 組：刻意脆弱的應用 —— 證明「抓得到真漏洞」（召回）

真實部署的靶場，漏洞位置有官方文件，可逐條驗證。

| 專案 | 語言 | 對應本輪改的類別 |
|---|---|---|
| `digininja/DVWA` | PHP | SQLi、命令注入、檔案上傳、CSRF、XSS（★ 幾乎全中，最推薦） |
| `WebGoat/WebGoat` | Java | 反序列化、SQLi、XXE |
| `juice-shop/juice-shop` | Node/TS | SQLi、XSS、原型污染（偏大、TS 多，可選） |

**判讀**：finding 密度**高是好事**（抓到真漏洞）。本輪放寬的規則
（`php-untrusted-deserialization`、`php-os-command-injection`、`php-sql-injection`、
`*-unrestricted-upload`）應命中 DVWA 對應的已知漏洞頁面。

```bash
python scan.py /tmp/proj/DVWA --show-snippet     # 逐條看命中行，對照已知漏洞驗證
python tools/real_fp_test.py /tmp/proj/DVWA      # 看密度/規則分佈
```

### B 組：真實維護良好的應用 —— 證明「真實碼上噪音低」（精確度）

| 專案 | 語言 | 看什麼 |
|---|---|---|
| `spring-projects/spring-petclinic` | Java | Spring 官方範例應用，看 access-control/IDOR 誤報 |
| `monicahq/monica` | PHP/Laravel | 真實 CRM，看放寬的 SQL/上傳規則在真實 Laravel 上是否爆量 |
| `hagopj13/node-express-boilerplate` | JS | 真實 Express 骨架，看 JS 噪音 |

**判讀**：finding 密度**低才是好事**（模型應濾掉大半 semgrep 噪音）。
若本輪放寬的規則在真實碼上**爆量且模型濾不掉**，就是要回頭收窄的訊號
（呼應 CSRF/路徑遊走的殘留分析）。

```bash
python tools/real_fp_test.py /tmp/proj/spring-petclinic /tmp/proj/monica /tmp/proj/node-express-boilerplate
```

## clone 指令

```bash
mkdir -p /tmp/proj && cd /tmp/proj
git clone --depth 1 https://github.com/digininja/DVWA
git clone --depth 1 https://github.com/WebGoat/WebGoat
git clone --depth 1 https://github.com/spring-projects/spring-petclinic
git clone --depth 1 https://github.com/monicahq/monica
git clone --depth 1 https://github.com/hagopj13/node-express-boilerplate
cd ~/NetLens/reviewer
```

## 判讀重點總結

- **關鍵指標 = `confirmed+disputed 個/KLOC`**：這是使用者實際看到的噪音。
  A 組高（好，抓到漏洞）、B 組低（好，不吵）。
- **`模型過濾率`**：模型在真實碼上濾掉多少 semgrep 噪音，驗證兩階段是否真的有用。
- **`呈現 finding 最多的規則`**：直接抓出在真實碼上放寬過頭的規則。
- 完整故事：「該報的地方報得出來（A 組），不該吵的地方安靜（B 組）」。

## 注意

- **帶模型較久**（中型應用約 10–30 分鐘）。想先快速看原始 semgrep 噪音可加 `--no-model`。
- `scan.py` 有 `MAX_FILES=500` 上限，超大專案只掃前 500 檔。
- 上述 URL 是建議起點，可換成 MCP Server 實際面對的專案類型。

---

# E：擴充真實專案基準（可信的 FP 密度）

3 個專案的 0.19/KLOC 只是起點。要能宣稱「可實用」，需要 **10–20 個多樣真實 repo** 的 FP 密度分布——合成 clean 的 26% 是對抗性、會誤導，真實密度才是部署級指標。

## 建議的多樣真實應用（維護良好、有部署）

```bash
mkdir -p /tmp/bench && cd /tmp/bench
# Python
git clone --depth 1 https://github.com/getsentry/sentry              # 大型 SaaS
git clone --depth 1 https://github.com/apache/airflow                 # 工作流平台
git clone --depth 1 https://github.com/miguelgrinberg/microblog       # Flask 教學應用
# JavaScript / TypeScript
git clone --depth 1 https://github.com/strapi/strapi                  # headless CMS
git clone --depth 1 https://github.com/nestjs/nest                    # Node 框架
git clone --depth 1 https://github.com/hagopj13/node-express-boilerplate
# Java
git clone --depth 1 https://github.com/spring-projects/spring-petclinic
git clone --depth 1 https://github.com/thingsboard/thingsboard        # IoT 平台
# PHP
git clone --depth 1 https://github.com/monicahq/monica                # Laravel CRM
git clone --depth 1 https://github.com/Cachet-Community/Cachet         # 狀態頁
git clone --depth 1 https://github.com/bcit-ci/CodeIgniter            # 框架
cd ~/NetLens/reviewer
```

## 一次跑全部、看整體與逐專案密度

```bash
# 逐專案（看哪個專案/語言噪音高）
for p in /tmp/bench/*/; do
  echo "===== $p ====="
  python tools/real_fp_test.py --no-model "$p" | grep -E "個 / KLOC|confirmed\+disputed"
done

# 帶模型的整體密度（挑幾個代表性的，較久）
python tools/real_fp_test.py /tmp/bench/microblog /tmp/bench/spring-petclinic /tmp/bench/monica /tmp/bench/node-express-boilerplate
```

## 判讀

- **目標指標**：`confirmed+disputed 個/KLOC` 的**中位數與分布**。單一專案不準，看跨 10+ 專案的整體。
- **可實用門檻參考**：業界靜態掃描工具真實碼上常見 < 1 個/KLOC 才不惱人；理想 < 0.5。
- **逐專案異常**：某專案密度特別高 → 看它觸發哪條規則（`real_fp_test` 的規則排名），多半是既有過寬規則在該框架上爆。
- 帶模型 vs `--no-model` 對照 → 看模型過濾率（呼應 C 的重訓目標）。
