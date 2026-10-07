# 🔍 NetLens｜AI 時代的瀏覽器護目鏡

> 在 AI 生成內容氾濫的時代，NetLens 幫你驗證網路圖片的真偽。

---

## 專題簡介

NetLens 是一個 AI 圖片真偽鑑識系統，目標是成為瀏覽器擴充套件，讓使用者在瀏覽網頁時能即時分析圖片是否由 AI 生成。

目前開發中的模塊：

| 模塊 | 說明 | 狀態 |
|------|------|------|
| `detection/` | AI 圖片偵測（EfficientNet-B4） | ✅ 開發中 |
| `security/` | 資安威脅偵測（釣魚連結、郵件分析） | 🔜 待開發 |
| `watermark/` | C2PA 護照 + 隱寫浮水印 | 🔜 待開發 |
| `api/` | FastAPI 後端 + 系統整合 | 🔜 待開發 |

---

## 目前成果（detection 模塊）

### 模型表現

| 測試類別 | 準確率 | 平均 AI 分數 |
|----------|--------|--------------|
| Kaggle 真實照片（訓練內） | 98.2% | 0.0201 |
| Kaggle AI 生成（SD/MJ 風格，訓練內） | 99.2% | 0.9908 |
| StyleGAN 140k test set（訓練內） | 100.0% | 0.9999 |
| StyleGAN thispersondoesnotexist（訓練外） | 40.0% | 0.4057 |

> 訓練資料：64,000 張（Kaggle AI vs Human + 140k Real and Fake Faces）
> 模型：EfficientNet-B4 fine-tune，解凍 blocks.5 + blocks.6 + conv_head + classifier
> 最佳驗證準確率：**99.6%**

### 分析功能

- **EfficientNet 分類**：輸出 AI 生成機率（0–100%）
- **GradCAM 熱力圖**：視覺化模型關注的可疑區域
- **ELA 分析**：壓縮差異檢測，找出竄改痕跡
- **FFT 頻譜分析**：頻率分布視覺化，輔助判斷 GAN artifact
- **URL 直接分析**：貼上圖片網址即可分析，不需下載

---

## 專案結構

```
CSIE_Project/
└── NetLens/
    ├── detection/
    │   ├── models/                     # 模型權重（不推上 GitHub）
    │   ├── test_images/
    │   │   ├── real/                   # 測試用真實照片
    │   │   ├── fake/                   # 測試用 AI 生成圖
    │   │   └── stylegan/               # StyleGAN 專用測試圖
    │   ├── dataset/                    # 訓練資料集（不推上 GitHub）
    │   ├── dataset_v2/                 # 擴充訓練資料集（不推上 GitHub）
    │   ├── outputs/                    # 分析結果輸出
    │   │   └── counter.json            # 分析次數計數器
    │   ├── detector.py                 # 核心偵測程式
    │   ├── train.py                    # Fine-tune 訓練腳本
    │   ├── prepare_dataset.py          # 資料集整理（Kaggle）
    │   ├── prepare_dataset_v2.py       # 資料集整理（Kaggle + StyleGAN）
    │   ├── download_dataset.py         # Kaggle 資料集下載
    │   ├── download_stylegan.py        # StyleGAN 140k 資料集下載
    │   ├── download_FF.py              # FaceForensics++ 下載（待使用）
    │   ├── evaluate.py                 # 跨生成器評估
    │   └── visualize_results.py        # 評估結果視覺化
    ├── security/                       # 待開發
    ├── watermark/                      # 待開發
    ├── api/                            # 待開發
    └── app.py                          # Gradio 展示介面
```

---

## 安裝與執行

### 環境需求

- Python 3.11
- CUDA 12.x（建議使用 NVIDIA GPU）
- conda（建議使用 miniconda）

### 第一步：建立 conda 環境

```bash
conda create -n CSIE_Project python=3.11
conda activate CSIE_Project
```

### 第二步：安裝 PyTorch（CUDA 版本）

```bash
conda install pytorch torchvision torchaudio pytorch-cuda=12.1 -c pytorch -c nvidia -y
```

### 第三步：安裝其他套件

```bash
pip install timm gradio opencv-python matplotlib pillow grad-cam requests pandas kagglehub
```

### 第四步：下載模型權重

模型權重因為檔案太大不放在 GitHub， `netlens_detector_v3.pth`在
```
https://drive.google.com/drive/folders/1eV5DG5dza-WBVeQS3RyzFR6Dj9wAHF3W?usp=sharing
```

放到以下路徑：
```
detection/models/netlens_detector_v3.pth
```

### 第五步：啟動 Gradio 介面

```bash
cd NetLens
python app.py
```

開啟瀏覽器進入 `http://127.0.0.1:7860` 即可使用。

---

## 主要腳本說明

| 腳本 | 用途 | 執行指令 |
|------|------|----------|
| `app.py` | 啟動 Gradio 展示介面 | `python app.py` |
| `detection/detector.py` | 批次分析 test_images 資料夾 | `python detection/detector.py` |
| `detection/train.py` | 重新訓練模型 | `python detection/train.py` |
| `detection/evaluate.py` | 跨生成器評估 | `python detection/evaluate.py` |
| `detection/prepare_dataset_v2.py` | 準備訓練資料集 | `python detection/prepare_dataset_v2.py` |
| `detection/visualize_results.py` | 產生評估圖表 | `python detection/visualize_results.py` |

---

## 已知問題

| 問題 | 原因 | 狀態 |
|------|------|------|
| 高品質 StyleGAN（thispersondoesnotexist.com）辨識率 40% | 後處理消除了 GAN artifact | 研究中，待加入更多訓練資料 |
| 社交平台圖片 URL 無法直接分析 | 防盜鏈保護（400/403） | 待瀏覽器套件解決 |
| PNG 圖片 ELA 效果較差 | ELA 設計給 JPEG，PNG 格式轉換產生噪音 | ✅ 已透過自動轉換 JPEG 改善 |

---

## 開發進度

- [x] detection 模塊核心偵測功能
- [x] EfficientNet-B4 fine-tune（99.6% 驗證準確率）
- [x] GradCAM 熱力圖
- [x] ELA 壓縮差異分析
- [x] FFT 頻域分析
- [x] Gradio 展示介面
- [x] URL 直接分析
- [x] StyleGAN 跨生成器評估實驗
- [ ] security 模塊（釣魚連結、郵件分析）
- [ ] watermark 模塊（C2PA、隱寫浮水印）
- [ ] 瀏覽器擴充套件
- [ ] FastAPI 後端整合
- [ ] FaceForensics++ 資料集整合

---

## 技術選型

| 項目 | 技術 |
|------|------|
| 主模型 | EfficientNet-B4（timm） |
| 訓練框架 | PyTorch 2.5.1 |
| 視覺化 | GradCAM、OpenCV、Matplotlib |
| 展示介面 | Gradio 6.14.0 |
| 後端（規劃中） | FastAPI |
| 訓練資料集 | Kaggle AI vs Human Generated + 140k Real and Fake Faces |