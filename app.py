import gradio as gr
import sys
import os
import json
import requests
from io import BytesIO
from PIL import Image
import time

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from detection.detector import AIImageDetector

# ── 載入 v5 模型 ───────────────────────────────
detector = AIImageDetector(
    model_path="detection/models/netlens_detector_v5.pth"
)

# ── counter ────────────────────────────────────
COUNTER_FILE = "detection/outputs/counter.json"

def load_counter():
    if os.path.exists(COUNTER_FILE):
        with open(COUNTER_FILE, "r") as f:
            return json.load(f).get("count", 0)
    return 0

def save_counter(count):
    os.makedirs(os.path.dirname(COUNTER_FILE), exist_ok=True)
    with open(COUNTER_FILE, "w") as f:
        json.dump({"count": count}, f)

analysis_count = load_counter()

# ───────────────────────────────────────────────
# CORE ANALYSIS
# ───────────────────────────────────────────────
def analyze_image(image):
    global analysis_count

    if image is None:
        return None, None, None, "請上傳圖片"

    analysis_count += 1
    save_counter(analysis_count)

    os.makedirs("detection/outputs", exist_ok=True)

    # 避免多用戶衝突
    temp_path = f"detection/outputs/temp_{int(time.time()*1000)}.jpg"

    # ★ 統一尺寸（非常重要）
    image = image.convert("RGB")
    image = image.resize((380, 380))
    image.save(temp_path)

    # 分析
    result = detector.analyze(temp_path)

    # 讀圖（copy避免 file lock）
    gradcam_img = Image.open(result["gradcam_path"]).copy()
    ela_img = Image.open(result["ela_path"]).copy()
    fft_img = Image.open(result["fft_path"]).copy()

    # 分數
    ai_pct = result["ai_score"] * 100
    conf_pct = result["confidence"] * 100
    fft_score = result.get("fft_score", 0)

    # 判斷
    if result["ai_score"] >= 0.5:
        verdict = "⚠️ AI 生成"
        hint = "模型判斷此圖較可能為 AI 生成"
    else:
        verdict = "✅ 真實照片"
        hint = "模型判斷此圖較可能為真實照片"

    report = f"""
## 鑑識報告

**結果：** {verdict}

**AI 機率：** {ai_pct:.2f}%

**信心：** {conf_pct:.2f}%

**FFT 異常分數：** {fft_score:.4f}

---

{hint}
"""

    return gradcam_img, ela_img, fft_img, report


# ───────────────────────────────────────────────
# URL INPUT
# ───────────────────────────────────────────────
def analyze_from_url(url):
    if not url or not url.strip():
        return None, None, None, "請輸入圖片網址"

    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        r = requests.get(url.strip(), headers=headers, timeout=10)
        r.raise_for_status()

        img = Image.open(BytesIO(r.content)).convert("RGB")

        # ★ 統一 resize（必須）
        img = img.resize((380, 380))

        return analyze_image(img)

    except Exception as e:
        return None, None, None, f"❌ 下載或解析失敗：{str(e)}"


# ───────────────────────────────────────────────
# UI
# ───────────────────────────────────────────────
with gr.Blocks(title="NetLens v5 AI Image Detector") as demo:

    gr.Markdown("# 🔍 NetLens v5｜AI 圖片鑑識系統")

    with gr.Row():
        with gr.Column(scale=1):
            input_image = gr.Image(type="pil", label="上傳圖片")
            analyze_btn = gr.Button("開始分析", variant="primary")

            url_input = gr.Textbox(label="圖片 URL")
            url_btn = gr.Button("分析 URL", variant="secondary")

        with gr.Column(scale=2):
            report_output = gr.Markdown()

    with gr.Row():
        gradcam_output = gr.Image(label="GradCAM")
        ela_output = gr.Image(label="ELA")
        fft_output = gr.Image(label="FFT")

    analyze_btn.click(
        fn=analyze_image,
        inputs=[input_image],
        outputs=[gradcam_output, ela_output, fft_output, report_output]
    )

    url_btn.click(
        fn=analyze_from_url,
        inputs=[url_input],
        outputs=[gradcam_output, ela_output, fft_output, report_output]
    )


if __name__ == "__main__":
    demo.launch(share=False)