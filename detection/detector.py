import torch
import timm
import numpy as np
from PIL import Image, ImageChops, ImageEnhance
from torchvision import transforms
from pytorch_grad_cam import GradCAM
from pytorch_grad_cam.utils.image import show_cam_on_image
from pytorch_grad_cam.utils.model_targets import ClassifierOutputTarget
import cv2
import os


class AIImageDetector:

    def __init__(self, model_path=None):

        self.device = torch.device(
            "cuda" if torch.cuda.is_available() else "cpu"
        )

        print(f"使用裝置：{self.device}")

        # ─────────────────────────────
        # v5 fusion model (9 channels)
        # ─────────────────────────────
        self.model = timm.create_model(
            "efficientnet_b4",
            pretrained=False,
            num_classes=2,
            in_chans=9
        ).to(self.device)

        if model_path and os.path.exists(model_path):
            self.model.load_state_dict(
                torch.load(model_path, map_location=self.device)
            )
            print(f"載入模型：{model_path}")
        else:
            print("⚠ 使用未訓練模型")

        self.model.eval()

        self.transform = transforms.Compose([
            transforms.Resize((380, 380)),
            transforms.ToTensor()
        ])

    # ─────────────────────────────
    # ELA
    # ─────────────────────────────
    def get_ela(self, img, quality=90):

        temp = "temp.jpg"
        img.save(temp, "JPEG", quality=quality)

        comp = Image.open(temp)

        diff = ImageChops.difference(img, comp)

        extrema = diff.getextrema()
        max_diff = max([e[1] for e in extrema]) or 1

        scale = 255.0 / max_diff
        ela = ImageEnhance.Brightness(diff).enhance(scale)

        os.remove(temp)
        return ela

    # ─────────────────────────────
    # FFT
    # ─────────────────────────────
    def get_fft(self, img):

        gray = np.array(img.convert("L")).astype(np.float32)

        fft = np.fft.fft2(gray)
        fft = np.fft.fftshift(fft)

        mag = np.log(np.abs(fft) + 1)

        mag = (mag - mag.min()) / (mag.max() - mag.min() + 1e-6)
        mag = (mag * 255).astype(np.uint8)

        mag = cv2.applyColorMap(mag, cv2.COLORMAP_INFERNO)
        mag = cv2.cvtColor(mag, cv2.COLOR_BGR2RGB)

        return Image.fromarray(mag)

    # ─────────────────────────────
    # BUILD 9 CHANNEL INPUT
    # ─────────────────────────────
    def build_input(self, image):

        rgb = self.transform(image)

        ela = self.transform(self.get_ela(image))
        fft = self.transform(self.get_fft(image))

        x = torch.cat([rgb, ela, fft], dim=0)  # 9 channels

        return x.unsqueeze(0).to(self.device)

    # ─────────────────────────────
    # PREDICT
    # ─────────────────────────────
    def predict(self, image_path):

        image = Image.open(image_path).convert("RGB")

        input_tensor = self.build_input(image)

        original = np.array(
            image.resize((380, 380))
        ).astype(np.float32) / 255.0

        with torch.no_grad():
            output = self.model(input_tensor)
            prob = torch.softmax(output, dim=1)

        fake_score = prob[0][0].item()
        real_score = prob[0][1].item()

        predicted = int(output.argmax(1))

        return {
            "fake_score": fake_score,
            "real_score": real_score,
            "predicted": predicted,
            "original": original,
            "input_tensor": input_tensor
        }

    # ─────────────────────────────
    # GRADCAM
    # ─────────────────────────────
    def generate_gradcam(self, original, input_tensor, output_path):

        target_layers = [self.model.conv_head]

        cam = GradCAM(
            model=self.model,
            target_layers=target_layers
        )

        targets = [ClassifierOutputTarget(0)]

        grayscale_cam = cam(
            input_tensor=input_tensor,
            targets=targets
        )[0]

        vis = show_cam_on_image(original, grayscale_cam, use_rgb=True)

        Image.fromarray(vis).save(output_path)

    # ─────────────────────────────
    # ANALYZE
    # ─────────────────────────────
    def analyze(self, image_path, output_dir="detection/outputs"):

        os.makedirs(output_dir, exist_ok=True)

        filename = os.path.splitext(os.path.basename(image_path))[0]

        result = self.predict(image_path)

        fake = result["fake_score"]
        real = result["real_score"]

        verdict = "⚠️ AI 生成" if fake > real else "✅ 真實照片"

        confidence = max(fake, real)

        image = Image.open(image_path).convert("RGB")

        original = np.array(image.resize((380, 380))) / 255.0

        gradcam_path = os.path.join(output_dir, f"{filename}_gradcam.jpg")

        self.generate_gradcam(
            original,
            result["input_tensor"],
            gradcam_path
        )

        return {
            "image_path": image_path,
            "verdict": verdict,
            "ai_score": fake,
            "real_score": real,
            "confidence": confidence,
            "gradcam_path": gradcam_path
        }


if __name__ == "__main__":

    detector = AIImageDetector(
        model_path="detection/models/netlens_detector_v5.pth"
    )

    for folder in ["detection/test_images/real", "detection/test_images/fake"]:

        if not os.path.exists(folder):
            continue

        for f in os.listdir(folder):

            if f.endswith((".jpg", ".png", ".jpeg")):
                path = os.path.join(folder, f)

                result = detector.analyze(path)

                print(result["verdict"])