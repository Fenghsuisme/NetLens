import os
import sys
import cv2
import numpy as np
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PIL import Image
from security.url_analyzer import analyze_url

# ── QR Code 解碼 ──────────────────────────────────
def decode_qr(image_path):
    """
    從圖片解碼 QR Code（使用 OpenCV）
    """
    try:
        # 用 OpenCV 讀取圖片
        image = cv2.imread(image_path)
        if image is None:
            return {
                "success": False,
                "error": "無法讀取圖片",
                "contents": []
            }

        # 建立 QR Code 偵測器
        detector = cv2.QRCodeDetector()

        # 偵測並解碼（支援多個 QR Code）
        retval, decoded_info, points, straight_qrcode = detector.detectAndDecodeMulti(image)

        if not retval or not any(decoded_info):
            return {
                "success": False,
                "error": "未偵測到 QR Code",
                "contents": []
            }

        contents = []
        for data in decoded_info:
            if data:
                contents.append({
                    "type": "QR_CODE",
                    "data": data
                })

        return {
            "success": True,
            "count": len(contents),
            "contents": contents
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "contents": []
        }

# ── QR Code 安全分析 ──────────────────────────────
def analyze_qr(image_path, use_virustotal=False):
    """
    解碼 QR Code 並分析其中的 URL 安全性
    """
    print(f"\n分析 QR Code：{image_path}")

    # 第一步：解碼
    decode_result = decode_qr(image_path)

    if not decode_result["success"]:
        return {
            "image_path": image_path,
            "success": False,
            "error": decode_result["error"],
            "results": []
        }

    print(f"  ▸ 解碼成功：找到 {decode_result['count']} 個 QR Code")

    # 第二步：分析每個解碼內容
    analysis_results = []

    for content in decode_result["contents"]:
        data = content["data"]
        print(f"  ▸ 內容：{data}")

        # 判斷內容類型
        if data.startswith("http://") or data.startswith("https://"):
            # URL 類型：直接送釣魚偵測
            url_result = analyze_url(data, use_virustotal=use_virustotal)
            analysis_results.append({
                "type": "URL",
                "content": data,
                "analysis": url_result
            })

        elif data.startswith("WIFI:"):
            # WiFi 類型：解析 SSID 和密碼
            analysis_results.append({
                "type": "WiFi",
                "content": data,
                "analysis": {
                    "verdict": "⚠️  WiFi QR Code，請確認來源可信",
                    "risk_level": "medium",
                    "reasons": ["WiFi QR Code 可能導向惡意熱點"]
                }
            })

        elif data.startswith("mailto:"):
            # Email 類型
            analysis_results.append({
                "type": "Email",
                "content": data,
                "analysis": {
                    "verdict": "🟡  Email QR Code，請確認寄件對象",
                    "risk_level": "low",
                    "reasons": []
                }
            })

        else:
            # 純文字或其他類型
            analysis_results.append({
                "type": "文字",
                "content": data,
                "analysis": {
                    "verdict": "🟢  純文字內容",
                    "risk_level": "low",
                    "reasons": []
                }
            })

    # 第三步：整合最高風險等級
    risk_levels = [r["analysis"].get("risk_level", "low")
                   for r in analysis_results]
    if "high" in risk_levels:
        overall_risk = "high"
        overall_verdict = "🔴  高風險 QR Code"
    elif "medium" in risk_levels:
        overall_risk = "medium"
        overall_verdict = "🟡  中風險 QR Code，建議謹慎"
    else:
        overall_risk = "low"
        overall_verdict = "🟢  低風險 QR Code"

    return {
        "image_path": image_path,
        "success": True,
        "overall_verdict": overall_verdict,
        "overall_risk": overall_risk,
        "results": analysis_results
    }


# ── 主程式 ────────────────────────────────────────
if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        # 從命令列接收圖片路徑
        image_path = sys.argv[1]
    else:
        # 預設測試：需要自己準備一張 QR Code 圖片
        image_path = "security/test_data/test_qr.png"

    if not os.path.exists(image_path):
        print(f"找不到圖片：{image_path}")
        print("使用方式：python security/qr_analyzer.py <圖片路徑>")
    else:
        result = analyze_qr(image_path)
        print(f"\n{'='*50}")
        print(f"整體判斷：{result.get('overall_verdict', '分析失敗')}")
        if result["success"]:
            for r in result["results"]:
                print(f"\n類型：{r['type']}")
                print(f"內容：{r['content']}")
                print(f"結果：{r['analysis']['verdict']}")
                if r["analysis"].get("reasons"):
                    for reason in r["analysis"]["reasons"]:
                        print(f"  • {reason}")
        print('='*50)