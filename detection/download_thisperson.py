import os
import requests
import random
import time

# =========================
# 設定
# =========================

# ✅ 最終路徑：raw_datasets/fake/thisperson
SAVE_DIR = "raw_datasets/fake/thisperson"

TOTAL_IMAGES = 50000
BASE_URL = "https://thispersondoesnotexist.com/"

FILE_PREFIX = "tp"

os.makedirs(SAVE_DIR, exist_ok=True)

session = requests.Session()


def download_image(i):
    try:
        url = BASE_URL + "?seed=" + str(random.randint(1, 10**9))

        headers = {
            "User-Agent": "Mozilla/5.0",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache"
        }

        response = session.get(url, headers=headers, timeout=15)

        if response.status_code == 200:

            # tp_00001.jpg
            path = os.path.join(SAVE_DIR, f"{FILE_PREFIX}_{i:05d}.jpg")

            if len(response.content) < 10000:
                return f"SKIP {i} (too small)"

            with open(path, "wb") as f:
                f.write(response.content)

            return f"OK {i}"

        return f"FAIL {i} {response.status_code}"

    except Exception as e:
        return f"ERROR {i} {str(e)}"


print("🚀 開始下載 ThisPersonDoesNotExist")
print(f"目標數量: {TOTAL_IMAGES}")
print(f"儲存位置: {SAVE_DIR}")

existing_files = [
    f for f in os.listdir(SAVE_DIR)
    if f.startswith(FILE_PREFIX + "_") and f.endswith(".jpg")
]

start_index = len(existing_files)

print(f"目前已有：{start_index} 張")

for i in range(start_index, TOTAL_IMAGES):
    result = download_image(i)
    print(result)
    time.sleep(0.5)

print("\n✅ 完成")