import os
import json
import requests
import csv
from datetime import datetime

BLACKLIST_DIR = "security/blacklists"
LAST_UPDATED_FILE = os.path.join(BLACKLIST_DIR, "last_updated.json")
UPDATE_INTERVAL_HOURS = 12

# ── PhishTank 開關（目前暫停註冊，先關閉）──────────
PHISHTANK_ENABLED = False
PHISHTANK_API_KEY = os.getenv("PHISHTANK_API_KEY", "")


def ensure_dir():
    os.makedirs(BLACKLIST_DIR, exist_ok=True)


def load_last_updated():
    if os.path.exists(LAST_UPDATED_FILE):
        with open(LAST_UPDATED_FILE, "r") as f:
            return json.load(f)
    return {}


def save_last_updated(data):
    with open(LAST_UPDATED_FILE, "w") as f:
        json.dump(data, f, indent=2)


def needs_update(source_name):
    last = load_last_updated()
    if source_name not in last:
        return True
    last_time = datetime.fromisoformat(last[source_name])
    hours_passed = (datetime.now() - last_time).total_seconds() / 3600
    return hours_passed >= UPDATE_INTERVAL_HOURS


def mark_updated(source_name):
    last = load_last_updated()
    last[source_name] = datetime.now().isoformat()
    save_last_updated(last)


# ── OpenPhish ─────────────────────────────────────
def update_openphish():
    if not needs_update("openphish"):
        print("  ▸ OpenPhish：快取有效，跳過更新")
        return

    print("  ▸ 下載 OpenPhish 黑名單...")
    try:
        resp = requests.get(
            "https://openphish.com/feed.txt",
            timeout=30
        )
        resp.raise_for_status()
        urls = [line.strip() for line in resp.text.splitlines() if line.strip()]
        out = os.path.join(BLACKLIST_DIR, "openphish.json")
        with open(out, "w") as f:
            json.dump({"updated": datetime.now().isoformat(), "urls": urls}, f)
        mark_updated("openphish")
        print(f"  ▸ OpenPhish：下載完成，共 {len(urls)} 筆")
    except Exception as e:
        print(f"  ▸ OpenPhish 下載失敗：{e}")


# ── URLhaus ───────────────────────────────────────
def update_urlhaus():
    if not needs_update("urlhaus"):
        print("  ▸ URLhaus：快取有效，跳過更新")
        return

    print("  ▸ 下載 URLhaus 黑名單...")
    try:
        resp = requests.get(
            "https://urlhaus.abuse.ch/downloads/csv_recent/",
            timeout=30
        )
        resp.raise_for_status()

        urls = []
        for line in resp.text.splitlines():
            if line.startswith("#") or not line.strip():
                continue
            try:
                parts = next(csv.reader([line]))
                if len(parts) >= 3:
                    url = parts[2].strip().strip('"')
                    if url.startswith("http"):
                        urls.append(url)
            except Exception:
                continue

        out = os.path.join(BLACKLIST_DIR, "urlhaus.json")
        with open(out, "w") as f:
            json.dump({"updated": datetime.now().isoformat(), "urls": urls}, f)
        mark_updated("urlhaus")
        print(f"  ▸ URLhaus：下載完成，共 {len(urls)} 筆")
    except Exception as e:
        print(f"  ▸ URLhaus 下載失敗：{e}")


# ── Abuse.ch FEODO（惡意 IP）─────────────────────
def update_abusech():
    if not needs_update("abusech"):
        print("  ▸ Abuse.ch：快取有效，跳過更新")
        return

    print("  ▸ 下載 Abuse.ch 黑名單...")
    try:
        resp = requests.get(
            "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
            timeout=30
        )
        resp.raise_for_status()
        data = resp.json()

        ips = []
        for entry in data:
            ip = entry.get("ip_address", "")
            if ip:
                ips.append({
                    "ip": ip,
                    "malware": entry.get("malware", ""),
                    "first_seen": entry.get("first_seen", "")
                })

        out = os.path.join(BLACKLIST_DIR, "abusech.json")
        with open(out, "w") as f:
            json.dump({"updated": datetime.now().isoformat(), "ips": ips}, f)
        mark_updated("abusech")
        print(f"  ▸ Abuse.ch：下載完成，共 {len(ips)} 筆")
    except Exception as e:
        print(f"  ▸ Abuse.ch 下載失敗：{e}")


# ── PhishTank（暫時關閉）─────────────────────────
def update_phishtank():
    if not PHISHTANK_ENABLED:
        print("  ▸ PhishTank：已關閉（等待開放註冊）")
        return
    if not needs_update("phishtank"):
        print("  ▸ PhishTank：快取有效，跳過更新")
        return
    # 之後開放後實作


# ── 查詢黑名單 ────────────────────────────────────
def check_blacklists(url):
    """
    查詢 URL 是否在本地黑名單中
    """
    results = {
        "in_openphish": False,
        "in_urlhaus": False,
        "in_abusech": False,
        "in_phishtank": False,
        "blacklist_score": 0
    }

    # 查 OpenPhish
    openphish_file = os.path.join(BLACKLIST_DIR, "openphish.json")
    if os.path.exists(openphish_file):
        with open(openphish_file, "r") as f:
            data = json.load(f)
        if url in data.get("urls", []):
            results["in_openphish"] = True
            results["blacklist_score"] += 5

    # 查 URLhaus
    urlhaus_file = os.path.join(BLACKLIST_DIR, "urlhaus.json")
    if os.path.exists(urlhaus_file):
        with open(urlhaus_file, "r") as f:
            data = json.load(f)
        if url in data.get("urls", []):
            results["in_urlhaus"] = True
            results["blacklist_score"] += 5

    # 查 Abuse.ch（IP 比對）
    import re
    import tldextract
    abusech_file = os.path.join(BLACKLIST_DIR, "abusech.json")
    if os.path.exists(abusech_file):
        with open(abusech_file, "r") as f:
            data = json.load(f)
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        ip_match = re.search(ip_pattern, url)
        if ip_match:
            url_ip = ip_match.group()
            known_ips = [entry["ip"] for entry in data.get("ips", [])]
            if url_ip in known_ips:
                results["in_abusech"] = True
                results["blacklist_score"] += 5

    return results


# ── 更新所有黑名單 ────────────────────────────────
def update_all(force=False):
    ensure_dir()
    print("\n開始更新黑名單...")
    if force:
        # 強制更新：清除上次更新記錄
        if os.path.exists(LAST_UPDATED_FILE):
            os.remove(LAST_UPDATED_FILE)

    update_openphish()
    update_urlhaus()
    update_abusech()
    update_phishtank()
    print("\n黑名單更新完成")


# ── 主程式 ────────────────────────────────────────
if __name__ == "__main__":
    import sys
    force = "--force" in sys.argv
    update_all(force=force)

    # 測試查詢
    print("\n測試黑名單查詢：")
    test_url = "https://www.google.com"
    result = check_blacklists(test_url)
    print(f"URL：{test_url}")
    print(f"結果：{result}")