import os
import sys
import re
import json
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from url_analyzer import analyze_url
from qr_analyzer import analyze_qr

# ── 從文字中抽取所有 URL ──────────────────────────
def extract_urls(text):
    """
    從任意文字中抽取所有 URL
    """
    pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    urls = re.findall(pattern, text)
    # 清理尾部標點符號
    cleaned = []
    for url in urls:
        url = url.rstrip('.,;:!?)')
        if url not in cleaned:
            cleaned.append(url)
    return cleaned


# ── 批次分析 ──────────────────────────────────────
def analyze_batch(urls, use_virustotal=False, use_sandbox=True):
    results = []
    total = len(urls)

    print(f"\n開始批次分析，共 {total} 個 URL")
    print("=" * 50)

    for i, url in enumerate(urls, 1):
        print(f"\n[{i}/{total}]", end="")
        result = analyze_url_cached(url, use_virustotal=use_virustotal, use_sandbox=use_sandbox)
        results.append(result)

    return results


# ── 從文字分析 ────────────────────────────────────
def analyze_text(text, use_virustotal=False):
    """
    從一段文字中抽取所有 URL 並分析
    適合分析郵件內容、網頁文字等
    """
    urls = extract_urls(text)

    if not urls:
        return {
            "success": False,
            "error": "文字中未找到任何 URL",
            "urls_found": 0,
            "results": []
        }

    print(f"從文字中找到 {len(urls)} 個 URL：")
    for url in urls:
        print(f"  • {url}")

    results = analyze_batch(urls, use_virustotal=use_virustotal)

    return {
        "success": True,
        "urls_found": len(urls),
        "results": results
    }


# ── 快取層 ────────────────────────────────────────
CACHE_FILE = "security/outputs/url_cache.json"
CACHE_EXPIRE_HOURS = 24  # 快取有效期 24 小時

def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

def save_cache(cache):
    os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, ensure_ascii=False, indent=2)

def get_cached_result(url):
    cache = load_cache()
    if url in cache:
        cached_time = datetime.fromisoformat(cache[url]["cached_at"])
        age_hours = (datetime.now() - cached_time).seconds / 3600
        if age_hours < CACHE_EXPIRE_HOURS:
            print(f"  ▸ 使用快取結果（{age_hours:.1f} 小時前）")
            return cache[url]["result"]
    return None

def cache_result(url, result):
    cache = load_cache()
    cache[url] = {
        "cached_at": datetime.now().isoformat(),
        "result": result
    }
    save_cache(cache)

# ── 判斷是否需要沙盒 ──────────────────────────────
def should_use_sandbox(url_result):
    """
    根據第一層分析結果，決定是否觸發沙盒
    """
    score = url_result.get("total_score", 0)
    features = url_result.get("details", {}).get("url_features", {})
    whois = url_result.get("details", {}).get("whois", {})
    ssl = url_result.get("details", {}).get("ssl", {})
    blacklist = url_result.get("details", {}).get("blacklist", {})
    visual = url_result.get("details", {}).get("visual", {})

    # 直接跳過沙盒的條件
    if blacklist.get("blacklist_score", 0) >= 5:
        return False, "黑名單命中，直接判定"
    if score >= 8:
        return False, "分數過高，直接高風險"
    if score < 3 and not url_result.get("is_short_url"):
        return False, "分數過低且非短網址，直接低風險"

    # 觸發沙盒的條件
    reasons = []

    if url_result.get("is_short_url"):
        reasons.append("偵測到短網址")

    if visual.get("impersonation_detected") and score < 8:
        reasons.append("品牌仿冒但分數不夠高")

    if not ssl.get("ssl_valid") and blacklist.get("blacklist_score", 0) == 0:
        reasons.append("SSL 異常但未在黑名單")

    if whois.get("domain_age_days") is None or whois.get("is_new_domain"):
        reasons.append("WHOIS 查不到或域名過新")

    if 3 <= score <= 7:
        reasons.append(f"總分 {score} 在灰色地帶")

    if reasons:
        return True, reasons
    return False, "無明顯可疑特徵"

# ── 帶快取的分析 ──────────────────────────────────
def analyze_url_cached(url, use_virustotal=False, use_sandbox=True):
    """
    分析 URL，優先使用快取
    自動判斷是否需要沙盒分析
    """
    # 先查快取
    cached = get_cached_result(url)
    if cached:
        return cached

    # 第一層：URL 特徵分析
    from url_analyzer import analyze_url
    url_result = analyze_url(url, use_virustotal=use_virustotal)

    # 判斷是否需要沙盒
    if use_sandbox:
        need_sandbox, sandbox_reason = should_use_sandbox(url_result)

        if need_sandbox:
            print(f"\n  ▸ 觸發沙盒分析，原因：{sandbox_reason}")
            from sandbox_analyzer import analyze_url_with_sandbox
            result = analyze_url_with_sandbox(url, use_virustotal=use_virustotal)
        else:
            print(f"\n  ▸ 跳過沙盒：{sandbox_reason}")
            result = url_result
    else:
        result = url_result

    # 存入快取
    cache_result(url, result)
    return result


# ── 格式化輸出 ────────────────────────────────────
def format_result(result):
    """
    把分析結果格式化成人類可讀的文字
    """
    lines = []
    lines.append(f"URL：{result['url']}")

    if result.get("is_short_url"):
        lines.append(f"展開後：{result['final_url']}")
        if not result.get("fully_resolved"):
            lines.append("⚠️  短網址無法完全追蹤")

    lines.append(f"結果：{result['verdict']}")
    lines.append(f"風險分數：{result['total_score']}")

    if result.get("reasons"):
        lines.append("可疑原因：")
        for r in result["reasons"]:
            lines.append(f"  • {r}")

    return "\n".join(lines)


def format_batch_results(results):
    """
    批次結果的彙整摘要
    """
    high = [r for r in results if r.get("risk_level") == "high"]
    medium = [r for r in results if r.get("risk_level") == "medium"]
    low = [r for r in results if r.get("risk_level") == "low"]

    lines = []
    lines.append(f"\n{'='*50}")
    lines.append(f"分析完成：共 {len(results)} 個 URL")
    lines.append(f"🔴 高風險：{len(high)} 個")
    lines.append(f"🟡 中風險：{len(medium)} 個")
    lines.append(f"🟢 低風險：{len(low)} 個")

    if high:
        lines.append("\n高風險 URL：")
        for r in high:
            lines.append(f"  🔴 {r['url']}")
            if r.get("reasons"):
                lines.append(f"     原因：{r['reasons'][0]}")

    lines.append("="*50)
    return "\n".join(lines)


# ── 主程式 ────────────────────────────────────────
if __name__ == "__main__":
    print("NetLens Security Analyzer")
    print("="*50)
    print("1. 分析單一 URL")
    print("2. 批次分析（每行一個 URL）")
    print("3. 從文字中抽取並分析所有 URL")
    print("4. 分析 QR Code 圖片")
    print("="*50)

    choice = input("請選擇模式（1-4）：").strip()

    if choice == "1":
        url = input("請輸入 URL：").strip()
        result = analyze_url_cached(url)
        print(f"\n{format_result(result)}")

    elif choice == "2":
        print("請輸入 URL（每行一個，輸入空行結束）：")
        urls = []
        while True:
            line = input().strip()
            if not line:
                break
            urls.append(line)
        if urls:
            results = analyze_batch(urls)
            for r in results:
                print(f"\n{format_result(r)}")
                print("-"*40)
            print(format_batch_results(results))

    elif choice == "3":
        print("請貼入文字內容（輸入空行結束）：")
        lines = []
        while True:
            line = input()
            if not line:
                break
            lines.append(line)
        text = "\n".join(lines)
        result = analyze_text(text)
        if result["success"]:
            for r in result["results"]:
                print(f"\n{format_result(r)}")
                print("-"*40)
            print(format_batch_results(result["results"]))
        else:
            print(f"錯誤：{result['error']}")

    elif choice == "4":
        path = input("請輸入 QR Code 圖片路徑：").strip()
        result = analyze_qr(path)
        print(f"\n整體判斷：{result.get('overall_verdict', '分析失敗')}")
        if result["success"]:
            for r in result["results"]:
                print(f"\n類型：{r['type']}")
                print(f"內容：{r['content']}")
                print(f"結果：{r['analysis']['verdict']}")

    else:
        print("無效選擇")