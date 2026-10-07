import os
import re
import time
import json
import hashlib
import requests
import whois
import validators
import tldextract
from datetime import datetime
from dotenv import load_dotenv
from update_blacklists import check_blacklists, update_all, needs_update

# 載入 .env
load_dotenv()
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
REURL_API_KEY = os.getenv("REURL_API_KEY")

# ── 已知釣魚特徵 ──────────────────────────────────
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "account", "secure",
    "update", "confirm", "banking", "paypal", "apple",
    "google", "microsoft", "amazon", "netflix", "password"
]

SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq",
    ".xyz", ".top", ".work", ".click"
]

LEGIT_DOMAINS = [
    "google.com", "facebook.com", "microsoft.com",
    "apple.com", "amazon.com", "paypal.com",
    "netflix.com", "twitter.com", "instagram.com",
    "youtube.com", "github.com", "wikipedia.org"
]

# ── 常見短網址服務清單 ────────────────────────────
SHORT_URL_DOMAINS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "short.link", "reurl.cc", "lihi.cc", "lihi1.cc",
    "pse.is", "pros.is", "0rz.tw", "isl.cc", "buff.ly",
    "rebrand.ly", "cutt.ly", "rb.gy", "shorturl.at"
]


# ── 短網址展開 ────────────────────────────────────
def expand_short_url(url, max_redirects=10):
    try:
        ext = tldextract.extract(url)
        full_domain = f"{ext.domain}.{ext.suffix}"

        is_short = any(full_domain == d or full_domain.endswith(f".{d}")
                       for d in SHORT_URL_DOMAINS)

        if not is_short:
            return {
                "is_short_url": False,
                "original_url": url,
                "final_url": url,
                "redirect_chain": [],
                "redirect_count": 0,
                "fully_resolved": True,
                "warning": None
            }

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "zh-TW,zh;q=0.9,en;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
        }

        # tinyurl preview 頁面處理
        if full_domain == "tinyurl.com" and "/preview/" in url:
            url = url.replace("/preview/", "/")

        # ── 通用 HTTP 重定向追蹤 ──────────────────
        response = requests.get(
            url,
            headers=headers,
            allow_redirects=True,
            timeout=10,
            stream=True
        )
        response.close()

        final_url = response.url
        redirect_chain = [url, final_url] if final_url != url else [url]

        # 檢查展開後是否還在短網址服務內
        final_ext = tldextract.extract(final_url)
        final_domain = f"{final_ext.domain}.{final_ext.suffix}"
        still_short = any(final_domain == d for d in SHORT_URL_DOMAINS)

        print(f"  ▸ 短網址展開：{url} → {final_url}")

        return {
            "is_short_url": True,
            "original_url": url,
            "final_url": final_url,
            "redirect_chain": redirect_chain,
            "redirect_count": len(redirect_chain) - 1,
            "fully_resolved": not still_short,
            "warning": "此短網址使用 JavaScript 重定向，無法完全追蹤目標網址" if still_short else None
        }

    except Exception as e:
        return {
            "is_short_url": False,
            "original_url": url,
            "final_url": url,
            "redirect_chain": [],
            "redirect_count": 0,
            "fully_resolved": False,
            "warning": str(e)
        }

# ── URL 特徵分析 ──────────────────────────────────
def analyze_url_features(url):
    features = {}
    score = 0

    ext = tldextract.extract(url)
    domain = ext.domain
    suffix = ext.suffix
    subdomain = ext.subdomain
    full_domain = f"{domain}.{suffix}"

    features["url_length"] = len(url)
    if len(url) > 75:
        score += 1
    if len(url) > 100:
        score += 1

    features["dash_count"] = url.count("-")
    features["at_count"] = url.count("@")
    if url.count("-") > 3:
        score += 1
    if url.count("@") > 0:
        score += 2

    subdomain_count = len(subdomain.split(".")) if subdomain else 0
    features["subdomain_count"] = subdomain_count
    if subdomain_count > 2:
        score += 1
    if subdomain_count > 4:
        score += 2

    url_lower = url.lower()
    ext2 = tldextract.extract(url)
    full_domain_check = f"{ext2.domain}.{ext2.suffix}"
    found_keywords = [
        kw for kw in SUSPICIOUS_KEYWORDS
        if kw in url_lower and full_domain_check not in LEGIT_DOMAINS
    ]
    features["suspicious_keywords"] = found_keywords
    score += len(found_keywords)

    features["suspicious_tld"] = any(
        url_lower.endswith(tld) or f".{suffix}" == tld
        for tld in SUSPICIOUS_TLDS
    )
    if features["suspicious_tld"]:
        score += 2

    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    features["has_ip"] = bool(re.search(ip_pattern, url))
    if features["has_ip"]:
        score += 3

    features["has_https"] = url.startswith("https://")
    if not features["has_https"]:
        score += 1

    for legit in LEGIT_DOMAINS:
        legit_name = legit.split(".")[0]
        if legit_name in url_lower and full_domain != legit:
            features["brand_impersonation"] = legit
            score += 3
            break
    else:
        features["brand_impersonation"] = None

    features["feature_score"] = score
    return features


# ── WHOIS 域名查詢 ────────────────────────────────
def check_domain_age(url):
    try:
        ext = tldextract.extract(url)
        domain = f"{ext.domain}.{ext.suffix}"
        w = whois.whois(domain)

        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date is None:
            return {
                "domain": domain,
                "creation_date": "無法取得",
                "domain_age_days": None,
                "is_new_domain": None,
                "whois_score": 1
            }

        age_days = (datetime.now() - creation_date).days

        return {
            "domain": domain,
            "creation_date": creation_date.strftime("%Y-%m-%d"),
            "domain_age_days": age_days,
            "is_new_domain": age_days < 30,
            "whois_score": 3 if age_days < 30 else (1 if age_days < 180 else 0)
        }

    except Exception as e:
        return {
            "domain": domain if 'domain' in locals() else "未知",
            "creation_date": "查詢失敗",
            "domain_age_days": None,
            "is_new_domain": None,
            "whois_score": 1
        }


# ── VirusTotal 查詢 ───────────────────────────────
def check_virustotal(url):
    if not VIRUSTOTAL_API_KEY:
        return {"error": "未設定 VIRUSTOTAL_API_KEY", "vt_score": 0}

    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}

        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=10
        )
        response.raise_for_status()
        analysis_id = response.json()["data"]["id"]

        for _ in range(5):
            time.sleep(3)
            result = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
                timeout=10
            )
            result.raise_for_status()
            data = result.json()["data"]

            if data["attributes"]["status"] == "completed":
                stats = data["attributes"]["stats"]
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total = sum(stats.values())

                return {
                    "malicious_count": malicious,
                    "suspicious_count": suspicious,
                    "total_engines": total,
                    "vt_score": 5 if malicious > 3 else (3 if malicious > 0 else (1 if suspicious > 0 else 0)),
                    "vt_detail": stats
                }

        return {"error": "掃描逾時", "vt_score": 0}

    except Exception as e:
        return {"error": str(e), "vt_score": 0}


# ── 視覺仿冒偵測 ──────────────────────────────────
def check_visual_impersonation(url):
    ext = tldextract.extract(url)
    full_domain = f"{ext.domain}.{ext.suffix}"
    url_lower = url.lower()

    brand_map = {
        "google": "google.com",
        "gmail": "google.com",
        "facebook": "facebook.com",
        "fb": "facebook.com",
        "instagram": "instagram.com",
        "apple": "apple.com",
        "icloud": "apple.com",
        "microsoft": "microsoft.com",
        "outlook": "microsoft.com",
        "office": "microsoft.com",
        "amazon": "amazon.com",
        "aws": "amazon.com",
        "paypal": "paypal.com",
        "netflix": "netflix.com",
        "twitter": "twitter.com",
        "line": "line.me",
        "yahoo": "yahoo.com",
    }

    impersonation_results = []

    for brand, legit_domain in brand_map.items():
        if brand in url_lower and full_domain != legit_domain:
            if not full_domain.endswith(legit_domain) and brand not in full_domain:
                impersonation_results.append({
                    "brand": brand,
                    "legit_domain": legit_domain,
                    "actual_domain": full_domain
                })

    visual_score = min(len(impersonation_results) * 3, 6)

    return {
        "impersonation_detected": len(impersonation_results) > 0,
        "impersonation_targets": impersonation_results,
        "visual_score": visual_score
    }


# ── SSL 憑證檢查 ──────────────────────────────────
def check_ssl(url):
    try:
        import ssl
        import socket
        from urllib.parse import urlparse

        parsed = urlparse(url)
        hostname = parsed.hostname

        if not hostname:
            return {"ssl_valid": False, "ssl_score": 1}

        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                expire_date = datetime.strptime(
                    cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
                )
                days_until_expire = (expire_date - datetime.now()).days

                return {
                    "ssl_valid": True,
                    "ssl_expire_date": expire_date.strftime("%Y-%m-%d"),
                    "days_until_expire": days_until_expire,
                    "ssl_score": 0
                }

    except ssl.SSLCertVerificationError:
        return {"ssl_valid": False, "ssl_error": "憑證驗證失敗", "ssl_score": 3}
    except Exception:
        return {"ssl_valid": False, "ssl_error": "無法連線", "ssl_score": 1}


# ── 整合分析 ──────────────────────────────────────
def analyze_url(url, use_virustotal=False):
    print(f"\n分析 URL：{url}")

    if not validators.url(url):
        return {
            "url": url,
            "verdict": "❌ 無效 URL",
            "risk_level": "error",
            "total_score": 0,
            "details": {}
        }

    # 短網址展開
    expand_result = expand_short_url(url)
    analysis_url = expand_result["final_url"]
    if expand_result["is_short_url"]:
        print(f"  ▸ 偵測到短網址，展開後分析：{analysis_url}")

    results = {}
    if needs_update("openphish") or needs_update("urlhaus"):
        print("  ▸ 黑名單過期，自動更新...")
        update_all()

    # 查詢黑名單
    print("  ▸ 查詢黑名單...")
    results["blacklist"] = check_blacklists(analysis_url)

    print("  ▸ 分析 URL 特徵...")
    results["url_features"] = analyze_url_features(analysis_url)

    print("  ▸ 查詢 WHOIS...")
    results["whois"] = check_domain_age(analysis_url)

    print("  ▸ 檢查品牌仿冒...")
    results["visual"] = check_visual_impersonation(analysis_url)

    print("  ▸ 驗證 SSL 憑證...")
    results["ssl"] = check_ssl(analysis_url)

    if use_virustotal:
        print("  ▸ 查詢 VirusTotal...")
        results["virustotal"] = check_virustotal(analysis_url)
    else:
        results["virustotal"] = {"vt_score": 0, "skipped": True}

    total_score = (
        results["url_features"]["feature_score"] +
        results["whois"].get("whois_score", 0) +
        results["visual"]["visual_score"] +
        results["ssl"].get("ssl_score", 0) +
        results["virustotal"].get("vt_score", 0) +
        results["blacklist"].get("blacklist_score", 0)
    )

    if results["virustotal"].get("malicious_count", 0) > 3:
        risk_level = "high"
        verdict = "🔴  高風險：已知惡意網址"
    elif total_score >= 8:
        risk_level = "high"
        verdict = "🔴  高風險：多項可疑特徵"
    elif total_score >= 4:
        risk_level = "medium"
        verdict = "🟡  中風險：部分可疑特徵，建議謹慎"
    else:
        risk_level = "low"
        verdict = "🟢  低風險：未發現明顯威脅"

    reasons = []
    f = results["url_features"]
    if expand_result["is_short_url"]:
        if expand_result.get("warning"):
            reasons.append(f"⚠️ {expand_result['warning']}")
        else:
            reasons.append(f"短網址展開後目的地：{analysis_url}")
    if f.get("has_ip"):
        reasons.append("URL 使用 IP 位址直連")
    if f.get("at_count", 0) > 0:
        reasons.append("URL 含有 @ 符號（常見釣魚手法）")
    if f.get("brand_impersonation"):
        reasons.append(f"仿冒品牌：{f['brand_impersonation']}")
    if f.get("suspicious_tld"):
        reasons.append("使用可疑頂級域名")
    if f.get("suspicious_keywords"):
        reasons.append(f"包含可疑關鍵字：{', '.join(f['suspicious_keywords'][:3])}")
    if results["whois"].get("is_new_domain"):
        reasons.append(f"新註冊域名（{results['whois']['domain_age_days']} 天前）")
    if results["visual"]["impersonation_detected"]:
        for t in results["visual"]["impersonation_targets"]:
            reasons.append(f"疑似仿冒 {t['brand']}（官方域名：{t['legit_domain']}）")
    if not results["ssl"].get("ssl_valid"):
        reasons.append("SSL 憑證無效或無法驗證")
    if results["virustotal"].get("malicious_count", 0) > 0:
        reasons.append(f"VirusTotal：{results['virustotal']['malicious_count']} 個引擎標記為惡意")
    if results["blacklist"].get("in_openphish"):
        reasons.append("⛔ 已列入 OpenPhish 釣魚黑名單")
    if results["blacklist"].get("in_urlhaus"):
        reasons.append("⛔ 已列入 URLhaus 惡意網址黑名單")
    if results["blacklist"].get("in_abusech"):
        reasons.append("⛔ IP 已列入 Abuse.ch 惡意 IP 黑名單")

    return {
        "url": url,
        "final_url": analysis_url,
        "is_short_url": expand_result["is_short_url"],
        "fully_resolved": expand_result.get("fully_resolved", True),
        "redirect_chain": expand_result.get("redirect_chain", []),
        "verdict": verdict,
        "risk_level": risk_level,
        "total_score": total_score,
        "reasons": reasons,
        "details": results
    }


# ── 主程式 ────────────────────────────────────────
if __name__ == "__main__":
    test_urls = [
        "https://reurl.cc/zQL7re",
        
    ]

    for url in test_urls:
        result = analyze_url(url, use_virustotal=False)
        print(f"\n{'='*50}")
        print(f"URL：{result['url']}")
        if result.get("is_short_url"):
            print(f"展開後：{result['final_url']}")
            if not result.get("fully_resolved"):
                print("⚠️  無法完全追蹤")
        print(f"結果：{result['verdict']}")
        print(f"總分：{result['total_score']}")
        if result.get("reasons"):
            print("可疑原因：")
            for r in result["reasons"]:
                print(f"  • {r}")
        print('='*50)