import os
import sys
import re
import json
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout

# ── 沙盒分析 ──────────────────────────────────────
def sandbox_analyze(url, timeout=10000):
    """
    用隔離的無頭瀏覽器分析 URL
    - 追蹤所有重定向（包含 JavaScript）
    - 收集頁面資訊
    - 偵測可疑行為
    瀏覽器用完即關，不留任何狀態
    """
    result = {
        "url": url,
        "final_url": url,
        "redirect_chain": [url],
        "redirect_count": 0,
        "page_title": None,
        "has_password_field": False,
        "has_login_form": False,
        "external_scripts": [],
        "suspicious_behaviors": [],
        "sandbox_score": 0,
        "success": False,
        "error": None
    }

    try:
        with sync_playwright() as p:
            # 啟動隔離的 Chromium
            browser = p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--disable-extensions",
                ]
            )

            # 建立隔離的 context（無 cookie、無登入狀態）
            context = browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                java_script_enabled=True,
                accept_downloads=False,  # 禁止下載
            )

            page = context.new_page()

            # 追蹤重定向鏈
            redirect_chain = [url]
            def on_response(response):
                if response.status in (301, 302, 303, 307, 308):
                    location = response.headers.get("location", "")
                    if location and location not in redirect_chain:
                        redirect_chain.append(location)

            page.on("response", on_response)

            # 收集外部腳本
            external_scripts = []
            def on_request(request):
                if request.resource_type == "script":
                    script_url = request.url
                    if url not in script_url:
                        external_scripts.append(script_url)

            page.on("request", on_request)

            # 前往目標網址
            print(f"  ▸ 沙盒啟動，訪問：{url}")
            try:
                page.goto(url, wait_until="networkidle", timeout=timeout)
            except PlaywrightTimeout:
                print(f"  ▸ 頁面載入逾時，取得目前狀態")

            # 取得最終 URL
            final_url = page.url
            if final_url not in redirect_chain:
                redirect_chain.append(final_url)

            # 取得頁面標題
            page_title = page.title()

            # 偵測密碼欄位
            password_fields = page.query_selector_all('input[type="password"]')
            has_password_field = len(password_fields) > 0

            # 偵測登入表單
            login_forms = page.query_selector_all('form')
            has_login_form = False
            for form in login_forms:
                form_html = form.inner_html().lower()
                if any(kw in form_html for kw in ["password", "login", "signin", "email", "username"]):
                    has_login_form = True
                    break

            # 偵測可疑行為
            suspicious_behaviors = []
            score = 0

            # 1. 最終 URL 和原始 URL 不同（重定向）
            if final_url != url:
                print(f"  ▸ 重定向到：{final_url}")
                result["redirect_count"] = len(redirect_chain) - 1

            # 2. 有密碼欄位但域名可疑
            if has_password_field:
                suspicious_behaviors.append("頁面含有密碼輸入欄位")
                score += 2

            # 3. 有登入表單
            if has_login_form:
                suspicious_behaviors.append("頁面含有登入表單")
                score += 1

            # 4. 外部腳本過多
            if len(external_scripts) > 10:
                suspicious_behaviors.append(f"載入大量外部腳本（{len(external_scripts)} 個）")
                score += 1

            # 5. 頁面標題含可疑關鍵字
            if page_title:
                title_lower = page_title.lower()
                suspicious_title_keywords = [
                    "verify", "login", "signin", "secure", "account",
                    "update", "confirm", "alert", "warning"
                ]
                found = [kw for kw in suspicious_title_keywords if kw in title_lower]
                if found:
                    suspicious_behaviors.append(f"頁面標題含可疑關鍵字：{', '.join(found)}")
                    score += len(found)

            # 6. JS 檢測
            js_threats = []

            # 取得頁面所有 script 內容
            scripts = page.evaluate("""() => {
                return Array.from(document.querySelectorAll('script'))
                    .map(s => s.innerText)
                    .filter(s => s.length > 0)
            }""")

            for script_content in scripts:
                s = script_content.lower()

                # 混淆程式碼特徵
                if script_content.count('\\x') > 20:
                    js_threats.append("偵測到 Hex 編碼混淆程式碼")
                if 'eval(' in s and ('atob(' in s or 'fromcharcode' in s):
                    js_threats.append("偵測到 eval + 解碼組合（常見惡意手法）")
                if s.count('\\u00') > 10:
                    js_threats.append("偵測到 Unicode 混淆程式碼")

                # Credential harvesting
                if 'document.forms' in s and ('submit' in s or 'onsubmit' in s):
                    if 'fetch(' in s or 'xmlhttprequest' in s or 'axios' in s:
                        js_threats.append("偵測到表單資料可能被攔截送出")

                # Crypto miner 特徵
                if any(kw in s for kw in ['coinhive', 'cryptonight', 'stratum+tcp', 'monero']):
                    js_threats.append("偵測到加密貨幣挖礦腳本")

                # 強制跳轉
                if s.count('window.location') > 3:
                    js_threats.append("偵測到多次強制跳轉")

                # Prompt Injection 隱藏指令
                pi_keywords = [
                    'ignore previous instructions',
                    'ignore all instructions',
                    'you are now',
                    'disregard previous',
                    'forget previous instructions',
                    'system prompt',
                    'jailbreak'
                ]
                found_pi = [kw for kw in pi_keywords if kw in s]
                if found_pi:
                    js_threats.append(f"偵測到 Prompt Injection 嘗試：{found_pi[0]}")

            # 同時檢查 HTML 裡的隱藏 Prompt Injection
            html_content = page.content().lower()
            pi_in_html = [kw for kw in [
                'ignore previous instructions',
                'ignore all instructions',
                'you are now an ai',
                'disregard previous',
            ] if kw in html_content]
            if pi_in_html:
                js_threats.append(f"HTML 中偵測到 Prompt Injection 嘗試")

            # 白色/隱藏文字偵測（常見 Prompt Injection 手法）
            hidden_text = page.evaluate("""() => {
                const elements = document.querySelectorAll('*');
                const hidden = [];
                for (const el of elements) {
                    const style = window.getComputedStyle(el);
                    const text = el.innerText || '';
                    if (text.length > 20) {
                        if (style.color === style.backgroundColor ||
                            style.fontSize === '0px' ||
                            style.opacity === '0' ||
                            style.visibility === 'hidden') {
                            hidden.push(text.substring(0, 50));
                        }
                    }
                }
                return hidden;
            }""")
            if hidden_text:
                js_threats.append(f"偵測到隱藏文字（可能為 Prompt Injection）")

            # 加進可疑行為和分數
            for threat in js_threats:
                suspicious_behaviors.append(threat)
                score += 2

            # 關閉瀏覽器（隔離結束）
            context.close()
            browser.close()
            print(f"  ▸ 沙盒關閉")

            result.update({
                "final_url": final_url,
                "redirect_chain": redirect_chain,
                "redirect_count": len(redirect_chain) - 1,
                "page_title": page_title,
                "has_password_field": has_password_field,
                "has_login_form": has_login_form,
                "external_scripts": external_scripts[:10],
                "js_threats": js_threats,
                "suspicious_behaviors": suspicious_behaviors,
                "sandbox_score": score,
                "success": True
            })

    except Exception as e:
        result["error"] = str(e)
        result["success"] = False
        print(f"  ▸ 沙盒分析失敗：{e}")

    return result


# ── 整合到 URL 分析 ───────────────────────────────
def analyze_url_with_sandbox(url, use_virustotal=False):
    """
    結合 url_analyzer 和沙盒分析的完整分析
    """
    from url_analyzer import analyze_url

    print(f"\n{'='*50}")
    print(f"完整分析：{url}")
    print(f"{'='*50}")

    # 第一層：快速 URL 特徵分析
    print("\n【第一層：URL 特徵分析】")
    url_result = analyze_url(url, use_virustotal=use_virustotal)

    # 第二層：沙盒分析（追蹤 JS 重定向 + 頁面行為）
    print("\n【第二層：沙盒分析】")
    sandbox_result = sandbox_analyze(url)

    # 整合分數
    total_score = url_result.get("total_score", 0) + sandbox_result.get("sandbox_score", 0)

    # 更新最終 URL（沙盒追蹤到的才是真正目的地）
    if sandbox_result["success"] and sandbox_result["final_url"] != url:
        final_url = sandbox_result["final_url"]
        redirect_chain = sandbox_result["redirect_chain"]
    else:
        final_url = url_result.get("final_url", url)
        redirect_chain = url_result.get("redirect_chain", [])

    # 整合可疑原因
    # 如果沙盒成功追蹤到最終 URL，移除「無法追蹤」的警告
    url_reasons = url_result.get("reasons", [])
    if sandbox_result["success"] and sandbox_result["final_url"] != url:
        url_reasons = [r for r in url_reasons if "JavaScript 重定向" not in r]

    reasons = url_reasons + sandbox_result.get("suspicious_behaviors", [])

    # 判斷風險等級
    if total_score >= 10:
        risk_level = "high"
        verdict = "🔴  高風險：多項可疑特徵"
    elif total_score >= 5:
        risk_level = "medium"
        verdict = "🟡  中風險：部分可疑特徵，建議謹慎"
    else:
        risk_level = "low"
        verdict = "🟢  低風險：未發現明顯威脅"

    return {
        "url": url,
        "final_url": final_url,
        "redirect_chain": redirect_chain,
        "verdict": verdict,
        "risk_level": risk_level,
        "total_score": total_score,
        "url_score": url_result.get("total_score", 0),
        "sandbox_score": sandbox_result.get("sandbox_score", 0),
        "reasons": reasons,
        "page_title": sandbox_result.get("page_title"),
        "has_password_field": sandbox_result.get("has_password_field"),
        "has_login_form": sandbox_result.get("has_login_form"),
        "sandbox_success": sandbox_result["success"],
        "url_details": url_result,
        "sandbox_details": sandbox_result
    }

# ── 主程式 ────────────────────────────────────────
if __name__ == "__main__":
    test_urls = [
        "https://reurl.cc/zQL7re",
        "https://google-account-verify.xyz/login",
        "https://byte-network-hub.christmas/821b5c8e-31ec-4d56-96d8-d0348ba7d3f3/g.ch",
    ]

    for url in test_urls:
        result = analyze_url_with_sandbox(url)
        print(f"\n{'='*50}")
        print(f"URL：{result['url']}")
        print(f"最終目的地：{result['final_url']}")
        if len(result['redirect_chain']) > 1:
            print(f"重定向鏈：{' → '.join(result['redirect_chain'])}")
        print(f"頁面標題：{result['page_title']}")
        print(f"結果：{result['verdict']}")
        print(f"總分：{result['total_score']}（URL:{result['url_score']} + 沙盒:{result['sandbox_score']}）")
        if result["reasons"]:
            print("可疑原因：")
            for r in result["reasons"]:
                print(f"  • {r}")
        print('='*50)