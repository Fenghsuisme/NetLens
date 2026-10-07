# -*- coding: utf-8 -*-
"""
core/mcp_api.py — NetLens 混合漏洞檢測器 MCP API 門戶
(路徑：C:/netlens/NetLens/reviewer/core/mcp_api.py)
"""
import os
import sys
from mcp.server.fastmcp import FastMCP

# ── 自動對齊根路徑 ──────────────────
_CORE_DIR = os.path.dirname(os.path.abspath(__file__))
_REVIEWER_ROOT = os.path.dirname(_CORE_DIR)

if _REVIEWER_ROOT not in sys.path:
    sys.path.insert(0, _REVIEWER_ROOT)

# 引入同目錄下的 analyzer 核心分析函數
try:
    from core.analyzer import analyze_code
    HAS_ANALYZER = True
except ImportError as e:
    print(f"  [MCP Server Error] 載入 core.analyzer 失敗: {e}")
    HAS_ANALYZER = False

# 初始化 FastMCP 服務
mcp = FastMCP("NetLens-Hybrid-Scanner")

# ── 最終修正：對接 FastMCP 內建的 SSE 網路應用程式 ──
app = mcp.sse_app


@mcp.tool()
def scan_code(code_content: str, file_name: str = "code.php", use_codebert: bool = True) -> dict:
    """
    接收程式碼，同時驅動黑名單套件掃描、Semgrep 靜態規則以及 CodeBERT 語意模型進行複合分析，
    並透過融合層（core/fusion.py）過濾誤報、對齊 CWE，最終回傳整合後的結構化 ScanReport。
    """
    if not HAS_ANALYZER:
        return {
            "status": "error",
            "message": "無法載入核心分析模組 (core.analyzer)，請檢查目錄結構或虛擬環境相依性。"
        }
        
    try:
        # 直接呼叫同目錄下 analyzer.py 的對外介面
        report = analyze_code(code_content, file_path=file_name, use_codebert=use_codebert)
        return report
        
    except Exception as e:
        return {
            "status": "error",
            "message": f"檢測器執行期間發生未預期錯誤: {str(e)}"
        }


if __name__ == "__main__":
    mcp.run()