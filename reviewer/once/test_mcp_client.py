# -*- coding: utf-8 -*-
"""
test_code/test_mcp_client.py — 測試跨網路呼叫 MCP 服務
"""
import asyncio
from mcp import ClientSession
from mcp.client.sse import sse_client

async def test_run():
    print("🌐 正在連線至本機 MCP SSE 伺服器...")
    
    # 建立標準的 MCP SSE 網路連線
    async with sse_client("http://localhost:8080/sse") as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            # 1. 握手初始化
            await session.initialize()
            print("✅ 連線成功！正在獲取工具清單...")
            
            # 2. 獲取工具清單（這會代替你原本想敲網址看到的畫面）
            tools_list = await session.list_tools()
            print("\n==== 🎯 伺服器提供的工具清單 ====")
            print(tools_list)
            print("================================\n")
            
            # 3. 發送一段測試程式碼讓遠端 core.analyzer 去跑
            print("🔍 正在發送測試程式碼進行混合漏洞掃描...")
            test_php_code = "<?php $cmd = $_POST['cmd']; system($cmd); ?>"
            
            result = await session.call_tool(
                "scan_code", 
                arguments={
                    "code_content": test_php_code,
                    "file_name": "test_webshell.php",
                    "use_codebert": True
                }
            )
            print("\n==== 📊 漏洞融合分析報告 (ScanReport) ====")
            print(result)
            print("==========================================")

if __name__ == "__main__":
    asyncio.run(test_run())