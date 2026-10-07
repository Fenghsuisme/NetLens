# -*- coding: utf-8 -*-
"""檢視測試檔的實際格式，找出解析失敗的原因"""
import re

TEST_FILE = "test_code/real_test/security_training_dataset_v1.txt"
content = open(TEST_FILE, encoding="utf-8").read()

print(f"檔案總長度：{len(content)} 字元")
print(f"總行數：{len(content.splitlines())}\n")

# 各種標記的出現次數
markers = {
    "---SPLIT---": content.count("---SPLIT---"),
    "###LABEL:": content.count("###LABEL:"),
    "###LANG:": content.count("###LANG:"),
    "###DESC:": content.count("###DESC:"),
    "```（總數）": content.count("```"),
}
print("標記統計：")
for k, v in markers.items():
    print(f"  {k:<16} {v}")

blocks = content.split("---SPLIT---")
print(f"\n用 ---SPLIT--- 切出：{len(blocks)} 段")

# 逐段檢查為何失敗
ok = no_label = no_code = short_code = 0
fail_samples = []
for i, b in enumerate(blocks):
    b = b.strip()
    if not b:
        continue
    has_label = bool(re.search(r"###LABEL:(\S+)", b))
    m = re.search(r"```\w*\n(.*?)```", b, re.DOTALL)
    if not has_label:
        no_label += 1
        if len(fail_samples) < 3:
            fail_samples.append(("無LABEL", i, b[:200]))
        continue
    if not m:
        no_code += 1
        if len(fail_samples) < 6:
            fail_samples.append(("無程式碼區塊", i, b[:300]))
        continue
    if len(m.group(1).strip()) < 30:
        short_code += 1
        continue
    ok += 1

print(f"\n解析結果：")
print(f"  成功         {ok}")
print(f"  無 ###LABEL   {no_label}")
print(f"  無程式碼區塊    {no_code}")
print(f"  程式碼過短     {short_code}")

if fail_samples:
    print(f"\n失敗樣本（前幾筆）：")
    for reason, idx, snippet in fail_samples:
        print(f"\n  ── 段 {idx}：{reason} ──")
        for ln in snippet.split("\n")[:10]:
            print(f"     {ln[:90]}")

# 印出第一段完整內容當參考
print("\n" + "=" * 70)
print("第一段完整內容（供確認格式）")
print("=" * 70)
first = next((b.strip() for b in blocks if b.strip()), "")
print(first[:800])