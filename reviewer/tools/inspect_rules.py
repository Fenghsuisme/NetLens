# -*- coding: utf-8 -*-
"""看一條規則的完整內容 + 實際跑一次看 finding 的 JSON 結構"""
import yaml, json, subprocess, tempfile, os

os.environ["PYTHONUTF8"] = "1"

# 讀 python.yml 裡的 sql-injection 規則
data = yaml.safe_load(open("rules/python.yml", encoding="utf-8"))
for r in data.get("rules", []):
    if r.get("id") == "sql-injection":
        print("═══ sql-injection 規則內容 ═══")
        print(yaml.dump(r, allow_unicode=True, sort_keys=False)[:1500])
        # 判斷模式類型
        keys = str(r.keys())
        if "taint" in yaml.dump(r) or "pattern-sources" in yaml.dump(r):
            print("\n>>> 這是 TAINT 模式（有資料流追蹤）")
        else:
            print("\n>>> 這是 PATTERN 模式（直接比對）")
        break

# 實際跑一段有 SQL 注入的測試碼，看 finding 結構
test_code = '''import sqlite3

def get_user(request):
    user_id = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id=" + user_id
    cursor.execute(query)
    return cursor.fetchall()
'''

with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8") as f:
    f.write(test_code)
    tmp = f.name
out = tmp + ".json"

try:
    subprocess.run(["semgrep", "--config", "rules/python.yml", "--no-git-ignore",
                    "--json", "--quiet", "--output", out, tmp],
                   capture_output=True, timeout=60)
    if os.path.exists(out):
        data = json.load(open(out, encoding="utf-8"))
        results = data.get("results", [])
        print(f"\n═══ 實際掃描結果：{len(results)} 個 finding ═══")
        for res in results[:2]:
            print(f"\n規則：{res.get('check_id')}")
            print(f"  start line: {res.get('start',{}).get('line')}")
            print(f"  end line:   {res.get('end',{}).get('line')}")
            extra = res.get("extra", {})
            print(f"  message: {extra.get('message','')[:80]}")
            # 關鍵：有沒有 dataflow_trace（taint 模式才有）
            if "dataflow_trace" in extra:
                print("  ★ 有 dataflow_trace（taint 模式，含 source/sink 位置）")
                dft = extra["dataflow_trace"]
                print(f"     結構：{json.dumps(dft, indent=2)[:600]}")
            else:
                print("  （無 dataflow_trace，單一區塊）")
except Exception as e:
    print(f"執行失敗：{e}")
finally:
    for p in (tmp, out):
        if os.path.exists(p): os.unlink(p)