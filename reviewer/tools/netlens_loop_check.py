# -*- coding: utf-8 -*-
"""
netlens_loop_check.py — 「寫→掃→修→重掃」迴圈的機械化守門員

每一輪呼叫本腳本掃描（指定的改動檔），它會：
  1. 用 scan.py 的完整管道（Semgrep + CodeBERT，v7v8_safe）掃描。
  2. 只把「✅ 確認漏洞且非低精確度類別」當作**阻擋迴圈**的 finding
     （CSRF/IDOR/權限/資料外洩/SSRF 這類低精確度類別與 🔍 disputed 只列為參考，不擋）。
  3. 跨輪比對（狀態存 dataset/.netlens_loop_state.json），輸出明確 verdict：
       CLEAN        阻擋類 finding = 0 → 迴圈完成
       CONTINUE     比上一輪變少 → 繼續修
       STOP_NOPROGRESS  修完卻沒變少 → 停止、交使用者（Claude 說修好但仍被報）
       STOP_OSCILLATION 冒出新規則的 finding → 停止、交使用者
       STOP_MAXITERS    達到輪數上限 → 停止、交使用者

用法：
  第一輪（開始新迴圈）：
    python tools/netlens_loop_check.py --reset <改動檔1> <改動檔2> ...
  之後每輪：
    python tools/netlens_loop_check.py <改動檔1> <改動檔2> ...
  收尾全掃（✅清零後的安全網）：
    python tools/netlens_loop_check.py --final <模組或專案目錄>

退出碼：0=CLEAN、10=CONTINUE、20=STOP_*（供腳本判斷；Claude 依印出的 verdict 行事）
"""
import argparse
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import scan
from scan import Scanner, LANG_EXT, SKIP_DIRS, LOW_TRUST_CATEGORIES

STATE = "dataset/.netlens_loop_state.json"
MAX_ITERS_DEFAULT = 4


def expand(targets):
    """把檔案/目錄展開成 (path, lang) 清單。"""
    out = []
    for t in targets:
        if os.path.isfile(t):
            ext = os.path.splitext(t)[1].lower()
            lang = next((l for l, e in LANG_EXT.items() if e == ext), None)
            if lang:
                out.append((t, lang))
        elif os.path.isdir(t):
            for root, dirs, names in os.walk(t):
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
                for n in names:
                    ext = os.path.splitext(n)[1].lower()
                    lang = next((l for l, e in LANG_EXT.items() if e == ext), None)
                    if lang:
                        out.append((os.path.join(root, n), lang))
    return out


def sig(f):
    """finding 簽章（不含行號，因每輪修改後行號會位移）：檔+規則+CWE。"""
    return f"{os.path.abspath(f['file'])}::{f.get('engine_rule','?')}::{f.get('engine_cwe','?')}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("targets", nargs="+")
    ap.add_argument("--reset", action="store_true", help="開始新迴圈（清狀態）")
    ap.add_argument("--final", action="store_true", help="收尾全掃（不比對、只報告）")
    ap.add_argument("--max-iters", type=int, default=MAX_ITERS_DEFAULT)
    args = ap.parse_args()

    files = expand(args.targets)
    if not files:
        print("verdict: ERROR　找不到可掃描的檔案（支援 .py/.js/.php/.java）")
        return 1

    try:
        scanner = Scanner(use_model=True)
    except Exception as e:
        print(f"verdict: ERROR　無法載入模型（本迴圈需在有模型的機器上跑）：{e}")
        return 1
    blocking, review = [], []
    for fp, lang in files:
        try:
            code = open(fp, encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        r = scanner.scan_code(code, lang, fp)
        for x in r.get("confirmed", []):
            if x.get("engine_category") in LOW_TRUST_CATEGORIES:
                review.append(x)          # 低精確度類別 → 只參考
            else:
                blocking.append(x)        # ✅ 高信心真漏洞 → 阻擋迴圈
        review.extend(r.get("disputed", []))

    count = len(blocking)
    cur_sigs = sorted({sig(f) for f in blocking})

    # ── 狀態 ──
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    st = {}
    if os.path.exists(STATE) and not args.reset:
        try:
            st = json.load(open(STATE, encoding="utf-8"))
        except Exception:
            st = {}
    # targets 換了視為新迴圈
    tgt_key = hashlib.md5(",".join(sorted(os.path.abspath(t) for t in args.targets)).encode()).hexdigest()
    if st.get("tgt_key") != tgt_key:
        st = {}
    it = st.get("iteration", 0) + 1
    prev_count = st.get("prev_count")
    prev_sigs = set(st.get("sigs", []))

    # ── verdict ──
    if args.final:
        verdict = "FINAL_CLEAN" if count == 0 else "FINAL_FINDINGS"
    elif count == 0:
        verdict = "CLEAN"
    elif it > args.max_iters:
        verdict = "STOP_MAXITERS"
    elif prev_count is not None and set(cur_sigs) - prev_sigs and count >= prev_count:
        verdict = "STOP_OSCILLATION"      # 沒變少且冒出新種類 → 修出新問題
    elif prev_count is not None and count >= prev_count:
        verdict = "STOP_NOPROGRESS"       # 修完卻沒變少
    else:
        verdict = "CONTINUE"

    if not args.final:
        json.dump({"tgt_key": tgt_key, "iteration": it,
                   "prev_count": count, "sigs": cur_sigs},
                  open(STATE, "w", encoding="utf-8"))

    # ── 輸出 ──
    print(f"verdict: {verdict}")
    print(f"iteration: {it}/{args.max_iters}　阻擋類(✅) finding: {count}"
          f"（上輪 {prev_count if prev_count is not None else '—'}）")
    if blocking:
        print("\n【需修正的確認漏洞 ✅】")
        for x in sorted(blocking, key=lambda z: (z['file'], z['line'])):
            print(f"  {x['file']}:{x['line']}  {x.get('model_name') or x.get('engine_category_zh')}"
                  f"（{x.get('engine_cwe')}）信心 {x.get('model_conf',0):.0%}　規則 {x.get('engine_rule','?').split('.')[-1]}")
    if review:
        print(f"\n【參考（不擋迴圈）🔍 低精確度/兩引擎不一致，共 {len(review)}】—— Claude 逐條判斷真偽，勿盲修")
        for x in sorted(review, key=lambda z: (z['file'], z['line']))[:15]:
            print(f"  {x['file']}:{x['line']}  規則:{x.get('engine_category_zh')} / 模型:{x.get('model_name','?')}")

    # ── 給 Claude 的行動指示 ──
    print("\n>>> ", end="")
    if verdict == "CLEAN":
        print("阻擋類漏洞已清零。建議對受影響模組跑一次 --final 收尾全掃，再結束。")
    elif verdict == "CONTINUE":
        print("修正上面的『確認漏洞』後，再次執行本腳本（不加 --reset）。逐條判斷真偽，誤報勿盲改。")
    elif verdict.startswith("STOP"):
        print("停止迴圈並交給使用者決定：Claude 已嘗試但漏洞未減少（可能是誤報或需人工判斷）。"
              "把上面清單與你的判斷（哪些是真漏洞、哪些疑為誤報）呈報給使用者。")
    elif verdict == "FINAL_CLEAN":
        print("收尾全掃亦無阻擋類漏洞。完成。")
    elif verdict == "FINAL_FINDINGS":
        print("收尾全掃發現跨檔漏洞（上面清單），回到修正流程或呈報使用者。")

    return {"CLEAN": 0, "CONTINUE": 10, "FINAL_CLEAN": 0}.get(verdict, 20)


if __name__ == "__main__":
    sys.exit(main())
