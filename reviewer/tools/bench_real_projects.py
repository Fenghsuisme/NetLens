# -*- coding: utf-8 -*-
"""
bench_real_projects.py — 對多個真實專案跑完整管道（Semgrep + CodeBERT），
量「使用者實際看到的噪音密度」並寫成持久紀錄檔（專案之後可刪，紀錄仍在）。

特點：
  - 模型只載入一次，逐專案掃描（省去每專案重載）。
  - 每專案掃描檔數上限 --max-files（預設 1000，比 scan.py 的 500 高）；
    超過則以固定 seed 隨機抽樣，紀錄「掃描檔/總檔」讓密度誠實。
  - 輸出 markdown：每專案一列 + 總表 + 各專案前幾名觸發規則。

用法（在 reviewer/ 根目錄、有模型的機器上）：
    python tools/bench_real_projects.py /path/proj1 /path/proj2 ...
    python tools/bench_real_projects.py --max-files 2000 /path/*/
    python tools/bench_real_projects.py --no-official /path/proj      # 離線（不載官方規則）

紀錄檔預設：dataset/bench_real_projects_<日期>.md
"""
import argparse
import os
import random
import re
import sys
import time
from collections import Counter
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import scan
from scan import Scanner, LANG_EXT, SKIP_DIRS

# 除了 scan.SKIP_DIRS，再跳過「非產品碼」目錄（測試/範例/文件/生成資產）——
# 這些對「真實碼噪音」不具代表性，且 fixture 本身就是噪音來源。
BENCH_SKIP_DIRS = set(SKIP_DIRS) | {
    "test", "tests", "__tests__", "spec", "specs", "e2e", "cypress",
    "examples", "example", "samples", "demo", "docs", "doc",
    "public", "static", "assets", "coverage", "fixtures", "stories",
    "locale", "locales", "i18n", "translations", "storybook",
}
# 生成/壓縮/第三方檔名（semgrep 在這些上又慢又沒意義）
GENERATED_RE = re.compile(
    r"(\.min\.|\.bundle\.|[-.]bundle|\.map$|\.generated\.|\.d\.ts$|"
    r"vendor|polyfill|jquery|bootstrap|chunk[-.])", re.I)
MAX_FILE_BYTES = 200_000     # 超過多半是壓縮/生成檔，跳過


def collect(path, cap, seed=42):
    """收集專案內受支援語言的『產品碼』檔；超過 cap 則隨機抽樣。回傳 (files, total)。"""
    all_files = []
    if os.path.isfile(path):
        ext = os.path.splitext(path)[1].lower()
        lang = next((l for l, e in LANG_EXT.items() if e == ext), None)
        return ([(path, lang)] if lang else []), (1 if lang else 0)
    for root, dirs, names in os.walk(path):
        dirs[:] = [d for d in dirs
                   if d.lower() not in BENCH_SKIP_DIRS and not d.startswith(".")]
        for n in names:
            ext = os.path.splitext(n)[1].lower()
            lang = next((l for l, e in LANG_EXT.items() if e == ext), None)
            if not lang:
                continue
            if GENERATED_RE.search(n):
                continue
            fp = os.path.join(root, n)
            try:
                if os.path.getsize(fp) > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            all_files.append((fp, lang))
    total = len(all_files)
    if total > cap:
        random.seed(seed)
        all_files = random.sample(all_files, cap)
    return all_files, total


def loc_of(fp):
    try:
        with open(fp, encoding="utf-8", errors="ignore") as f:
            return sum(1 for _ in f)
    except Exception:
        return 0


def scan_project(scanner, path, cap):
    t_scan = time.time()
    files, total = collect(path, cap)
    v = Counter()          # confirmed / disputed / filtered / engine_only
    rules = Counter()      # 呈現(confirmed+disputed) 的規則
    cats = Counter()
    loc = 0
    for i, (fp, lang) in enumerate(files, 1):
        try:
            code = open(fp, encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        loc += code.count("\n") + 1
        try:
            r = scanner.scan_code(code, lang, fp)
        except Exception:
            continue
        for k in ("confirmed", "disputed", "filtered", "engine_only"):
            v[k] += len(r.get(k, []))
        for it in r.get("confirmed", []) + r.get("disputed", []):
            rule = it.get("engine_rule") or it.get("rule") or "?"
            rules[rule.split(".")[-1]] += 1
            cats[it.get("engine_category_zh") or "?"] += 1
        if i % 100 == 0:
            print(f"    {i}/{len(files)}", flush=True)
    return {
        "name": os.path.basename(os.path.normpath(path)),
        "scanned": len(files), "total": total, "loc": loc,
        "v": v, "rules": rules, "cats": cats,
        "secs": time.time() - t_scan,
    }


def fmt_project(r):
    shown = r["v"]["confirmed"] + r["v"]["disputed"]
    kloc = max(r["loc"], 1) / 1000
    model_judged = r["v"]["filtered"] + shown
    filt_rate = (r["v"]["filtered"] / model_judged * 100) if model_judged else 0
    return (r["name"], r["scanned"], r["total"], r["loc"],
            r["v"]["confirmed"], r["v"]["disputed"], r["v"]["filtered"],
            shown / kloc, filt_rate)


def main():
    ap = argparse.ArgumentParser(description="真實專案完整管道噪音基準")
    ap.add_argument("projects", nargs="+", help="專案目錄")
    ap.add_argument("--max-files", type=int, default=800,
                    help="每專案掃描檔數上限（超過隨機抽樣，預設 800）")
    ap.add_argument("--with-official", action="store_true",
                    help="加入官方 p/security-audit（逐檔載入數百條規則、極慢，預設關閉）")
    ap.add_argument("--out", help="紀錄檔路徑（預設 dataset/bench_real_projects_<日期>.md）")
    args = ap.parse_args()

    out = args.out or f"dataset/bench_real_projects_{datetime.now():%Y%m%d_%H%M}.md"
    os.makedirs(os.path.dirname(out), exist_ok=True)

    print("載入模型（僅一次）...")
    t_load = time.time()
    scanner = Scanner(use_model=True, with_official=args.with_official)
    load_secs = time.time() - t_load

    results = []
    t0 = time.time()
    for p in args.projects:
        if not os.path.isdir(p) and not os.path.isfile(p):
            print(f"⚠️ 跳過（找不到）：{p}")
            continue
        print(f"\n掃描 {p} ...", flush=True)
        results.append(scan_project(scanner, p, args.max_files))

    # ── 彙總 ──
    agg = Counter()
    agg_rules = Counter()
    tot_loc = tot_shown = tot_files = tot_scan_secs = 0
    for r in results:
        for k, n in r["v"].items():
            agg[k] += n
        agg_rules += r["rules"]
        tot_loc += r["loc"]
        tot_files += r["scanned"]
        tot_scan_secs += r["secs"]
        tot_shown += r["v"]["confirmed"] + r["v"]["disputed"]

    lines = []
    lines.append(f"# 真實專案噪音基準　{datetime.now():%Y-%m-%d %H:%M}")
    lines.append("")
    lines.append(f"- 管道：scan.py（Semgrep 自訂+補強{'＋官方' if args.with_official else '（未含官方）'} + CodeBERT）")
    lines.append(f"- 每專案掃描上限：{args.max_files} 檔（超過以 seed=42 隨機抽樣）")
    lines.append(f"- 已排除：測試/範例/文件/生成資產目錄、壓縮/bundle/vendor 檔、>200KB 檔")
    lines.append(f"- 模型：{scanner.model_path}")
    lines.append(f"- 專案數：{len(results)}　總掃描 LOC：{tot_loc:,}")
    lines.append("")
    lines.append("## 每專案")
    lines.append("")
    lines.append("| 專案 | 掃描檔/總檔 | 掃描LOC | ✅confirmed | 🔍disputed | ⚪filtered | 呈現/KLOC | 模型過濾率 |")
    lines.append("|---|---|---:|---:|---:|---:|---:|---:|")
    for r in results:
        (name, scanned, total, loc, c, d, f, dens, fr) = fmt_project(r)
        lines.append(f"| {name} | {scanned}/{total} | {loc:,} | {c} | {d} | {f} | "
                     f"{dens:.2f} | {fr:.0f}% |")
    # 總計列
    tk = max(tot_loc, 1) / 1000
    mj = agg["filtered"] + tot_shown
    lines.append(f"| **總計** | — | {tot_loc:,} | {agg['confirmed']} | {agg['disputed']} | "
                 f"{agg['filtered']} | **{tot_shown/tk:.2f}** | "
                 f"{(agg['filtered']/mj*100) if mj else 0:.0f}% |")
    lines.append("")
    lines.append("## 全體：呈現 finding 最多的規則（前 15，找真實碼上放寬過頭的）")
    lines.append("")
    for rule, c in agg_rules.most_common(15):
        lines.append(f"- {c:>4}  {rule}")
    lines.append("")
    lines.append("## 各專案前 5 名觸發規則")
    lines.append("")
    for r in results:
        lines.append(f"**{r['name']}**（呈現 {r['v']['confirmed']+r['v']['disputed']}）")
        for rule, c in r["rules"].most_common(5):
            lines.append(f"  - {c:>3}  {rule}")
        lines.append("")

    # ── 掃描速度（簡報效能指標）──
    scan_secs = tot_scan_secs or (time.time() - t0)
    lines.append("## 掃描速度")
    lines.append("")
    lines.append(f"- 模型載入（一次性）：{load_secs:.1f}s")
    lines.append(f"- 純掃描耗時（不含載入）：{scan_secs:.0f}s　掃描 {tot_files:,} 檔 / {tot_loc:,} 行")
    if scan_secs > 0:
        lines.append(f"- 吞吐量：**{tot_files/scan_secs:.1f} 檔/秒**"
                     f"　**{tot_loc/scan_secs:,.0f} 行/秒**"
                     f"　（**{scan_secs/max(tot_loc,1)*1000:.2f} 秒/KLOC**）")
    if tot_files:
        lines.append(f"- 每檔平均：{scan_secs/tot_files*1000:.0f} ms/檔")
    lines.append(f"- 官方規則：{'含' if args.with_official else '未含（--no-official）'}")
    lines.append("")
    lines.append("## 每專案速度")
    lines.append("")
    lines.append("| 專案 | 掃描檔 | 掃描LOC | 耗時 | 檔/秒 | 秒/KLOC |")
    lines.append("|---|---:|---:|---:|---:|---:|")
    for r in results:
        s = r["secs"] or 1e-9
        lines.append(f"| {r['name']} | {r['scanned']} | {r['loc']:,} | {r['secs']:.0f}s | "
                     f"{r['scanned']/s:.1f} | {s/max(r['loc'],1)*1000:.2f} |")
    lines.append("")

    lines.append(f"耗時 {time.time()-t0:.0f}s（含載入 {load_secs:.0f}s）")
    with open(out, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    print("\n" + "\n".join(lines[:40]))
    print(f"\n✅ 紀錄檔：{out}")


if __name__ == "__main__":
    sys.exit(main())
