# -*- coding: utf-8 -*-
"""
rules_cleanup.py — 規則庫整理：封存基準 + 關閉不適用語言的規則

兩個動作：

  1. 封存基準（--archive）
     將現行 rules/ 完整複製到 rules_baseline/。
     原因：實驗數據「補強規則貢獻 +28.6pp」是以
           「A 自訂規則 vs C 自訂+補強」的對照得出。
           一旦把補強併入原始規則檔，該對照即無法重現。
           封存基準可保住實驗的可重現性。

  2. 關閉不適用語言的規則（--strip-memory）
     記憶體類 CWE（120/121/122/125/787/416/119）僅適用 C/C++，
     但目前 python.yml / javascript.yml / php.yml / java.yml
     都有對應規則。實測診斷原型污染時發現，
     Java/JS/Python 樣本大量被 CWE-787、CWE-119 命中——
     這些語言不存在越界寫入，屬純誤報。

     融合層雖已用 applicable_languages 過濾，
     但規則層仍會執行、產生 finding，徒增掃描時間與雜訊。

用法：
  python rules_cleanup.py --archive          先封存
  python rules_cleanup.py --strip-memory     再清理（會自動備份）
  python rules_cleanup.py --dry-run --strip-memory   只看會刪什麼
"""
import argparse
import os
import re
import shutil
import sys
from collections import defaultdict

try:
    import yaml
except ImportError:
    print("需要 pyyaml：pip install pyyaml")
    sys.exit(1)

RULES_DIR = "rules"
BASELINE_DIR = "rules_baseline"

# 僅適用 C/C++ 的記憶體類 CWE
MEMORY_ONLY_CWES = {
    "CWE-119",  # 記憶體緩衝區邊界操作不當
    "CWE-120",  # 緩衝區複製未檢查大小
    "CWE-121",  # 堆疊緩衝區溢位
    "CWE-122",  # 堆積緩衝區溢位
    "CWE-125",  # 越界讀取
    "CWE-787",  # 越界寫入
    "CWE-416",  # 釋放後使用
}

# 記憶體管理由執行環境負責、不會有上述漏洞的語言
MEMORY_SAFE_LANGS = {"python", "javascript", "typescript", "php", "java", "csharp"}


def _cwe_of(rule):
    """取出規則的 CWE（相容純編號與帶描述兩種格式）"""
    meta = rule.get("metadata", {}) or {}
    raw = meta.get("cwe")
    if not raw:
        return None
    if isinstance(raw, list):
        raw = raw[0] if raw else None
    if not raw:
        return None
    m = re.search(r"CWE[-\s]?(\d+)", str(raw))
    return f"CWE-{m.group(1)}" if m else None


def archive():
    if not os.path.isdir(RULES_DIR):
        print(f"❌ 找不到 {RULES_DIR}/")
        return False
    if os.path.exists(BASELINE_DIR):
        print(f"⚠️ {BASELINE_DIR}/ 已存在")
        ans = input("   覆蓋？[y/N] ").strip().lower()
        if ans != "y":
            print("   取消")
            return False
        shutil.rmtree(BASELINE_DIR)

    shutil.copytree(RULES_DIR, BASELINE_DIR)
    n = sum(1 for _, _, fs in os.walk(BASELINE_DIR) for f in fs
            if f.endswith((".yml", ".yaml")))
    print(f"✅ 已封存 {n} 個規則檔至 {BASELINE_DIR}/")
    print(f"   之後若需重現「補強前」的實驗，指定此目錄即可")

    # 寫一份說明，避免日後不明所以
    with open(os.path.join(BASELINE_DIR, "README.md"), "w", encoding="utf-8") as f:
        f.write(
            "# 規則基準封存\n\n"
            "此目錄為規則整合前的狀態，用於重現對照實驗。\n\n"
            "對應的實驗數據（新測試集 2,742 筆，A 類 300 筆抽樣）：\n\n"
            "| 配置 | 召回率 | 誤報 |\n"
            "|------|-------|------|\n"
            "| 本目錄（自訂規則） | 45.7% | 3 |\n"
            "| + 7 份補強規則 | 74.3% | 3 |\n"
            "| + 官方 p/security-audit | 77.0% | 3 |\n\n"
            "重現方式：將 rule_experiment_v2.py 的規則路徑\n"
            "指向 rules_baseline/{lang}.yml 即可。\n"
        )
    return True


def strip_memory(dry_run=False, only_langs=None, keep_ts=False):
    """
    only_langs  只處理這些語言的規則檔（None = 全部）
    keep_ts     跳過 languages 含 typescript 的規則
                （因部分 js 規則同時宣告 javascript 與 typescript，
                  移除會連帶影響 TS）
    """
    if not os.path.isdir(RULES_DIR):
        print(f"❌ 找不到 {RULES_DIR}/")
        return False

    files = [f for f in os.listdir(RULES_DIR) if f.endswith((".yml", ".yaml"))]
    if only_langs:
        files = [f for f in files
                 if os.path.splitext(f)[0].lower() in only_langs]
        if not files:
            print(f"❌ 沒有符合的規則檔（指定語言：{sorted(only_langs)}）")
            return False
    total_removed = 0
    detail = defaultdict(list)
    skipped_ts = []

    for fn in sorted(files):
        path = os.path.join(RULES_DIR, fn)
        try:
            data = yaml.safe_load(open(path, encoding="utf-8"))
        except Exception as e:
            print(f"  ⚠️ {fn} 解析失敗：{e}")
            continue
        if not isinstance(data, dict) or "rules" not in data:
            continue

        kept, removed = [], []
        for r in data["rules"]:
            langs = {str(l).lower() for l in r.get("languages", [])}
            cwe = _cwe_of(r)
            # 該規則的語言全屬記憶體安全語言，且 CWE 屬記憶體類 → 移除
            is_memory_rule = (cwe in MEMORY_ONLY_CWES and langs
                              and langs <= MEMORY_SAFE_LANGS)
            # 保護 TypeScript：部分 js 規則同時宣告 javascript 與 typescript
            if is_memory_rule and keep_ts and "typescript" in langs:
                kept.append(r)
                skipped_ts.append((r.get("id", "?"), cwe, sorted(langs)))
                continue
            if is_memory_rule:
                removed.append((r.get("id", "?"), cwe, sorted(langs)))
            else:
                kept.append(r)

        if not removed:
            continue

        total_removed += len(removed)
        detail[fn] = removed

        if dry_run:
            continue

        # 備份後寫回
        bak = path + ".bak"
        if not os.path.exists(bak):
            shutil.copy(path, bak)
        data["rules"] = kept
        with open(path, "w", encoding="utf-8") as f:
            yaml.dump(data, f, allow_unicode=True, sort_keys=False,
                      default_flow_style=False)

    # 報告
    print("=" * 70)
    print("移除不適用語言的記憶體類規則" + ("（dry-run，未實際修改）" if dry_run else ""))
    print("=" * 70)
    if not detail:
        print("\n沒有找到需要移除的規則")
        return True

    for fn, removed in detail.items():
        print(f"\n【{fn}】移除 {len(removed)} 條")
        for rid, cwe, langs in removed:
            print(f"   {rid:<48} {cwe:<10} {','.join(langs)}")

    if skipped_ts:
        print(f"\n【因涉及 TypeScript 而保留】{len(skipped_ts)} 條")
        for rid, cwe, langs in skipped_ts:
            print(f"   {rid:<48} {cwe:<10} {','.join(langs)}")

    print(f"\n合計移除 {total_removed} 條")
    if not dry_run:
        print(f"原始檔已備份為 *.yml.bak")
        print(f"\n理由：這些 CWE 描述的是手動記憶體管理的錯誤，")
        print(f"      在 {'/'.join(sorted(MEMORY_SAFE_LANGS))} 中由執行環境負責，")
        print(f"      規則命中必為誤報。移除可減少掃描時間與報告雜訊。")
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--archive", action="store_true", help="封存現行規則為基準")
    ap.add_argument("--strip-memory", action="store_true",
                    help="移除記憶體安全語言中的記憶體類規則")
    ap.add_argument("--dry-run", action="store_true", help="只顯示不修改")
    ap.add_argument("--langs", nargs="*",
                    help="只處理這些語言的規則檔（預設：全部）"
                         "　例：--langs python javascript php java")
    ap.add_argument("--keep-ts", action="store_true",
                    help="跳過 languages 含 typescript 的規則")
    args = ap.parse_args()

    if not (args.archive or args.strip_memory):
        ap.print_help()
        print("\n建議順序：")
        print("  1. python rules_cleanup.py --archive")
        print("  2. python rules_cleanup.py --dry-run --strip-memory \\")
        print("       --langs python javascript php java")
        print("  3. 確認無誤後拿掉 --dry-run 再跑一次")
        print("\n只清主打的四種語言，保留 csharp / typescript：")
        print("  python rules_cleanup.py --strip-memory \\")
        print("    --langs python javascript php java --keep-ts")
        return

    if args.archive:
        archive()
        print()
    if args.strip_memory:
        langs = {l.lower() for l in args.langs} if args.langs else None
        if langs:
            print(f"限定語言：{', '.join(sorted(langs))}\n")
        strip_memory(args.dry_run, langs, args.keep_ts)


if __name__ == "__main__":
    main()