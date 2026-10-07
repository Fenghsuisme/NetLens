# -*- coding: utf-8 -*-
"""
config_loader.py — CWE 標準化設定的共用載入模組

讀取 reviewer/config/ 底下的兩個設定檔：
  - cwe_catalog.json      （CWE 百科）
  - vuln_categories.json  （漏洞類別定義）


用法：
    from core.config_loader import (
        normalize_label, get_category, get_cwe_info,
        is_applicable, cwe_to_category, label_to_category,
    )
"""
import os
import json
import functools

# ── 設定檔路徑 ────────────────────────────────────
# 以本檔案位置為基準，往上一層找 config/（core/ 的兄弟資料夾）
_HERE = os.path.dirname(os.path.abspath(__file__))
_CONFIG_DIR = os.path.join(os.path.dirname(_HERE), "config")

_CATALOG_PATH = os.path.join(_CONFIG_DIR, "cwe_catalog.json")
_CATEGORIES_PATH = os.path.join(_CONFIG_DIR, "vuln_categories.json")


# ── 載入（含快取，只讀一次）──────────────────────
@functools.lru_cache(maxsize=1)
def _load_catalog():
    with open(_CATALOG_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    return {k: v for k, v in data.items() if not k.startswith("_")}


@functools.lru_cache(maxsize=1)
def _load_categories():
    with open(_CATEGORIES_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    return {k: v for k, v in data.items() if not k.startswith("_")}


# ── 別名正規化 ────────────────────────────────────
def _canonical(s):
    """把字串正規化成比對用格式：小寫、連字號轉底線、去空白"""
    return str(s).strip().lower().replace("-", "_")


@functools.lru_cache(maxsize=1)
def _build_alias_index():
    """建立 {正規化別名: 標準類別代號} 的反查索引"""
    index = {}
    cats = _load_categories()
    for canon_name, info in cats.items():
        # 標準名稱本身
        index[_canonical(canon_name)] = canon_name
        # display_name 與 name_zh 也可反查
        for key in ("display_name", "name_zh"):
            if info.get(key):
                index[_canonical(info[key])] = canon_name
        # 所有別名
        for alias in info.get("aliases", []):
            index[_canonical(alias)] = canon_name
    return index


@functools.lru_cache(maxsize=1)
def _build_label_index():
    """建立 {label數字: 標準類別代號}"""
    return {info["label"]: name
            for name, info in _load_categories().items()
            if info.get("label") is not None}


@functools.lru_cache(maxsize=1)
def _build_cwe_to_category():
    """建立 {CWE: [(類別, 'primary'|'related'), ...]}"""
    index = {}
    for name, info in _load_categories().items():
        p = info.get("primary_cwe")
        if p:
            index.setdefault(p, []).append((name, "primary"))
        for r in info.get("related_cwe", []):
            index.setdefault(r, []).append((name, "related"))
    return index


# ── 對外 API ──────────────────────────────────────
def normalize_label(label):
    """
    任意標籤（別名/大小寫/連字號）→ 標準類別代號。
    找不到回傳 None。
    例：normalize_label('weak-crypto') -> 'weak_cryptography'
    """
    return _build_alias_index().get(_canonical(label))


def get_category(name):
    """
    取得某類別的完整資訊 dict（吃標準代號或別名皆可）。
    找不到回傳 None。
    """
    canon = normalize_label(name)
    if canon is None:
        return None
    return _load_categories().get(canon)


def label_to_category(label_num):
    """數字標籤 → 標準類別代號（CodeBERT 輸出反查用）"""
    try:
        return _build_label_index().get(int(label_num))
    except (ValueError, TypeError):
        return None


def get_cwe_info(cwe_id):
    """
    取得某 CWE 的完整資訊 dict。
    吃 'CWE-89' 或 '89' 或 89 皆可。找不到回傳 None。
    """
    cwe = _normalize_cwe(cwe_id)
    return _load_catalog().get(cwe)


def is_applicable(cwe_id, language):
    """
    判斷某 CWE 是否適用於某語言（融合層過濾誤報用）。
    - CWE 不存在 → False
    - applicable_languages 為空 → True（視為未界定，不過濾）
    """
    info = get_cwe_info(cwe_id)
    if info is None:
        return False
    langs = info.get("applicable_languages", [])
    if not langs:
        return True
    return _canonical(language) in [_canonical(x) for x in langs]


def cwe_to_category(cwe_id, prefer="primary"):
    """
    反查某 CWE 對應到哪個漏洞類別。
    回傳標準類別代號；有多個時，prefer='primary' 優先回傳 primary 對應。
    找不到回傳 None。
    """
    cwe = _normalize_cwe(cwe_id)
    matches = _build_cwe_to_category().get(cwe, [])
    if not matches:
        return None
    if prefer == "primary":
        for name, kind in matches:
            if kind == "primary":
                return name
    return matches[0][0]


def display_name(name_or_label):
    """
    取得呈現給使用者的精確漏洞名稱。
    吃標準代號、別名、或數字標籤皆可。
    """
    canon = None
    if isinstance(name_or_label, int) or str(name_or_label).isdigit():
        canon = label_to_category(name_or_label)
    else:
        canon = normalize_label(name_or_label)
    if canon is None:
        return str(name_or_label)
    info = _load_categories().get(canon, {})
    return info.get("display_name") or info.get("name_zh") or canon


# ── 內部工具 ──────────────────────────────────────
def _normalize_cwe(cwe_id):
    """'89' / 89 / 'CWE-89' / 'cwe-89: xxx' → 'CWE-89'"""
    s = str(cwe_id).upper().replace(" ", "")
    if s.startswith("CWE-"):
        num = ""
        for ch in s[4:]:
            if ch.isdigit():
                num += ch
            else:
                break
        return f"CWE-{num}" if num else s
    if s.isdigit():
        return f"CWE-{s}"
    return s


# ── 自我測試 ──────────────────────────────────────
if __name__ == "__main__":
    print("=" * 55)
    print("config_loader 自我測試")
    print("=" * 55)

    print(f"\n設定檔目錄：{_CONFIG_DIR}")
    print(f"catalog 存在：{os.path.exists(_CATALOG_PATH)}")
    print(f"categories 存在：{os.path.exists(_CATEGORIES_PATH)}")

    print(f"\n載入 CWE 數量：{len(_load_catalog())}")
    print(f"載入類別數量：{len(_load_categories())}")

    print("\n[別名正規化]")
    for t in ["weak_crypto", "weak-crypto", "WEAK_CRYPTOGRAPHY", "debug_backdoor",
              "data_leakage", "sqli", "不明標籤xyz"]:
        print(f"  {t:<22} -> {normalize_label(t)}")

    print("\n[數字標籤反查]")
    for i in [0, 2, 5, 12]:
        print(f"  label {i:<2} -> {label_to_category(i)}")

    print("\n[CWE 資訊]")
    for c in ["CWE-89", "89", "CWE-125"]:
        info = get_cwe_info(c)
        print(f"  {c:<8} -> {info['name_zh'] if info else None}"
              f"（適用：{info['applicable_languages'] if info else '-'}）")

    print("\n[語言適用性過濾]")
    for c, lang in [("CWE-89", "python"), ("CWE-125", "python"),
                    ("CWE-125", "c"), ("CWE-1321", "javascript"),
                    ("CWE-1321", "python")]:
        print(f"  {c} 適用於 {lang:<10}? -> {is_applicable(c, lang)}")

    print("\n[CWE 反查類別]")
    for c in ["CWE-89", "CWE-78", "CWE-77", "CWE-798"]:
        print(f"  {c:<8} -> {cwe_to_category(c)}")

    print("\n[使用者顯示名稱]")
    for x in ["sql_injection", "weak_crypto", 5, "CWE-89 對應"]:
        print(f"  {str(x):<18} -> {display_name(x)}")

    print("\n完成")