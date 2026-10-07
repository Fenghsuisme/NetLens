# -*- coding: utf-8 -*-
"""
label_map.py — config 標籤 ↔ 模型標籤的對應

問題：
  測試集的標籤由 core/config_loader 產生，採 22 類體系；
  但模型（v6 之後）採 17 類體系，是 merge_17class.py 合併重編號後的結果。
  兩者在 label 15 之後錯開，導致評估時模型判對卻被算成錯。

  實測發現（verify_labels.py）：
    config label 16（不受限檔案上傳）的樣本
      → 模型輸出 15（模型體系的不受限檔案上傳）
      → 因編號不同被判為錯誤，該類正確率顯示為 0%

對應關係（源自 merge_17class.py 的 MERGE_LABELS 與 RELABEL_MAP）：

    config            模型        說明
    0–14              0–14       一致
    15 IDOR           16         併入權限控制缺陷
    16 不受限檔案上傳    15         往前遞補
    17 權限控制缺陷     16         往前遞補
    18–21 記憶體類      —          不在 17 類體系內

用法：
    from label_map import config_to_model, MODEL_LABEL_NAMES

    model_label = config_to_model(config_label)
    if model_label is None:
        continue   # 該類別不在模型的分類範圍內
"""

# config（22 類）→ 模型（17 類）
CONFIG_TO_MODEL = {
    0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 6: 6, 7: 7,
    8: 8, 9: 9, 10: 10, 11: 11, 12: 12, 13: 13, 14: 14,
    15: 16,   # IDOR → 權限控制缺陷（合併）
    16: 15,   # 不受限檔案上傳
    17: 16,   # 權限控制缺陷
    # 18–21 記憶體類不在 17 類體系內，故不列入
}

# 模型（17 類）的名稱，與訓練腳本的 LABEL_NAMES 一致
MODEL_LABEL_NAMES = {
    0: "正常程式碼", 1: "指令注入", 2: "SQL 注入", 3: "程式碼執行",
    4: "資料外洩", 5: "後門", 6: "弱加密", 7: "硬編碼密碼",
    8: "路徑遊走", 9: "不安全反序列化", 10: "跨站腳本", 11: "原型污染",
    12: "惡意套件", 13: "跨站請求偽造", 14: "伺服器端請求偽造",
    15: "不受限檔案上傳", 16: "權限控制缺陷",
}

# 模型 → config（反查用；15/16 兩類為多對一，取代表值）
MODEL_TO_CONFIG = {
    0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 6: 6, 7: 7,
    8: 8, 9: 9, 10: 10, 11: 11, 12: 12, 13: 13, 14: 14,
    15: 16,   # 不受限檔案上傳
    16: 17,   # 權限控制缺陷（含原 IDOR）
}


def config_to_model(label):
    """config 標籤轉模型標籤。不在模型範圍內時回傳 None。"""
    return CONFIG_TO_MODEL.get(label)


def model_to_config(label):
    """模型標籤轉 config 標籤。"""
    return MODEL_TO_CONFIG.get(label)


def model_name(label):
    return MODEL_LABEL_NAMES.get(label, f"label{label}")


if __name__ == "__main__":
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    try:
        from core.config_loader import label_to_category, get_category
        has_config = True
    except Exception:
        has_config = False

    print("config（22類） → 模型（17類）對應表")
    print("=" * 62)
    print(f"  {'config':>7}  {'config 類別名':<22} {'模型':>5}  {'模型類別名'}")
    print("  " + "-" * 58)
    for cl in sorted(CONFIG_TO_MODEL):
        ml = CONFIG_TO_MODEL[cl]
        cname = "?"
        if has_config:
            cat = label_to_category(cl)
            if cat:
                info = get_category(cat)
                cname = info.get("name_zh", cat) if info else cat
        mark = "  ← 錯開" if cl != ml else ""
        print(f"  {cl:>7}  {cname:<22} {ml:>5}  {model_name(ml)}{mark}")

    print("\n  未對應（不在 17 類體系內）：")
    for cl in [18, 19, 20, 21]:
        cname = "?"
        if has_config:
            cat = label_to_category(cl)
            if cat:
                info = get_category(cat)
                cname = info.get("name_zh", cat) if info else cat
        print(f"  {cl:>7}  {cname}")