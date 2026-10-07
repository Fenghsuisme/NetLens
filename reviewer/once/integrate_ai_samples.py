import pandas as pd
import re
import os

# ── 標籤對應 ──────────────────────────────────────
LABEL_MAP = {
    "sql_injection":             2,
    "command_injection":         1,
    "xss":                       10,
    "hardcoded_secret":          7,
    "hardcoded_credential":      7,
    "data_exfiltration":         4,
    "data_leakage":              4,
    "weak_cryptography":         6,
    "weak_crypto":               6,
    "path_traversal":            8,
    "backdoor":                  5,
    "backdoor_debug":            5,
    "debug_backdoor":            5,
    "code_execution":            3,
    "dynamic_code_exec":         3,
    "unsafe_eval":               3,
    "insecure_deserialization":  9,
    "unsafe_deserialization":    9,
    "prototype_pollution":       11,
    "malicious_import":          12,
    "clean":                     0,
}

LABEL_NAMES = {
    0:  "正常程式碼",
    1:  "指令注入",
    2:  "SQL 注入",
    3:  "程式碼執行",
    4:  "資料外洩",
    5:  "後門",
    6:  "弱加密",
    7:  "硬編碼密碼",
    8:  "路徑遊走",
    9:  "不安全反序列化",
    10: "XSS",
    11: "原型污染",
    12: "惡意套件",
}

LANG_MAP = {
    "python":     "python",
    "javascript": "javascript",
    "js":         "javascript",
    "php":        "php",
    "java":       "java",
    "typescript": "typescript",
    "ts":         "typescript",
}


# ── 解析 AI 生成的測試檔案 ────────────────────────
def parse_file(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    blocks = content.split("---SPLIT---")
    samples = []

    for block in blocks:
        block = block.strip()
        if not block:
            continue

        label_match = re.search(r"###LABEL:(\S+)", block)
        lang_match  = re.search(r"###LANG:(\S+)", block)
        code_match = re.search(r"```\w*\n(.*?)```", block, re.DOTALL)

        if not (label_match and lang_match):
            continue

        label_str = label_match.group(1).strip().lower()
        lang_str  = lang_match.group(1).strip().lower()

        if code_match:
            code = code_match.group(1).strip()
        else:
            # 備用：把 ###DESC 之後的內容當作程式碼
            desc_pos = block.find("###DESC:")
            if desc_pos == -1:
                continue
            desc_line_end = block.find("\n", desc_pos)
            if desc_line_end == -1:
                continue
            code = block[desc_line_end:].strip()

        label = LABEL_MAP.get(label_str)
        lang  = LANG_MAP.get(lang_str, lang_str)

        if label is None:
            print(f"  ⚠️ 未知標籤：{label_str}，跳過")
            continue

        if len(code) < 50:
            continue

        samples.append({
            "code":        code,
            "language":    lang,
            "label":       label,
            "category":    label_str,
            "category_zh": LABEL_NAMES.get(label, label_str),
        })

    return samples


# ── 主程式 ────────────────────────────────────────
def main():
    FILES = {
        "Gemini": "reviewer/test_code/real_test/security_training_dataset_v1.txt",
        "GPT":    "reviewer/test_code/real_test/security_training_examples_100.md",
    }

    all_new = []

    for source, filepath in FILES.items():
        if not os.path.exists(filepath):
            print(f"找不到：{filepath}，跳過")
            continue
        samples = parse_file(filepath)
        print(f"{source}：解析到 {len(samples)} 筆有效樣本")
        all_new.extend(samples)

    print(f"\n新增樣本總計：{len(all_new)} 筆")

    # 載入現有資料集
    combined_path = "reviewer/dataset/dataset_combined_v1.csv"
    if os.path.exists(combined_path):
        existing_df = pd.read_csv(combined_path)
        print(f"現有資料集：{len(existing_df)} 筆")
    else:
        print("找不到現有資料集，建立新的")
        existing_df = pd.DataFrame()

    # 合併
    new_df = pd.DataFrame(all_new)
    if len(existing_df) > 0:
        combined_df = pd.concat([existing_df, new_df], ignore_index=True)
    else:
        combined_df = new_df

    # 去重複
    before = len(combined_df)
    combined_df = combined_df.drop_duplicates(subset=["code"])
    after = len(combined_df)
    if before != after:
        print(f"移除重複：{before - after} 筆")

    # 打亂順序
    combined_df = combined_df.sample(frac=1, random_state=42).reset_index(drop=True)

    print(f"\n合併後總筆數：{len(combined_df)}")
    print("\n各類別數量：")
    for label in sorted(combined_df["label"].unique()):
        name  = LABEL_NAMES.get(label, str(label))
        count = (combined_df["label"] == label).sum()
        print(f"  {label:2d} {name}：{count} 筆")

    # 儲存
    combined_df.to_csv(combined_path, index=False, encoding="utf-8")
    print(f"\n已儲存至：{combined_path}")


if __name__ == "__main__":
    main()