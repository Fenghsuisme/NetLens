# -*- coding: utf-8 -*-
"""
fusion.py — 融合層

把三個引擎（黑名單 / Semgrep / CodeBERT）的原始輸出，融合成乾淨的結構化報告。

核心職責：
  1. 過濾   — 丟掉語言不適用的 CWE（如 Python 檔卻報 CWE-125 記憶體漏洞）
  2. 正規化 — 原始 CWE / 數字標籤 → 標準類別 + 精確漏洞名稱
  3. 合併   — 同一行多引擎命中 → 合成一筆，記錄證據來源（選項A）
  4. 排序   — 依嚴重度 + 行號

資料結構（兩層，單檔為多檔的特例）：
  Finding    單一發現
  FileReport 單一檔案報告（含多個 Finding）
  ScanReport 整次掃描（含多個 FileReport，單檔/專案共用）

用法：
  from core.fusion import fuse_file, build_scan_report
  fr = fuse_file("login.py", "python", semgrep_raw, codebert_raw, blacklist_raw)
  report = build_scan_report([fr], scan_type="single_file")
"""
from datetime import datetime

from core.config_loader import (
    normalize_label, label_to_category, get_cwe_info,
    is_applicable, cwe_to_category, display_name, get_category,
)

# ── 嚴重度排序權重 ────────────────────────────────
_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _severity_rank(sev):
    return _SEVERITY_ORDER.get(str(sev).upper(), 0)


# ── 建立單一 Finding ──────────────────────────────
def _make_finding(line, category, cwe, severity, source,
                  confidence=None, code_snippet="", evidence="",
                  match_type="primary"):
    """產生一個標準格式的 Finding。category 可為 None（無法對應時）"""
    canon = normalize_label(category) if category else None
    info = get_category(canon) if canon else None

    return {
        "line": int(line) if line else 0,
        "category": canon,
        "display_name": display_name(canon) if canon else "未分類",
        "cwe": cwe,
        "severity": str(severity).upper(),
        "sources": [source],
        "confidence": confidence,
        "code_snippet": (code_snippet or "").strip(),
        "evidence": evidence,
        "match_type": match_type,
        # 預留擴充欄位（之後填）
        "fix_suggestion": None,
        "explanation": None,
        "codebert_supported": info.get("codebert_supported") if info else None,
    }


# ── 各引擎原始輸出 → Finding 清單 ────────────────
def _from_semgrep(semgrep_raw, language):
    """
    semgrep_raw: run_semgrep() 回傳的 findings list，每筆含
      rule_id, message, severity, line_start, cwe(list), code_snippet
    會過濾掉語言不適用的 CWE。
    """
    findings = []
    for f in semgrep_raw or []:
        cwe_list = f.get("cwe", []) or []
        # Semgrep 一條規則可能標多個 CWE，逐一處理
        if not cwe_list:
            # 沒有 CWE 資訊，保留但標未分類
            findings.append(_make_finding(
                line=f.get("line_start", 0), category=None, cwe=None,
                severity=f.get("severity", "WARNING"), source="semgrep",
                code_snippet=f.get("code_snippet", ""),
                evidence=f.get("rule_id", ""),
            ))
            continue

        for cwe in cwe_list:
            cwe_norm = _norm_cwe(cwe)
            # 過濾：此 CWE 不適用當前語言 → 丟掉（清誤報）
            if not is_applicable(cwe_norm, language):
                continue

            category = cwe_to_category(cwe_norm)
            info = get_cwe_info(cwe_norm)
            # 嚴重度優先用 catalog 定義，其次用 Semgrep 回報的
            severity = (info or {}).get("severity") or f.get("severity", "MEDIUM")
            # 判定是 primary 還是 related 命中
            match_type = _match_type(cwe_norm, category)

            findings.append(_make_finding(
                line=f.get("line_start", 0),
                category=category,
                cwe=cwe_norm,
                severity=severity,
                source="semgrep",
                code_snippet=f.get("code_snippet", ""),
                evidence=f.get("rule_id", ""),
                match_type=match_type,
            ))
    return findings


def _from_codebert(codebert_raw):
    """
    codebert_raw: dict 或 None
      { "label": 2, "confidence": 0.95 }  或
      { "category": "sql_injection", "confidence": 0.95 }
    CodeBERT 是整段判斷，line=0。label 0(clean) 不產生 finding。
    """
    if not codebert_raw:
        return []
    label = codebert_raw.get("label")
    category = codebert_raw.get("category")
    conf = codebert_raw.get("confidence")

    if category is None and label is not None:
        category = label_to_category(label)
    if not category or normalize_label(category) == "clean":
        return []

    canon = normalize_label(category)
    info = get_category(canon)
    pcwe = (info or {}).get("primary_cwe")
    sev = (get_cwe_info(pcwe) or {}).get("severity", "HIGH") if pcwe else "HIGH"

    return [_make_finding(
        line=0, category=canon, cwe=pcwe, severity=sev,
        source="codebert", confidence=conf,
        evidence=f"CodeBERT 語意判斷（信心度 {conf:.0%}）" if conf else "CodeBERT 語意判斷",
    )]


def _from_blacklist(blacklist_raw):
    """
    blacklist_raw: list of {line, package}
    黑名單命中一律歸類為 malicious_import。
    """
    findings = []
    for pkg in blacklist_raw or []:
        findings.append(_make_finding(
            line=pkg.get("line", 0),
            category="malicious_import",
            cwe="CWE-829",
            severity="CRITICAL",
            source="blacklist",
            code_snippet=pkg.get("package", ""),
            evidence=f"已知惡意套件：{pkg.get('package','')}",
        ))
    return findings


# ── 合併去重（選項A）──────────────────────────────
def _merge_findings(findings):
    """
    選項A：同一 (line, category) 的多引擎發現合併成一筆，
    sources 累積，信心度取最高，證據合併。
    CodeBERT 的整段判斷(line=0)若與某逐行發現同類別，用來替該發現背書。
    """
    # 先分出 CodeBERT 的整段判斷（line=0）
    codebert_global = [f for f in findings
                       if f["line"] == 0 and "codebert" in f["sources"]]
    line_findings = [f for f in findings
                     if not (f["line"] == 0 and "codebert" in f["sources"])]

    # 依 (line, category) 合併逐行發現
    merged = {}
    for f in line_findings:
        key = (f["line"], f["category"])
        if key not in merged:
            merged[key] = f
        else:
            m = merged[key]
            for s in f["sources"]:
                if s not in m["sources"]:
                    m["sources"].append(s)
            # 信心度取較高
            if f["confidence"] is not None:
                m["confidence"] = max(m["confidence"] or 0, f["confidence"])
            # 嚴重度取較高
            if _severity_rank(f["severity"]) > _severity_rank(m["severity"]):
                m["severity"] = f["severity"]
            # 證據合併
            if f["evidence"] and f["evidence"] not in m["evidence"]:
                m["evidence"] = f"{m['evidence']}; {f['evidence']}"
            # primary 優先
            if f["match_type"] == "primary":
                m["match_type"] = "primary"

    result = list(merged.values())

    # CodeBERT 整段判斷：若同類別已有逐行發現 → 背書（加 source）；否則單獨列一筆
    for cb in codebert_global:
        backed = False
        for m in result:
            if m["category"] == cb["category"]:
                if "codebert" not in m["sources"]:
                    m["sources"].append("codebert")
                if cb["confidence"] is not None:
                    m["confidence"] = max(m["confidence"] or 0, cb["confidence"])
                if cb["evidence"] and cb["evidence"] not in m["evidence"]:
                    m["evidence"] = f"{m['evidence']}; {cb['evidence']}"
                backed = True
        if not backed:
            result.append(cb)

    return result


# ── 對外：融合單一檔案 ────────────────────────────
def fuse_file(file_path, language, semgrep_raw=None,
              codebert_raw=None, blacklist_raw=None):
    """把三引擎的原始輸出融合成一個 FileReport"""
    findings = []
    findings += _from_blacklist(blacklist_raw)
    findings += _from_semgrep(semgrep_raw, language)
    findings += _from_codebert(codebert_raw)

    findings = _merge_findings(findings)

    # 排序：嚴重度高→低，同嚴重度依行號
    findings.sort(key=lambda f: (-_severity_rank(f["severity"]), f["line"]))

    # 統計
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
               "total": len(findings), "multi_engine": 0}
    for f in findings:
        summary[f["severity"].lower()] = summary.get(f["severity"].lower(), 0) + 1
        if len(f["sources"]) > 1:
            summary["multi_engine"] += 1

    return {
        "file_path": file_path,
        "language": language,
        "findings": findings,
        "summary": summary,
    }


# ── 對外：組成整次掃描報告（單檔/專案共用）───────
def build_scan_report(file_reports, scan_type="single_file"):
    """把多個 FileReport 彙整成 ScanReport"""
    overall = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
               "total": 0, "files_scanned": len(file_reports),
               "files_with_issues": 0}
    for fr in file_reports:
        s = fr["summary"]
        for k in ("critical", "high", "medium", "low", "info", "total"):
            overall[k] += s.get(k, 0)
        if s.get("total", 0) > 0:
            overall["files_with_issues"] += 1

    # 風險分數（0-100，越高越危險）：加權嚴重度
    score = min(100, overall["critical"] * 25 + overall["high"] * 10
                + overall["medium"] * 3 + overall["low"] * 1)

    # 最危險的檔案（依 critical+high 數）
    def _danger(fr):
        s = fr["summary"]
        return s.get("critical", 0) * 10 + s.get("high", 0)
    most_dangerous = sorted(file_reports, key=_danger, reverse=True)
    most_dangerous_file = (most_dangerous[0]["file_path"]
                           if most_dangerous and _danger(most_dangerous[0]) > 0
                           else None)

    # 風險等級
    if overall["critical"] > 0 or overall["high"] >= 3:
        risk_level, verdict = "high", "🔴 高風險"
    elif overall["high"] >= 1 or overall["medium"] >= 3:
        risk_level, verdict = "medium", "🟡 中風險"
    elif overall["total"] > 0:
        risk_level, verdict = "low", "🟢 低風險"
    else:
        risk_level, verdict = "clean", "✅ 未發現問題"

    return {
        "scan_type": scan_type,
        "scanned_at": datetime.now().isoformat(),
        "files": file_reports,
        "overall_summary": overall,
        "risk_score": score,
        "risk_level": risk_level,
        "verdict": verdict,
        "most_dangerous_file": most_dangerous_file,
    }


# ── 內部工具 ──────────────────────────────────────
def _norm_cwe(cwe):
    s = str(cwe).upper().replace(" ", "")
    if s.startswith("CWE-"):
        num = ""
        for ch in s[4:]:
            if ch.isdigit(): num += ch
            else: break
        return f"CWE-{num}" if num else s
    if s.isdigit():
        return f"CWE-{s}"
    return s


def _match_type(cwe, category):
    """判斷這個 CWE 對該類別是 primary 還是 related 命中"""
    if not category:
        return "unclassified"
    info = get_category(category)
    if not info:
        return "unclassified"
    if info.get("primary_cwe") == cwe:
        return "primary"
    if cwe in info.get("related_cwe", []):
        return "related"
    return "primary"