# -*- coding: utf-8 -*-
"""
gen_hard_negatives.py — 產生「看起來像漏洞、但實際安全」的 hard-negative 樣本

目的（對應 RETRAIN_PLAN 的 P1）：
  eval_clean 實測顯示模型會「自信地」把安全碼判成漏洞（B 策略的信心門檻因此無效）。
  這些安全形狀（path.join+basename、prepared SQL、帶 token 的 POST handler…）
  正是現行 safe_dataset 覆蓋不足之處。此腳本把它們產生成 label 0 訓練樣本，
  教模型「這種形狀是安全的」，才是降 FP 的根治。

輸出結構與 integrate_safe_dataset.py 相容：
    <root>/CWE-xxx/<name>.<ext>          （每檔一段安全碼，label 一律 0）

用法：
    python dataset_generate/gen_hard_negatives.py            # 預設輸出 dataset/hard_negatives/
    python dataset_generate/gen_hard_negatives.py <out_root>

之後在訓練機：把 integrate_safe_dataset.py 的 SAFE_DATASET_ROOT 指向這個資料夾
（或把內容複製進既有 safe_dataset/），再跑 integrate → merge_17class → 重訓。

註：這些是「安全版」對照，每一段都經人工核對確為安全（有驗證/轉義/參數化/token）。
    覆蓋率有限、屬高品質種子；可用同樣「安全形狀」的 prompt 交給 LLM 大量擴增。
"""
import os
import sys

EXT = {"python": ".py", "javascript": ".js", "java": ".java", "php": ".php"}

# ── 每個 CWE 一組「安全但像漏洞」的樣本 ──
# key = CWE 資料夾名；value = [(lang, code), ...]
SAMPLES = {
    # 路徑遊走：用 basename/resolve+邊界檢查，非使用者可控拼接
    "CWE-22": [
        ("python", '''import os
UPLOAD_DIR = "/var/app/uploads"
def read_upload(filename):
    safe = os.path.basename(filename)
    full = os.path.join(UPLOAD_DIR, safe)
    if not os.path.abspath(full).startswith(UPLOAD_DIR + os.sep):
        raise ValueError("invalid path")
    with open(full, "rb") as f:
        return f.read()
'''),
        ("javascript", '''const path = require('path');
const fs = require('fs');
const BASE = path.resolve('/var/app/uploads');
function sendUpload(req, res) {
  const name = path.basename(req.params.name);
  const full = path.resolve(BASE, name);
  if (!full.startsWith(BASE + path.sep)) return res.status(400).end();
  res.sendFile(full);
}
'''),
        ("java", '''import java.nio.file.*;
public class FileService {
    private static final Path BASE = Paths.get("/var/app/uploads").toAbsolutePath().normalize();
    public byte[] read(String name) throws Exception {
        Path p = BASE.resolve(name).normalize();
        if (!p.startsWith(BASE)) throw new SecurityException("path traversal");
        return Files.readAllBytes(p);
    }
}
'''),
        ("php", '''<?php
$UPLOAD_DIR = "/var/www/uploads/";
$name = basename($_GET["file"]);
$path = $UPLOAD_DIR . $name;
$real = realpath($path);
if ($real === false || strpos($real, realpath($UPLOAD_DIR)) !== 0) {
    http_response_code(400);
    exit("invalid");
}
readfile($real);
'''),
        ("php", '''<?php
// 框架 bootstrap：常數路徑拼接，非使用者輸入
require __DIR__ . "/../vendor/autoload.php";
$app = require_once __DIR__ . "/../bootstrap/app.php";
$app->run();
'''),
        ("python", '''from pathlib import Path
BASE = Path("/var/app/data").resolve()
def load(name):
    target = (BASE / name).resolve()
    target.relative_to(BASE)          # 不在 BASE 底下會拋 ValueError
    return target.read_text()
'''),
        ("javascript", '''const path = require('path');
function safeJoin(base, userPath) {
  const normalized = path.normalize(userPath);
  if (normalized.split(path.sep).includes('..')) throw new Error('traversal');
  return path.join(base, normalized);
}
'''),
        ("java", '''import java.io.*;
import org.apache.commons.io.FilenameUtils;
public class Loader {
    public File resolve(String base, String userName) {
        String clean = FilenameUtils.getName(userName);   // 去除路徑成分
        return new File(base, clean);
    }
}
'''),
    ],
    # SQL 注入：參數化 / 預備語句 / ORM
    "CWE-89": [
        ("python", '''def get_user(cursor, user_id):
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()
'''),
        ("python", '''def search(db, term):
    return db.execute("SELECT * FROM items WHERE name = %s", (term,)).fetchall()
'''),
        ("javascript", '''async function getUser(db, req, res) {
  const rows = await db.query("SELECT * FROM users WHERE id = $1", [req.params.id]);
  res.json(rows);
}
'''),
        ("java", '''import java.sql.*;
public class UserDao {
    public User find(Connection c, String id) throws SQLException {
        PreparedStatement ps = c.prepareStatement("SELECT * FROM users WHERE id = ?");
        ps.setString(1, id);
        return map(ps.executeQuery());
    }
}
'''),
        ("php", '''<?php
function getUser(PDO $pdo, $id) {
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
    $stmt->execute([":id" => $id]);
    return $stmt->fetch();
}
'''),
        ("python", '''from sqlalchemy import select
def get_user(session, user_id):
    # ORM 參數化，無字串拼接
    return session.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
'''),
        ("javascript", '''async function findItem(sequelize, req, res) {
  // Sequelize replacements 綁定參數，安全
  const rows = await sequelize.query("SELECT * FROM items WHERE sku = :sku",
    { replacements: { sku: req.query.sku }, type: sequelize.QueryTypes.SELECT });
  res.json(rows);
}
'''),
        ("java", '''import javax.persistence.*;
public class ItemDao {
    @PersistenceContext EntityManager em;
    public Item find(String code) {
        return em.createQuery("SELECT i FROM Item i WHERE i.code = :c", Item.class)
                 .setParameter("c", code).getSingleResult();
    }
}
'''),
        ("php", '''<?php
// Eloquent 查詢建構器自動綁定參數
$user = User::where("email", $request->input("email"))->first();
'''),
    ],
    # 指令注入：陣列參數/escapeshellarg，非 shell 字串拼接
    "CWE-78": [
        ("python", '''import subprocess
def ping(host):
    # shell=False + 陣列參數，無 shell 注入
    return subprocess.run(["ping", "-c", "4", host], shell=False, capture_output=True)
'''),
        ("php", '''<?php
$file = $_GET["file"];
$safe = escapeshellarg($file);
$out = shell_exec("wc -l " . $safe);
echo htmlspecialchars($out);
'''),
        ("java", '''public Process run(String dir) throws Exception {
    // ProcessBuilder 以 list 傳參，不經 shell，無注入
    return new ProcessBuilder("ls", "-la", dir).start();
}
'''),
        ("javascript", '''const { execFile } = require('child_process');
function convert(input, output, cb) {
  // execFile 不經 shell，參數以陣列傳遞
  execFile('convert', [input, output], cb);
}
'''),
    ],
    # XSS：轉義輸出 / textContent
    "CWE-79": [
        ("javascript", '''function render(el, userText) {
  // textContent 不會解析 HTML，安全
  el.textContent = userText;
}
'''),
        ("php", '''<?php
$name = $_GET["name"];
echo "<div>" . htmlspecialchars($name, ENT_QUOTES, "UTF-8") . "</div>";
'''),
        ("java", '''public String render(String userInput) {
    String safe = org.apache.commons.text.StringEscapeUtils.escapeHtml4(userInput);
    return "<p>" + safe + "</p>";
}
'''),
        ("javascript", '''import DOMPurify from 'dompurify';
function show(el, userHtml) {
  el.innerHTML = DOMPurify.sanitize(userHtml);   // 淨化後才寫入
}
'''),
        ("python", '''from flask import render_template
def profile(name):
    # Jinja2 預設自動轉義，變數不會被當 HTML
    return render_template("profile.html", name=name)
'''),
    ],
    # CSRF：POST handler 有 token 驗證
    "CWE-352": [
        ("php", '''<?php
session_start();
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    if (!hash_equals($_SESSION["csrf_token"] ?? "", $_POST["csrf_token"] ?? "")) {
        http_response_code(403);
        exit("invalid csrf token");
    }
    $stmt = $db->prepare("UPDATE users SET email = ? WHERE id = ?");
    $stmt->execute([$_POST["email"], $_SESSION["user_id"]]);
}
'''),
        ("python", '''from flask import request, session, abort
def update_profile():
    if request.form.get("csrf_token") != session.get("csrf_token"):
        abort(403)
    db.session.execute("UPDATE users SET bio = :b WHERE id = :i",
                       {"b": request.form["bio"], "i": session["uid"]})
    db.session.commit()
'''),
        ("javascript", '''const csrf = require('csurf');
router.use(csrf());
router.post('/account', (req, res) => {
  // csurf middleware 已驗證 token，未過驗證會在中介層擋下
  db.query("UPDATE accounts SET name = $1 WHERE id = $2",
           [req.body.name, req.session.userId]);
  res.sendStatus(204);
});
'''),
        ("java", '''import org.springframework.web.bind.annotation.*;
@RestController
public class AccountController {
    // Spring Security 預設對 POST 強制 CSRF token 驗證
    @PostMapping("/account")
    public void update(@RequestParam String name, @AuthenticationPrincipal User u) {
        accountService.rename(u.getId(), name);
    }
}
'''),
    ],
    # 檔案上傳：副檔名/MIME 白名單且確實擋下
    "CWE-434": [
        ("python", '''import os
from werkzeug.utils import secure_filename
ALLOWED = {"png", "jpg", "jpeg", "gif"}
def upload(file):
    name = secure_filename(file.filename)
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if ext not in ALLOWED:
        raise ValueError("file type not allowed")
    file.save(os.path.join("/var/app/uploads", name))
'''),
        ("php", '''<?php
$allowed = ["image/png", "image/jpeg"];
$finfo = finfo_open(FILEINFO_MIME_TYPE);
$mime = finfo_file($finfo, $_FILES["f"]["tmp_name"]);
if (!in_array($mime, $allowed, true)) {
    http_response_code(400);
    exit("bad type");
}
move_uploaded_file($_FILES["f"]["tmp_name"], "/var/www/up/" . basename($_FILES["f"]["name"]));
'''),
        ("javascript", '''const multer = require('multer');
const upload = multer({
  dest: '/tmp/up',
  fileFilter: (req, file, cb) => {
    const ok = ['image/png', 'image/jpeg'].includes(file.mimetype);
    cb(ok ? null : new Error('type not allowed'), ok);   // 限制型別
  },
});
'''),
    ],
    # 資訊外洩：錯誤處理不洩漏內部細節
    "CWE-200": [
        ("python", '''import logging
def handler(request):
    try:
        return process(request)
    except Exception:
        logging.exception("internal error")   # 細節只進 log
        return {"error": "internal server error"}, 500   # 回應不含堆疊
'''),
        ("java", '''public Response handle(Request req) {
    try {
        return process(req);
    } catch (Exception e) {
        log.error("processing failed", e);       // 細節進 log
        return Response.serverError().entity("Internal Server Error").build();
    }
}
'''),
    ],
    # 原型污染：合併時過濾危險 key
    "CWE-1321": [
        ("javascript", '''const DANGEROUS = ["__proto__", "constructor", "prototype"];
function merge(target, source) {
  for (const key of Object.keys(source)) {
    if (DANGEROUS.includes(key)) continue;      // 擋掉危險 key
    if (typeof source[key] === "object" && source[key] !== null) {
      target[key] = merge(target[key] || {}, source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}
'''),
        ("python", '''def deep_merge(base, updates):
    for key, value in updates.items():
        if key.startswith("__"):                 # 擋掉 dunder
            continue
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            deep_merge(base[key], value)
        else:
            base[key] = value
'''),
    ],
    # 硬編碼憑證：改從環境變數讀
    "CWE-798": [
        ("python", '''import os
DB_PASSWORD = os.environ["DB_PASSWORD"]
API_KEY = os.environ.get("API_KEY")
def connect():
    return db.connect(user="app", password=DB_PASSWORD)
'''),
        ("javascript", '''const dbPassword = process.env.DB_PASSWORD;
const apiKey = process.env.API_KEY;
const client = new Client({ password: dbPassword });
'''),
    ],
    # IDOR / 授權：查詢帶擁有權檢查
    "CWE-639": [
        ("python", '''def get_order(cursor, order_id, current_user_id):
    # WHERE 同時綁 order id 與擁有者，非只憑使用者可控 id
    cursor.execute("SELECT * FROM orders WHERE id = ? AND user_id = ?",
                   (order_id, current_user_id))
    return cursor.fetchone()
'''),
        ("java", '''public Order get(long orderId, long currentUserId) {
    Order o = repo.findById(orderId);
    if (o == null || o.getUserId() != currentUserId) {
        throw new AccessDeniedException("not owner");   // 擁有權檢查
    }
    return o;
}
'''),
    ],
    # 弱加密的安全對照：用強演算法
    "CWE-328": [
        ("python", '''import hashlib
def fingerprint(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()      # SHA-256，非 md5/sha1
'''),
        ("php", '''<?php
// 密碼用 password_hash（bcrypt），非 md5/sha1
$hash = password_hash($_POST["password"], PASSWORD_BCRYPT);
'''),
    ],
    # SSRF：抓取前先以 allowlist 驗證主機
    "CWE-918": [
        ("python", '''from urllib.parse import urlparse
import requests
ALLOWED_HOSTS = {"api.trusted.com", "cdn.trusted.com"}
def fetch(url):
    host = urlparse(url).hostname
    if host not in ALLOWED_HOSTS:            # 白名單驗證
        raise ValueError("host not allowed")
    return requests.get(url, timeout=5).text
'''),
        ("javascript", '''const ALLOWED = new Set(['api.trusted.com']);
async function proxy(req, res) {
  const u = new URL(req.query.url);
  if (!ALLOWED.has(u.hostname)) return res.status(400).end();   // 白名單
  const r = await fetch(u.href);
  res.send(await r.text());
}
'''),
        ("php", '''<?php
$allowed = ["api.trusted.com"];
$host = parse_url($_GET["url"], PHP_URL_HOST);
if (!in_array($host, $allowed, true)) {
    http_response_code(400);
    exit("host not allowed");
}
$ch = curl_init($_GET["url"]);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
echo curl_exec($ch);
'''),
    ],
    # 授權：敏感操作前檢查角色/權限
    "CWE-863": [
        ("python", '''from flask import session, abort
def delete_user(target_id):
    if not session.get("is_admin"):          # 授權檢查
        abort(403)
    db.session.execute("DELETE FROM users WHERE id = :i", {"i": target_id})
    db.session.commit()
'''),
        ("java", '''import org.springframework.security.access.prepost.PreAuthorize;
public class AdminService {
    @PreAuthorize("hasRole('ADMIN')")        // 方法層授權
    public void deleteUser(long id) {
        userRepo.deleteById(id);
    }
}
'''),
        ("php", '''<?php
session_start();
if (($_SESSION["role"] ?? "") !== "admin") {   // 授權檢查
    http_response_code(403);
    exit("forbidden");
}
$stmt = $db->prepare("DELETE FROM users WHERE id = ?");
$stmt->execute([$_POST["id"]]);
'''),
    ],
}


def main():
    out_root = sys.argv[1] if len(sys.argv) > 1 else "dataset/hard_negatives"
    n = 0
    for cwe, items in SAMPLES.items():
        d = os.path.join(out_root, cwe)
        os.makedirs(d, exist_ok=True)
        per_lang = {}
        for lang, code in items:
            per_lang[lang] = per_lang.get(lang, 0) + 1
            idx = per_lang[lang]
            # 檔名含 hn（hard-negative）與 seed；_detect_model 會標成 unknown
            fn = f"hn_{cwe.lower()}_{lang}_{idx}_seed{EXT[lang]}"
            with open(os.path.join(d, fn), "w", encoding="utf-8") as f:
                f.write(code)
            n += 1
    print(f"✅ 產生 {n} 筆 hard-negative 樣本 → {out_root}/CWE-*/")
    print(f"   CWE 類別：{', '.join(SAMPLES.keys())}")
    print("\n下一步（訓練機）：")
    print("  1. 將 integrate_safe_dataset.py 的 SAFE_DATASET_ROOT 指向此資料夾")
    print("     （或把 CWE-*/ 內容複製進既有 safe_dataset/）")
    print("  2. python training/integrate_safe_dataset.py")
    print("  3. python training/merge_17class.py")
    print("  4. python training/train_model_v7v8.py")


if __name__ == "__main__":
    main()
