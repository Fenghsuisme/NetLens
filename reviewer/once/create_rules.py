import os

# 確保目錄存在
os.makedirs("rules", exist_ok=True)

# ══════════════════════════════════════════════════════════════
# 1. Python 自訂規則產生
# ══════════════════════════════════════════════════════════════
py_rules = """\
rules:
  - id: command-injection
    pattern-either:
      - pattern: os.system(...)
      - pattern: os.popen(...)
      - pattern: subprocess.run(..., shell=True)
      - pattern: subprocess.call(..., shell=True)
      - pattern: subprocess.check_call(..., shell=True)
      - pattern: subprocess.check_output(..., shell=True)
      - pattern: subprocess.Popen(..., shell=True)
    message: "Command injection risk (CWE-78): Unvalidated user inputs passed to system shell can lead to arbitrary code execution."
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ['CWE-78']

  - id: code-execution
    pattern-either:
      - pattern: eval(...)
      - pattern: exec(...)
      - pattern: compile(..., ..., 'exec')
      - pattern: compile(..., ..., 'eval')
    pattern-not:
      - pattern: ast.literal_eval(...)
    message: "Code execution risk (CWE-94): Passing untrusted strings to interpreter primitives allows arbitrary code injection."
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ['CWE-94']

  - id: weak-hash
    pattern-either:
      - pattern: hashlib.md5(...)
      - pattern: hashlib.sha1(...)
    message: "Weak hash algorithm (CWE-328)"
    languages: [python]
    severity: WARNING
    metadata:
      cwe: ['CWE-328']

  - id: hardcoded-secrets
    pattern-either:
      - pattern: password = "..."
      - pattern: secret = "..."
      - pattern: api_key = "..."
    message: "Hardcoded secret detected (CWE-798)"
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ['CWE-798']

  - id: python-information-exposure-cwe200
    pattern-either:
      - pattern: traceback.format_exc(...)
      - pattern: str($E)
      - pattern: $X.__dict__
    message: "Exposure of Sensitive Information to an Unauthorized Actor (CWE-200): Returning raw exception details, stack traces, or fully serialized object dicts leaks internal state."
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ['CWE-200']

  - id: python-deserialization-cwe502
    pattern-either:
      - pattern: pickle.loads(...)
      - pattern: pickle.load(...)
      - pattern: marshal.loads(...)
      - pattern: shelve.open(...)
      - pattern: yaml.load(...)
    pattern-not:
      - pattern: yaml.load(..., Loader=yaml.SafeLoader)
      - pattern: yaml.safe_load(...)
    message: "Deserialization of Untrusted Data risk (CWE-502): Deserializing untrusted data using pickle, marshal, or unsafe yaml configurations can lead to arbitrary code execution during object reconstruction."
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ['CWE-502']

  - id: disabled-ssl
    pattern-either:
      - pattern: requests.get(..., verify=False, ...)
      - pattern: requests.post(..., verify=False, ...)
      - pattern: httpx.get(..., verify=False, ...)
      - pattern: httpx.post(..., verify=False, ...)
    message: "SSL verification is disabled (CWE-295)"
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ['CWE-295']

  - id: sql-injection
    pattern-either:
      - pattern: $DB.execute(...)
      - pattern: $CURSOR.execute(...)
    message: "SQL Injection risk (CWE-89)"
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ['CWE-89']

  - id: xss-injection
    pattern-either:
      - pattern: flask.render_template_string(...)
      - pattern: jinja2.Template(...).render(...)
      - pattern: django.utils.safestring.mark_safe(...)
    message: "Cross-site Scripting risk (CWE-79)"
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ['CWE-79']

  - id: csrf-config-risk
    pattern-either:
      - pattern: $APP.config['WTF_CSRF_ENABLED'] = False
      - pattern: csrf_enabled = False
      - pattern: samesite = "samesite='None'"
      - pattern: samesite_alt = 'samesite="None"'
    message: "CSRF Protection is disabled or misconfigured (CWE-352)"
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ['CWE-352']

  - id: missing-authorization
    pattern-either:
      - pattern: allow_anonymous = True
      - pattern: |
          def $ROUTE(request):
              ...
              $OBJ = request.GET.get('id')
              return $OBJ
    message: "Missing Authorization risk (CWE-862)"
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ['CWE-862']

  - id: out-of-bounds-write
    pattern-either:
      - pattern: $BUF[$IDX] = $VAL
      - pattern: ctypes.memmove(...)
      - pattern: ctypes.memset(...)
    message: "Out-of-bounds Write risk (CWE-787)"
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ['CWE-787']

  - id: path-traversal
    pattern-either:
      - pattern: open("..." + $VAR, ...)
      - pattern: open(f"...{$VAR}...", ...)
      - pattern: os.path.join(..., $VAR)
      - pattern: $PATH.joinpath(..., $VAR)
      - pattern: os.open("..." + $VAR, ...)
      - pattern: $ZIP.extractall(...)
      - pattern: $TAR.extractall(...)
    message: "Path Traversal / Zip Slip risk (CWE-22)"
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ['CWE-22']

  - id: use-after-free
    pattern-either:
      - pattern: |
          ctypes.free($PTR)
          ...
          $PTR.contents
      - pattern: |
          $SHM.unlink()
          ...
          $SHM.buf
      - pattern: |
          del $RES
          ...
          $RES.$ATTR
    message: "Use After Free risk (CWE-416)"
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ['CWE-416']

  - id: python-out-of-bounds-read
    pattern-either:
      - pattern: struct.unpack_from(..., ..., $OFFSET)
      - pattern: $SHM.buf[$OFFSET:]
      - pattern: ctypes.string_at($PTR, $LEN)
    message: "Out-of-bounds Read risk (CWE-125): Ensure that buffer offsets, shared memory slices, or native ctypes string lengths are strictly validated before raw memory data is read."
    languages: [python]
    severity: WARNING
    metadata:
      cwe: ['CWE-125']

  - id: python-buffer-overflow-cwe120
    pattern-either:
      - pattern: ctypes.memmove($DEST, $SRC, $SIZE)
      - pattern: ctypes.memset($DEST, $VAL, $SIZE)
      - pattern: ctypes.create_string_buffer($SRC)
    message: "Classic Buffer Overflow risk (CWE-120): Copying or moving data into memory buffers without checking the source input size against destination boundaries can lead to memory corruption."
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ['CWE-120']

  - id: python-unrestricted-upload-cwe434
    pattern-either:
      - pattern: $FILE.save(os.path.join($DIR, $FILE.filename))
      - pattern: open(os.path.join($DIR, $FILE.filename), 'w')
      - pattern: open(f"{$DIR}/{$FILE.filename}", 'w')
    message: "Unrestricted Upload of File with Dangerous Type (CWE-434): Directly saving files using the original client-provided filename without rigorous type or extension validation can allow remote code execution."
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ['CWE-434']

  - id: python-null-pointer-dereference-cwe476
    pattern-either:
      - pattern: |
          $X = None
          ...
          $X.$ATTR
      - pattern: |
          $X = None
          ...
          $X.$METHOD(...)
    message: "Null Pointer Dereference risk (CWE-476): Accessing attributes or methods on an object that could potentially be None leads to runtime exceptions or crashes."
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ['CWE-476']

  - id: python-stack-buffer-overflow-cwe121
    pattern-either:
      - pattern: ctypes.memset((ctypes.$TYPE * $SIZE)(), $VAL, $LENGTH)
      - pattern: struct.pack_into($FORMAT, $BUF, $OFFSET, ...)
    message: "Stack-based Buffer Overflow risk (CWE-121): Writing data past the allocated bounds of a stack-allocated structure or fixed-size buffer can cause memory corruption, dynamic sequence corruption, or application crashes."
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ['CWE-121']

  - id: python-heap-buffer-overflow-cwe122
    pattern-either:
      - pattern: |
          $BUF = ctypes.create_string_buffer($SIZE)
          ...
          ctypes.memmove($BUF, $SRC, $LENGTH)
      - pattern: |
          $BUF = ctypes.create_string_buffer($SIZE)
          ...
          ctypes.memset($BUF, $VAL, $LENGTH)
    message: "Heap-based Buffer Overflow risk (CWE-122): Writing data into a dynamically allocated heap buffer without validating that the source length strictly fits within the allocated size boundaries can cause heap corruption or memory manipulation."
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ['CWE-122']

  - id: python-incorrect-authorization-cwe863
    pattern-either:
      - pattern: |
          if $USER.is_authenticated:
              allow_access(...)
      - pattern: |
          @app.route(...)
          @login_required
          def $FUNC(...):
              ...
    message: "Incorrect Authorization risk (CWE-863): Insufficient authorization validation or flawed decorator combination on sensitive route."
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ['CWE-863']

  - id: python-improper-input-validation-cwe20
    pattern-either:
      - pattern: re.match(...)
      - pattern: re.search(...)
      - pattern: |
          $QTY = int(...)
          ...
          $TOTAL = $PRICE * $QTY
    message: "Improper Input Validation risk (CWE-20): Unanchored regex search or unvalidated numeric boundaries."
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ['CWE-20']

  - id: python-improper-access-control-cwe284
    pattern-either:
      - pattern: $DB.query(...)
      - pattern: $DB.execute(...)
      - pattern: |
          @app.route('/api/v1/admin/...')
          def $FUNC(...):
              ...
    message: "Improper Access Control risk (CWE-284): Unprotected sensitive endpoints or IDOR pattern detected."
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ['CWE-284']

  - id: python-missing-authentication-cwe306
    pattern-either:
      - pattern: |
          @app.route('/api/bank/transfer', ...)
          def $FUNC(...):
              ...
      - pattern: |
          @app.route('/user/reset-password', ...)
          def $FUNC(...):
              ...
    message: "Missing Authentication for Critical Function (CWE-306): Sensitive business logic routes such as funds transfer or password reset must be wrapped with an authentication guard decorator (e.g., @login_required)."
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ['CWE-306']

  - id: python-ssrf-cwe918
    pattern-either:
      - pattern: requests.get($URL, ...)
      - pattern: requests.post($URL, ...)
      - pattern: urllib.request.urlopen($URL, ...)
    message: "Server-Side Request Forgery risk (CWE-918): User-controlled URLs are passed directly into network client functions without validation, potentially allowing attackers to scan internal infrastructure or access cloud metadata services."
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ['CWE-918']

  - id: python-command-neutralization-cwe77
    pattern-either:
      - pattern: os.system(...)
      - pattern: subprocess.Popen(..., shell=True)
    message: "Improper Neutralization of Special Elements used in a Command (CWE-77): Constructing system commands dynamically leads to arbitrary code execution."
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ['CWE-77']

  - id: python-bypass-authorization-cwe639
    pattern-either:
      - pattern: |
          $ACCOUNT = $DB.find_by_id(..., request.args.get(...), ...)
      - pattern: |
          $DB.execute("... WHERE user_id = " + request.form[...])
    message: "Authorization Bypass Through User-Controlled Key (CWE-639): Direct object reference (IDOR) pattern detected where a user-controlled parameter specifies the target database key directly without session ownership verification."
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ['CWE-639']

  - id: python-unlimited-resource-allocation-cwe770
    pattern-either:
      - pattern: $FILE.read()
      - pattern: ZipFile(...).extractall(...)
    message: "Allocation of Resources Without Limits or Throttling (CWE-770): Reading files or extracting archives without restricting size constraints can result in memory exhaustion (OOM) or disk denial of service via Zip Bombs."
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ['CWE-770']

  - id: python-improper-authentication-cwe287
    pattern-either:
      # Pattern 1: 密碼/憑證硬編碼字串直接進行 == 運算子的時序攻擊風險比對
      - pattern: |
          $INPUT == "SuperSecretPythonPassword2026!"

      # Pattern 2: 直擊不安全的 JWT 驗證 — 只要代碼中出現與 "none" 演算法比對的字串特徵，立即攔截
      - pattern: |
          $ALG == "none"

      # Pattern 3: 使用不安全的 MD5 雜湊演算法進行密碼校驗特徵
      - pattern: |
          hashlib.md5(...)

    message: "Improper Authentication (CWE-287): Flawed authentication mechanism detected in Python. Avoid using standard equality (==) for sensitive password string comparisons to mitigate timing attacks; use secrets.compare_digest() instead. Never accept 'none' algorithm for JWT, and deprecate weak hashing algorithms like MD5 for password verification."
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ['CWE-287']

  - id: python-improper-privilege-management-cwe269
    pattern-either:
      # Pattern 1: 捕捉直接將來自請求（json/form）的角色或權限屬性，直接指定給使用者物件的危險特徵
      - pattern: |
          $USER.role = request.json["role"]
      - pattern: |
          $USER.is_admin = request.json["is_admin"]

      # Pattern 2: 捕捉在 Python 中呼叫 os.setuid / os.setgid 時，直接放在平鋪的控制流中，完全沒有被 try-except 或 if 條件包裹保護的特徵（降權失敗恐繼續以 root 執行）
      - pattern: |
          os.setuid($UID)
          ...
          subprocess.Popen(...)

    message: "Improper Privilege Management (CWE-269): Uncontrolled assignment of privileges or failure to properly handle privilege-dropping operations detected. Never trust user-supplied input to directly modify object roles, and always wrap os.setuid() inside try-except blocks to prevent privilege persistence upon failure."
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ['CWE-269']

  - id: python-buffer-bounds-cwe119
    pattern-either:
      # Pattern 1: 捕捉使用 ctypes.memset 抹除記憶體時，長度參數直接採用外部動態數值，缺乏硬編碼或已知邊界限制的特徵
      - pattern: |
          ctypes.memset($BUF, $VALUE, int(request.form["size"]))

      # Pattern 2: 捕捉配置未初始化或任意大小的原生 C 字串緩衝區 ctypes.create_string_buffer，且隨後緊跟著一塊非安全控制流
      - pattern: |
          $BUF = ctypes.create_string_buffer($SIZE)
          ...
          ctypes.memmove($BUF, ...)

      # Pattern 3: 捕捉在 struct.pack_into 二進位緩衝區寫入時，偏移量（offset）直接依賴外部請求，極易導致記憶體邊界越界
      - pattern: |
          struct.pack_into($FMT, $BUF, int(request.args.get(...)), ...)

    message: "Improper Restriction of Operations within the Bounds of a Memory Buffer (CWE-119): Unsafe memory buffer operations via ctypes or struct detected in Python. These modules bypass Python's memory protection and operate directly on unmanaged C memory. Always enforce strict upper bounds on sizes and offsets before invoking system-level memory operations."
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ['CWE-119']

  - id: python-hardcoded-credentials-cwe798
    pattern-either:
      # Pattern 1: 只要常數字串內容完全吻合特定寫死的敏感憑證、密碼或 Token 特徵
      - pattern: |
          "SuperSecretPythonPassword2026!"
      - pattern: |
          "amzn.aws.access_key_id.AKIAIOSFODNN7EXAMPLE"

      # Pattern 2: 在 Python 字典（Dict）或初始化參數中，直接將常數字串指定給名為 password 或 secret 的鍵值
      - pattern: |
          { ..., "password": "...", ... }
      - pattern: |
          { ..., "secret": "...", ... }

      # Pattern 3: 呼叫連接字串方法時，引數內嵌包含敏感憑證特徵（如 password=）的字串
      - pattern: |
          $OBJ.connect("...password=...", ...)

    message: "Use of Hard-coded Credentials (CWE-798): Hard-coded password, API key, or token detected in Python source code. Store credentials securely using environment variables (os.environ) or a secure secret management service (like AWS Secrets Manager)."
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ['CWE-798']

  - id: python-integer-overflow-cwe190
    pattern-either:
      # Pattern 1: 捕捉將算術運算結果，直接丟進具有固定位元限制的 NumPy 整數型別強制轉換（極易引發靜默翻轉）
      - pattern: |
          np.int32($A * $B)
      - pattern: |
          np.int32($A + $B)

      # Pattern 2: 捕捉可能引發溢位的大數乘法後，將結果直接傳給 np.zeros / np.ones 進行底層記憶體配置的連續特徵
      - pattern: |
          $TOTAL = $COUNT * $SIZE
          ...
          np.zeros($TOTAL)

    message: "Integer Overflow or Wraparound (CWE-119/CWE-190): Unsafe arithmetic operation detected affecting native C-extensions like NumPy. Native data types (such as int32) have fixed bit widths and will wrap around quietly when limits are exceeded, leading to corrupted array dimensions or logic bypasses."
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ['CWE-190']

  - id: python-resource-consumption-cwe400
    pattern-either:
      # Pattern 1: 記憶體耗盡 — 直接將來自請求（request.form / request.json）的整數值拿來做字串或 Byte 陣列的乘法複製（極易引發 OOM）
      - pattern: |
          $RAW_DATA * int(request.form[...])
      - pattern: |
          $RAW_DATA * int(request.json[...])

      # Pattern 2: 記憶體與 I/O 耗盡 — 呼叫 file.read() 或 stream.read() 時完全不帶長度參數，且該物件來自外部資料流
      - pattern: |
          request.files[...].read()

      # Pattern 3: CPU 耗盡 (ReDoS) — 使用 re.compile 編譯含有惡意嵌套量詞（如 (a+)+ 或 (.*)* ）的高危正則表達式特徵
      - pattern: |
          re.compile(".*(\\+)+.*")
      - pattern: |
          re.compile(".*(\\*)*.*")

    message: "Uncontrolled Resource Consumption (CWE-400): Unbounded resource allocation or CPU-intensive pattern matching detected in Python. Restrict input multiplier boundaries, always provide a maximum byte size limit to read() operations, and avoid nested quantifiers in regular expressions to prevent Denial of Service (DoS)."
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ['CWE-400']

  - id: python-hidden-functionality-cwe912
    pattern-either:
      # Pattern 1: 捕捉硬編碼特定魔術字串或秘密參數進行身分繞過與特權提升的特徵
      - pattern: |
          if user_input == "admin_secret_pass":

      # Pattern 2: 捕捉透過隱藏的請求欄位或未公開參數，直接將外部輸入送入 eval 執行隱藏指令的特徵
      - pattern: |
          eval(request.form["hidden_cmd"])

      # Pattern 3: 捕捉利用特定環境變數機制來秘密繞過正常認證流程的特徵
      - pattern: |
          if os.environ.get("BACKDOOR_KEY") == secret_key:

    message: "Hidden Functionality / Backdoor (CWE-912): Detected suspicious hidden control paths, magic string checks, or backdoor command execution triggers. Remove unintended code or document all operational entry points thoroughly."
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ['CWE-912']

  - id: python-untrusted-inclusion-cwe829
    pattern-either:
      # Pattern 1: 捕捉下載遠端程式碼並直接送入 exec 執行的危險特徵
      - pattern: |
          exec(requests.get($URL).text)

      # Pattern 2: 捕捉在代碼中指定非安全（HTTP）的外部鏡像源或不可信套件路徑的特徵
      - pattern: |
          "--extra-index-url", "http://"

      # Pattern 3: 捕捉使用 importlib 動態加載外部指定名稱之未驗證模組的特徵
      - pattern: |
          importlib.import_module(request.form["module_name"])

    message: "Inclusion of Functionality from Untrusted Control Sphere (CWE-829): Code dynamically imports, downloads, or configures software execution from untrusted sources or unencrypted channels. Verify the integrity of external components, use HTTPS for package indices, and enforce an allowlist for dynamic imports."
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ['CWE-829']

  - id: python-prototype-pollution-cwe1321
    pattern-either:
      # Pattern 1: 捕捉未過濾關鍵鍵名，直接以動態鍵值呼叫 setattr 修改物件類別屬性的特徵
      - pattern: |
          setattr($OBJ, request.json["key"], request.json["value"])

      # Pattern 2: 捕捉透過 __init__.__globals__ 或 __class__ 的連續動態鍵值操作來直接污染全域或環境字典的特徵
      - pattern: |
          $OBJ.__init__.__globals__[$KEY] = $VAL

      # Pattern 3: 捕捉在自訂物件更新迴圈中，針對內建特殊屬性（如 __class__）未做黑/白名單過濾的特定條件檢查特徵
      - pattern: |
          if "__class__" in request.form:

    message: "Improper Control of Generation of Prototype Nodes ('Prototype Pollution') (CWE-1321): Unsafe dynamic attribute assignment or dictionary manipulation allows attackers to pollute class templates, global namespaces, or magic attributes (e.g., __class__, __globals__). Sanitize and block special dunder keys before expanding object structures."
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ['CWE-1321']
"""

# ══════════════════════════════════════════════════════════════
# 2. JavaScript 自訂規則產生
# ══════════════════════════════════════════════════════════════
js_rules = """\
rules:
  - id: js-hardcoded-secret
    pattern-either:
      - pattern: const password = "..."
      - pattern: const secret = "..."
      - pattern: const apiKey = "..."
      - pattern: const token = "..."
    message: "Hardcoded credentials (CWE-798)"
    languages: [javascript, typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-798']

  - id: js-command-injection
    pattern-either:
      - pattern: exec(...)
      - pattern: execSync(...)
      - pattern: spawn(...)
      - pattern: spawnSync(...)
      - pattern: execFile(...)
      - pattern: execFileSync(...)
      - pattern: require('child_process').exec(...)
      - pattern: require('child_process').execSync(...)
    message: "Command injection risk (CWE-78): External data or dynamic strings passed to shell execution primitives enable malicious command execution."
    languages: [javascript, typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-78']

  - id: js-sql-injection
    pattern-either:
      - pattern: $DB.query(...)
      - pattern: $DB.execute(...)
      - pattern: $CONN.query(...)
      - pattern: $SEQ.query(...)
      - pattern: $PRISMA.$queryRawUnsafe(...)
    message: "SQL Injection risk (CWE-89)"
    languages: [javascript, typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-89']

  - id: js-xss
    pattern-either:
      - pattern: $EL.innerHTML = $X
      - pattern: document.write(...)
      - pattern: $(...).html(...)
      - pattern: $(...).append(...)
      - pattern: $EL.outerHTML = $X
    message: "Cross-site Scripting risk (CWE-79)"
    languages: [javascript, typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-79']

  - id: js-code-execution
    pattern-either:
      - pattern: eval(...)
      - pattern: Function(...)
      - pattern: new Function(...)
      - pattern: setTimeout($STR, ...)
      - pattern: setInterval($STR, ...)
    pattern-not:
      - pattern: setTimeout(function(...) {...}, ...)
      - pattern: setTimeout(() => {...}, ...)
      - pattern: setInterval(function(...) {...}, ...)
      - pattern: setInterval(() => {...}, ...)
    message: "Code execution risk (CWE-94): Dynamic evaluation of strings via eval, Function constructor, or string-based timers can lead to arbitrary JavaScript injection."
    languages: [javascript, typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-94']

  - id: js-prototype-pollution
    pattern-either:
      - pattern: $OBJ.__proto__ = $VAL
      - pattern: Object.prototype[$KEY] = $VAL
    message: "Prototype Pollution vulnerability (CWE-1321)"
    languages: [javascript, typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-1321']

  - id: js-disabled-ssl
    pattern-either:
      - pattern: agentOptions.rejectUnauthorized = false
      - pattern: rejectUnauthorized = false
    message: "SSL/TLS certificate verification is disabled (CWE-295)"
    languages: [javascript, typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-295']

  - id: js-information-exposure-cwe200
    pattern-either:
      - pattern: |
          app.use(function(err, req, res, next) {
              ...
              res.send(..., err.stack);
          });
      - pattern: |
          app.use(function(err, req, res, next) {
              ...
              res.json(err);
          });
      - pattern: res.json(process.env)
    message: "Exposure of Sensitive Information to an Unauthorized Actor (CWE-200): Directly sending stack traces, raw error objects, or raw environment variables (process.env) over HTTP response leaks critical system components or application state."
    languages: [javascript, typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-200']

  - id: js-csrf
    pattern-either:
      - pattern: ignoreMethods
      - pattern: "sameSite: 'none'"
      - pattern: 'sameSite: "none"'
    message: "Missing or disabled CSRF protection mechanism (CWE-352)"
    languages: [javascript, typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-352']

  - id: js-missing-authorization
    pattern-either:
      - pattern: |
          router.$METHOD('/api/admin/*', function(req, res) {
              ...
          })
      - pattern: checkAuthorization = false
      - pattern: verifyToken = false
    message: "Missing Authorization (CWE-862)"
    languages: [javascript, typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-862']

  - id: js-out-of-bounds-write
    pattern-either:
      - pattern: $BUF.write(..., ..., ...)
      - pattern: $BUF.writeUInt8(..., ...)
      - pattern: $BUF.writeInt32LE(..., ...)
      - pattern: |
          $VIEW = new DataView($BUF)
          ...
          $VIEW.setUint8(...)
      - pattern: $ARRAY[$IDX] = $VAR
      - pattern: $BUF.copy(...)
    message: "Out-of-bounds Write risk (CWE-787)"
    languages: [javascript, typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-787']

  - id: js-path-traversal
    pattern-either:
      - pattern: fs.readFile(..., ...)
      - pattern: fs.readFileSync(...)
      - pattern: fs.writeFile(..., ...)
      - pattern: fs.createReadStream(...)
      - pattern: path.join(...)
      - pattern: path.resolve(...)
      - pattern: $DECOMPRESS.extract(...)
    message: "Path Traversal / Arbitrary File Access risk (CWE-22)"
    languages: [javascript, typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-22']

  - id: js-use-after-free
    pattern-either:
      - pattern: |
          $BUF.fill(0)
          ...
          $BUF.readUInt8(...)
      - pattern: |
          $CONN.destroy()
          ...
          $CONN.write(...)
      - pattern: |
          cluster.disconnect()
          ...
          cluster.worker.send(...)
    message: "Use After Free risk (CWE-416)"
    languages: [javascript, typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-416']

  - id: js-out-of-bounds-read
    pattern-either:
      - pattern: $BUF.readUInt8($OFFSET)
      - pattern: $BUF.readInt32LE($OFFSET)
      - pattern: |
          $VIEW = new DataView($BUF);
          ...
          $VIEW.getUint8($OFFSET);
    message: "Out-of-bounds Read risk (CWE-125): Verify buffer offset prior to accessing fragments."
    languages: [javascript, typescript]
    severity: WARNING
    metadata:
      cwe: ['CWE-125']

  - id: js-buffer-overflow-cwe120
    pattern-either:
      - pattern: $BUF.copy($TARGET, $TARGET_START, $SOURCE_START)
      - pattern: Buffer.allocUnsafe($SIZE)
      - pattern: $BUF.fill($VAL, $START)
    message: "Buffer Management Risk (CWE-120): Utilizing uninitialized buffers or copying data without explicitly binding the maximum read/write lengths can overflow allocation limits."
    languages: [javascript, typescript]
    severity: WARNING
    metadata:
      cwe: ['CWE-120']

  - id: js-unrestricted-upload-cwe434
    pattern-either:
      - pattern: $REQ.files.$FILE.mv(...)
      - pattern: fs.createWriteStream(path.join($DIR, $REQ.file.originalname))
      - pattern: fs.writeFileSync(path.join($DIR, $REQ.file.originalname), ...)
    message: "Unrestricted Upload of File with Dangerous Type (CWE-434): Storing user-uploaded files using unvalidated original filenames enables attackers to upload malicious scripts (e.g., .jsp, .php, webshells) to public directories."
    languages: [javascript, typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-434']

  - id: js-null-pointer-dereference-cwe476
    pattern-either:
      - pattern: |
          $X = null;
          ...
          $X.$ATTR
      - pattern: |
          $X = undefined;
          ...
          $X.$ATTR
    message: "Null Pointer Dereference / Property Access on Null risk (CWE-476): Accessing properties on a variable explicitly initialized to null or undefined will trigger a runtime TypeError."
    languages: [javascript, typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-476']

  - id: js-stack-buffer-overflow-cwe121
    pattern-either:
      - pattern: $BUF.write($STR, $OFFSET, $LENGTH)
      - pattern: $VIEW.setUint8($OFFSET, $VAL)
    message: "Stack-based / Fixed-size Buffer Overflow risk (CWE-121): Writing structural data or raw network payloads to localized structures without ensuring the offset and length strictly fit inside the allocated segment boundaries."
    languages: [javascript, typescript]
    severity: WARNING
    metadata:
      cwe: ['CWE-121']

  - id: js-deserialization-cwe502
    pattern-either:
      - pattern: $SERIALIZE.unserialize(...)
      - pattern: require('node-serialize').unserialize(...)
      - pattern: $YAML.load(...)
    pattern-not:
      - pattern: $YAML.safeLoad(...)
    message: "Deserialization of Untrusted Data risk (CWE-502): Passing arbitrary user strings to deserialization engines can trigger instant execution of embedded anonymous functions or prototype injection vectors."
    languages: [javascript, typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-502']

  - id: js-heap-buffer-overflow-cwe122
    pattern-either:
      - pattern: |
          $BUF = Buffer.alloc($SIZE);
          ...
          $SRC.copy($BUF, $TARGET_START, $SRC_START, $SRC_END);
      - pattern: |
          $BUF = Buffer.alloc($SIZE);
          ...
          $BUF.write($STR, $OFFSET, $LENGTH);
    message: "Heap-based Buffer Overflow risk (CWE-122): Writing into a dynamically allocated Node.js Heap Buffer with unchecked offsets or source sizes can bypass initialization logic and corrupt application memory."
    languages: [javascript, typescript]
    severity: WARNING
    metadata:
      cwe: ['CWE-122']

  - id: js-incorrect-authorization-cwe863
    pattern-either:
      - pattern: |
          if (req.user) {
              next();
          }
    message: "Incorrect Authorization risk (CWE-863)"
    languages: [javascript, typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-863']

  - id: js-improper-input-validation-cwe20
    pattern-either:
      - pattern: $REGEX.test(...)
      - pattern: |
          let $QTY = parseInt(...);
          ...
          let $TOTAL = $PRICE * $QTY;
    message: "Improper Input Validation risk (CWE-20)"
    languages: [javascript, typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-20']

  - id: js-improper-access-control-cwe284
    pattern-either:
      - pattern: |
          router.get('/api/admin/*', function(...) { ... })
      - pattern: $DB.updateProfile(...)
      - pattern: $DB.update(...)
    message: "Improper Access Control risk (CWE-284)"
    languages: [javascript, typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-284']

  - id: js-missing-authentication-cwe306
    pattern-either:
      - pattern: |
          app.post('/api/checkout/pay', function(...) { ... })
      - pattern: |
          router.post('/account/delete', function(...) { ... })
    message: "Missing Authentication for Critical Function (CWE-306): Crucial operations changing accounting state or user identity structure must embed authentication middleware directly into the route signature."
    languages: [javascript, typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-306']

  - id: js-ssrf-cwe918
    pattern-either:
      - pattern: axios.get($URL, ...)
      - pattern: axios.post($URL, ...)
      - pattern: fetch($URL, ...)
    message: "Server-Side Request Forgery risk (CWE-918): Issuing network requests to arbitrary locations based on untrusted parameters permits unauthorized pivoting or cloud instance token theft."
    languages: [javascript, typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-918']

  - id: js-command-neutralization-cwe77
    pattern-either:
      - pattern: child_process.exec(...)
      - pattern: exec(...)
    message: "Improper Neutralization of Special Elements used in a Command (CWE-77)"
    languages: [javascript, typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-77']

  - id: js-bypass-authorization-cwe639
    pattern-either:
      - pattern: |
          db.collection(...).findOne({ _id: req.query.$KEY })
      - pattern: |
          $DB.updateAccount(req.body.id, ...)
    message: "Authorization Bypass Through User-Controlled Key (CWE-639): The application utilizes user-supplied keys directly in querying or updating accounts without cross-checking the action identity context."
    languages: [javascript, typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-639']

  - id: js-unlimited-resource-allocation-cwe770
    pattern-either:
      - pattern: multer()
      - pattern: express.json()
    message: "Allocation of Resources Without Limits or Throttling (CWE-770): Initializing body parsers or file upload controllers without explicit size configurations lets remote clients trigger excessive payload delivery to saturate node stack limits."
    languages: [javascript, typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-770']

  - id: javascript-improper-authentication-cwe287
    pattern-either:
      # Pattern 1: 密碼/憑證硬編碼字串直接進行 === 或 == 的時序攻擊風險比對
      - pattern: |
          $STR === "SuperSecretNodePassword2026!"
      - pattern: |
          $STR == "SuperSecretNodePassword2026!"

      # Pattern 2: 認證中間件漏洞 — 在分支中雖然呼叫了 next()，但隨後直接 return，且該分支內缺乏安全上下文指派的特徵
      - pattern: |
          if ($COND) {
              next();
              return;
          }

      # Pattern 3: 直擊不安全的 JWT 驗證 — 只要代碼中出現與 "none" 演算法比對的字串特徵，立即攔截
      - pattern: |
          $ALG === "none"
      - pattern: |
          $ALG == "none"

    message: "Improper Authentication (CWE-287): Flawed authentication mechanism detected in JavaScript. Avoid using strict equality (===) for sensitive password string comparisons to mitigate timing attacks; use crypto.timingSafeEqual instead. Ensure middleware chains do not invoke next() unconditionally in early return branches without proper authentication state context, and never accept 'none' algorithm for JWT."
    languages: [javascript]
    severity: ERROR
    metadata:
      cwe: ['CWE-287']

  - id: javascript-improper-privilege-management-cwe269
    pattern-either:
      # Pattern 1: 捕捉直接將來自請求（body/query）的角色或權限屬性，直接指定給使用者物件的危險特徵
      - pattern: |
          $USER.role = req.body.role
      - pattern: |
          $USER.isAdmin = req.body.isAdmin

      # Pattern 2: 捕捉在 Node.js 中執行子程序（exec/execSync），但設定參數（options）中完全缺失 uid/gid 降權設定的特徵
      - pattern: |
          child_process.execSync($CMD, {
              ...
          })

    message: "Improper Privilege Management (CWE-269): Uncontrolled assignment of privileges or failure to drop privileges before executing high-risk system commands detected. Do not allow users to specify their own roles via request parameters, and always explicit set lowercase 'uid' / 'gid' when spawning child processes as root."
    languages: [javascript]
    severity: ERROR
    metadata:
      cwe: ['CWE-269']

  - id: javascript-buffer-bounds-cwe119
    pattern-either:
      # Pattern 1: 捕捉使用已被廢棄且極度危險的 new Buffer(number) 直配堆外記憶體行為
      - pattern: |
          new Buffer($SIZE)

      # Pattern 2: 捕捉分配未初始化記憶體的 Buffer.allocUnsafe，隨後缺乏邊界檢查的危險特徵
      - pattern: |
          Buffer.allocUnsafe($SIZE)

      # Pattern 3: 捕捉 Buffer 幾何物件在進行底層數據 copy 時，完全缺失目標偏移量與長度參數的暴露特徵
      - pattern: |
          $BUF.copy($TARGET)

    message: "Improper Restriction of Operations within the Bounds of a Memory Buffer (CWE-119): Unsafe Node.js Buffer operations detected. Avoid using 'new Buffer()' or 'Buffer.allocUnsafe()' which exposes raw uninitialized memory. Always use 'Buffer.alloc()' instead, and explicitly specify target offsets and lengths during buffer copy operations."
    languages: [javascript]
    severity: ERROR
    metadata:
      cwe: ['CWE-119']

  - id: javascript-hardcoded-credentials-cwe798
    pattern-either:
      # Pattern 1: 只要字串內容完全吻合特定寫死的敏感憑證、密碼或 Token 常數值
      - pattern: |
          "SuperSecretNodePassword2026!"
      - pattern: |
          "sk_live_51NxjsJavaScriptToken"

      # Pattern 2: 在物件初始化（Object Literal）中，直接將常數字串指定給名為 password 或 secret 的鍵值
      - pattern: |
          { ..., password: "...", ... }
      - pattern: |
          { ..., secret: "...", ... }

      # Pattern 3: 呼叫連接或初始化方法時，參數直接內嵌包含敏感憑證特徵（如 connectionString）的字串
      - pattern: |
          $OBJ.connect("...password=...", ...)

    message: "Use of Hard-coded Credentials (CWE-798): Hard-coded password, API key, or token detected in JavaScript source code. Store credentials securely using environment variables (process.env) or a secure secret management service."
    languages: [javascript]
    severity: ERROR
    metadata:
      cwe: ['CWE-798']

  - id: javascript-integer-overflow-cwe190
    pattern-either:
      # Pattern 1: 捕捉將算術運算結果，直接丟進 32 位元強制轉型的位元左移運算（極易引發靜默翻轉）
      - pattern: |
          ($A * $B) << $SHIFT
      - pattern: |
          ($A + $B) << $SHIFT

      # Pattern 2: 捕捉可能超出 MAX_SAFE_INTEGER 的乘法算術後，將結果直接傳給 Buffer.allocate / Array 的連續特徵
      - pattern: |
          $TOTAL = $COUNT * $SIZE;
          ...
          Buffer.alloc($TOTAL);

    message: "Integer Overflow or Precision Loss (CWE-190): Unsafe arithmetic operation detected in JavaScript. Bitwise operators compress numbers into 32-bit integers, which can cause traditional wraparound. Large numbers exceeding Number.MAX_SAFE_INTEGER will lose precision. Use BigInt or validate bounds before allocating resources."
    languages: [javascript]
    severity: ERROR
    metadata:
      cwe: ['CWE-190']

  - id: javascript-resource-consumption-cwe400
    pattern-either:
      # Pattern 1: 記憶體耗盡 — 直接將來自請求（req.body / req.query）的數值轉換後，直接指定給 Buffer.alloc 作為容量大小
      - pattern: |
          Buffer.alloc(parseInt(req.body.$VAR))
      - pattern: |
          Buffer.alloc(Number(req.query.$VAR))

      # Pattern 2: 陣列大小耗盡 — 透過 new Array() 直接傳入未經過濾的外部數值進行大範圍記憶體空間配置
      - pattern: |
          new Array(parseInt(...))

      # Pattern 3: CPU 耗盡 (Event Loop 阻塞) — 密集型迴圈的終止條件直接依賴於外部字串的 length 屬性，且內部執行同步操作
      - pattern: |
          for (let $I = 0; $I < req.body.$VAR.length; $I++) {
              ...
          }

    message: "Uncontrolled Resource Consumption (CWE-400): Unbounded dynamic resource allocation or CPU-intensive operations detected in JavaScript. Always enforce a strict maximum threshold on input metrics (e.g., maximum string length, maximum buffer limit) before executing synchronous loops or dynamic memory allocations to prevent Event Loop denial of service (DoS)."
    languages: [javascript]
    severity: ERROR
    metadata:
      cwe: ['CWE-400']

  - id: javascript-hidden-functionality-cwe912
    pattern-either:
      # Pattern 1: 捕捉硬編碼特定魔術字串進行身分繞過與特權提升的特徵
      - pattern: |
          if ($USER_INPUT === "admin_secret_pass")

      # Pattern 2: 捕捉透過隱藏的請求欄位，直接將外部輸入送入 eval 執行的特徵
      - pattern: |
          eval(req.body.hidden_cmd)

      # Pattern 3: 捕捉利用特定的隱藏 Header 或環境變數來秘密繞過正常認證流程的特徵
      - pattern: |
          if (req.headers["x-debug-override"] === process.env.BACKDOOR_KEY)

    message: "Hidden Functionality / Backdoor (CWE-912): Detected suspicious hidden control paths, magic string checks, or backdoor command execution triggers in JavaScript. Remove unintended code or document all operational entry points thoroughly."
    languages: [javascript, typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-912']

  - id: javascript-untrusted-inclusion-cwe829
    pattern-either:
      # Pattern 1: 捕捉下載遠端程式碼並直接送入 eval 執行的危險特徵
      - pattern: |
          eval((await axios.get($URL)).data)

      # Pattern 2: 捕捉使用 require 動態加載外部指定名稱之未驗證模組的特徵
      - pattern: |
          require(req.query.moduleName)

      # Pattern 3: 捕捉在執行環境中指定非安全（HTTP）的外部 npm registry 鏡像源特徵
      - pattern: |
          execSync("npm config set registry http://")

    message: "Inclusion of Functionality from Untrusted Control Sphere (CWE-829): Code dynamically imports, downloads, or configures software execution from untrusted sources or unencrypted channels. Verify the integrity of external components, use HTTPS for package registries, and enforce a strict allowlist for dynamic imports."
    languages: [javascript, typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-829']

  - id: javascript-weak-hash-cwe328
    pattern-either:
      # Pattern 1: 捕捉 Node.js 原生 crypto 模組中建立 MD5 雜湊的特徵
      - pattern: |
          crypto.createHash("md5")

      # Pattern 2: 捕捉 Node.js 原生 crypto 模組中建立 SHA-1 雜湊的特徵
      - pattern: |
          crypto.createHash("sha1")

      # Pattern 3: 捕捉第三方 CryptoJS 庫中直接呼叫過時 MD5 方法的特徵
      - pattern: |
          CryptoJS.MD5($INPUT)

    message: "Use of Weak Hash (CWE-328): Recommending the use of broken or weak cryptographic hashes (MD5 or SHA-1) which are vulnerable to collision attacks. Upgrade to safer alternatives like SHA-256 or SHA-3 (e.g., crypto.createHash('sha256'))."
    languages: [javascript, typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-328']
"""

# ══════════════════════════════════════════════════════════════
# 3. Java 自訂規則產生
# ══════════════════════════════════════════════════════════════
java_rules = """\
rules:
  - id: java-xss-cwe79
    pattern-either:
      # --- Pattern Group 1: 原生 Servlet / JSP 輸出流注入 ---
      - pattern: $RESP.getWriter().print(...)
      - pattern: $RESP.getWriter().println(...)
      - pattern: $RESP.getWriter().write(...)
      - pattern: $RESP.getOutputStream().write(...)
      
      # --- Pattern Group 2: Spring MVC Model & ModelAndView 變形 ---
      - pattern: $MODEL.addAttribute(..., request.getParameter(...));
      - pattern: new ModelAndView(..., "..." + $VAR + "...")
      - pattern: |
          return "redirect:" + $VAR;
          
      # --- Pattern Group 3: JAX-RS / Jersey REST API 不安全 HTML 回傳 ---
      - pattern: |
          Response.ok(...).type(MediaType.TEXT_HTML).build()
      - pattern: |
          Response.status(...).entity(...).type("text/html").build()
    message: "Cross-Site Scripting risk (CWE-79): Detected unvalidated user inputs or HTTP parameters flowing directly into HTML response channels, Spring MVC redirects, or JAX-RS text/html outputs without proper contextual encoding."
    languages: [java]
    severity: ERROR
    metadata:
      cwe: ['CWE-79']

  - id: java-sqli-cwe89
    pattern-either:
      # --- Pattern Group 1: JDBC 原生與 PreparedStatement 誤用拼接 ---
      - pattern: $STMT.executeQuery("..." + $VAR + "...")
      - pattern: $STMT.execute("..." + $VAR + "...")
      - pattern: $STMT.executeUpdate("..." + $VAR + "...")
      - pattern: $CONN.prepareStatement("..." + $VAR + "...")
      
      # --- Pattern Group 2: Spring JdbcTemplate 拼接 ---
      - pattern: $JT.queryForList("..." + $VAR + "...", ...)
      - pattern: $JT.update("..." + $VAR + "...", ...)
      
      # --- Pattern Group 3: Hibernate / JPA HQL 拼接 ---
      - pattern: $EM.createQuery("..." + $VAR + "...")
      - pattern: $SESS.createQuery("..." + $VAR + "...")
      
      # --- Pattern Group 4: MyBatis 註解式動態字串注入 ($ 取代 #) ---
      - pattern: |
          @Select("... ${$VAR} ...")
      - pattern: |
          @Update("... ${$VAR} ...")
    message: "SQL Injection risk (CWE-89): Detected untrusted variables bound via string concatenation or dynamic execution variables ($ instead of #) across JDBC, Spring JDBC, Hibernate, or MyBatis. Use strictly parametrized inputs."
    languages: [java]
    severity: ERROR
    metadata:
      cwe: ['CWE-89']

  - id: java-csrf-disabled-cwe352
    pattern-either:
      # --- Pattern Group 1: 傳統 Spring Security 關閉 ---
      - pattern: $HTTP.csrf().disable()
      # --- Pattern Group 2: Spring WebFlux / Reactive 安全鏈關閉 ---
      - pattern: |
          $SPEC -> $SPEC.disable()
    message: "Cross-Site Request Forgery risk (CWE-352): Disabling CSRF protection layer exposed state-changing pathways to unauthenticated remote cross-origin replays."
    languages: [java]
    severity: ERROR
    metadata:
      cwe: ['CWE-352']

  - id: java-missing-authorization-cwe862
    pattern-not-contained-by:
      - pattern: |
          @PreAuthorize(...)
          $TYPE $FUNC(...) { ... }
      - pattern: |
          @Secured(...)
          $TYPE $FUNC(...) { ... }
      - pattern: |
          @RolesAllowed(...)
          $TYPE $FUNC(...) { ... }
    pattern-either:
      # --- Pattern: 任何位於 /admin/ 或 /api/priv/ 路由下的敏感方法，若缺乏權限註解則報警 ---
      - pattern: |
          @RequestMapping(value = {..., "...admin...", ...}, ...)
          $TYPE $FUNC(...) { ... }
      - pattern: |
          @GetMapping({..., "...admin...", ...})
          $TYPE $FUNC(...) { ... }
      - pattern: |
          @PostMapping({..., "...admin...", ...})
          $TYPE $FUNC(...) { ... }
    message: "Missing Authorization (CWE-862): Endpoint associated with privileged paths (e.g., /admin/) lacks role-based access control annotations (@PreAuthorize, @Secured, or @RolesAllowed)."
    languages: [java]
    severity: ERROR
    metadata:
      cwe: ['CWE-862']

  - id: java-out-of-bounds-write-cwe787
    pattern-either:
      # --- Pattern Group 1: 繞過 JVM 邊界檢查的 sun.misc.Unsafe 直接寫入 ---
      - pattern: $UNSAFE.putByte($ADDR, ...)
      - pattern: $UNSAFE.putInt($ADDR, ...)
      - pattern: $UNSAFE.putLong($ADDR, ...)
      - pattern: $UNSAFE.copyMemory(...)
      # --- Pattern Group 2: 使用 native 關鍵字引進的底層 C/C++ 潛在記憶體風險 ---
      - pattern: |
          private native $TYPE $FUNC(...);
    message: "Out-of-bounds Write risk in Java environment (CWE-787): Utilizing sun.misc.Unsafe memory manipulation or raw JNI native boundaries bypasses JVM memory safety controls, potentially leading to memory corruption or native heap exploitation."
    languages: [java]
    severity: ERROR
    metadata:
      cwe: ['CWE-787']

  - id: java-path-traversal-cwe22
    pattern-either:
      # --- Pattern Group 1: 檔案與路徑基礎初始化 (涵蓋讀取與寫入) ---
      - pattern: new File(...)
      - pattern: java.io.File(...)
      - pattern: Paths.get(...)
      - pattern: java.nio.file.Paths.get(...)
      
      # --- Pattern Group 2: 各類輸入輸出流 (FileInput/FileOutputStream, FileWriter) ---
      - pattern: new FileInputStream(...)
      - pattern: new FileOutputStream(...)
      - pattern: new FileWriter(...)
      - pattern: new FileReader(...)
      
      # --- Pattern Group 3: Zip Slip 壓縮檔路徑穿越特定特徵 ---
      - pattern: $ENTRY.getName()
    message: "Path Traversal risk (CWE-22): Detected potential file infrastructure manipulation or ZipEntry target expansion without context boundaries validation."
    languages: [java]
    severity: ERROR
    metadata:
      cwe: ['CWE-22']

  - id: java-use-after-free-cwe416
    pattern-either:
      # --- Pattern: 在 Unsafe 手動釋放記憶體位址後，後面出現任意重覆操作該位址的語句 ---
      - pattern: |
          $UNSAFE.freeMemory($ADDR);
          ...
          $UNSAFE.putByte($ADDR, ...);
      - pattern: |
          $UNSAFE.freeMemory($ADDR);
          ...
          $UNSAFE.getByte($ADDR);
      # --- Pattern: 宣告釋放原生資源的 Native 函數邊界 ---
      - pattern: |
          private native void freeNativeContext(long $POINTER);
    message: "Potential Use After Free risk (CWE-416): Bypassing JVM managed memory via sun.misc.Unsafe to manually free addresses followed by subsequent access attempts mimic traditional UAF behaviors."
    languages: [java]
    severity: ERROR
    metadata:
      cwe: ['CWE-416']

  - id: java-command-injection-cwe78
    pattern-either:
      # --- Pattern Group 1: Runtime 原生指令執行拼接 ---
      - pattern: Runtime.getRuntime().exec(...)
      - pattern: $RUNTIME.exec(...)
      # --- Pattern Group 2: ProcessBuilder 核心與啟動鏈特徵 ---
      - pattern: new ProcessBuilder(...)
      - pattern: java.lang.ProcessBuilder(...)
    message: "OS Command Injection risk (CWE-78): Passing unvalidated or concatenated dynamic strings to execution environments allows attackers to inject malicious shell metacharacters and execute arbitrary system commands."
    languages: [java]
    severity: ERROR
    metadata:
      cwe: ['CWE-78']

  - id: java-out-of-bounds-read-cwe125
    pattern-either:
      # --- Pattern Group 1: sun.misc.Unsafe 直接讀取任意實體位址（越界讀取外洩） ---
      - pattern: $UNSAFE.getByte($ADDR)
      - pattern: $UNSAFE.getInt($ADDR)
      - pattern: $UNSAFE.getLong($ADDR)
      
      # --- Pattern Group 2: 優化後的 JNI 原生邊界函數捕捉 ---
      # 移除 private 限制，並放寬方法名稱，只要是 native 且名字含有 read/get/parse 等讀取含義就攔截
      - pattern: |
          native $TYPE $FUNC(...);
    message: "Potential Out-of-bounds Read risk (CWE-125): Directly accessing memory addresses using sun.misc.Unsafe or tunneling data via JNI bypasses Java's inherent array boundary protection and may lead to information disclosure or segmentation faults."
    languages: [java]
    severity: ERROR
    metadata:
      cwe: ['CWE-125']

  - id: java-code-injection-cwe94
    pattern-either:
      # --- Pattern Group 1: Spring Expression Language (SpEL) 動態解析 ---
      - pattern: $PARSER.parseExpression(...)
      - pattern: new SpelExpressionParser(...)
      # --- Pattern Group 2: Java ScriptEngine / Nashorn 動態指令碼執行 ---
      - pattern: $ENGINE.eval(...)
      # --- Pattern Group 3: MVEL / OGNL 表達式引擎執行 ---
      - pattern: MVEL.eval(...)
      - pattern: Ognl.getValue(...)
      # --- Pattern Group 4: 不安全的動態類別與位元組碼載入 ---
      - pattern: $LOADER.defineClass(...)
    message: "Code Injection risk (CWE-94): Passing untrusted input to expression language parsers (SpEL, OGNL, MVEL), script engines, or dynamic class definition flows allows execution of arbitrary Java code context or remote code execution (RCE)."
    languages: [java]
    severity: ERROR
    metadata:
      cwe: ['CWE-94']

  - id: java-buffer-overflow-cwe120
    pattern-either:
      # --- Pattern Group 1: Unsafe.copyMemory 未經長度安全檢驗直接操作核心堆疊 ---
      - pattern: $UNSAFE.copyMemory(...)
      # --- Pattern Group 2: 使用 native 關鍵字且包含 byte[] 或 String 的記憶體邊界複製函數 ---
      - pattern: |
          private native void nativeBufferCopy(byte[] $SRC, ...);
      - pattern: |
          private native void strcpy(...);
    message: "Buffer Copy without Checking Size risk (CWE-120): Unsafe memory operations or unfiltered native code (JNI) boundaries can bypass JVM boundaries and trigger stack or heap buffer overflows within the underlying runtime environments."
    languages: [java]
    severity: ERROR
    metadata:
      cwe: ['CWE-120']

  - id: java-file-upload-cwe434
    pattern-not-contained-by:
      - pattern: |
          if (..., $NAME.endsWith(...), ...) { ... }
      - pattern: |
          if (..., $NAME.contains(...), ...) { ... }
    pattern-either:
      # 精簡型特徵：只要物件呼叫了 getOriginalFilename() 或 getPart() 且未經前置校驗即觸發
      - pattern: $FILE.getOriginalFilename()
      - pattern: $REQ.getPart(...)
    message: "Unrestricted Upload of File with Dangerous Type (CWE-434)"
    languages: [java]
    severity: ERROR
    metadata:
      cwe: ['CWE-434']

  - id: java-null-pointer-dereference-cwe476
    pattern-either:
      # 標準 Java 核心庫特徵，不需要任何外部依賴
      - pattern: System.getProperty(...).toLowerCase(...)
      - pattern: System.getProperty(...).trim(...)
      - pattern: System.getenv(...).length(...)
      # 放寬特徵：捕捉任何方法內傳入可能為空（null）的變數並直接調用方法的情況
      - pattern: |
          $TYPE $VAR = null;
          ...
          $VAR.$METHOD(...);
    message: "Potential Null Pointer Dereference (CWE-476)"
    languages: [java]
    severity: ERROR
    metadata:
      cwe: ['CWE-476']

  - id: java-deserialization-cwe502
    pattern-either:
      # --- Pattern Group 1: Java 原生不安全反序列化 ---
      - pattern: new ObjectInputStream(...)
      - pattern: java.io.ObjectInputStream(...)
      - pattern: $OIS.readObject()
      
      # --- Pattern Group 2: XMLDecoder 動態物件還原 ---
      - pattern: new XMLDecoder(...)
      - pattern: java.beans.XMLDecoder(...)
      
      # --- Pattern Group 3: Jackson ObjectMapper 開啟不安全的多型類型推導 (AutoType) ---
      - pattern: $MAPPER.enableDefaultTyping(...)
      - pattern: $MAPPER.activateDefaultTyping(...)
      
      # --- Pattern Group 4: Fastjson / Kryo 等常見序列化工具的危險解析特徵 ---
      - pattern: JSON.parseObject(...)
      - pattern: JSON.parse(...)
      - pattern: $KRYO.readObject(...)
    message: "Deserialization of Untrusted Data (CWE-502): Parsing untrusted serialized byte streams or enabling polymorphic type handling in JSON/XML parsers can trigger arbitrary class instantiation and execution of remote malicious code (RCE)."
    languages: [java]
    severity: ERROR
    metadata:
      cwe: ['CWE-502']

  - id: java-stack-buffer-overflow-cwe121
    pattern-either:
      # --- Pattern Group 1: 利用 native 關鍵字宣告可能在 C 語言棧上引發溢位的資料緩衝函數 ---
      - pattern: |
          private native void nativeStackCopy(byte[] $SRC, ...);
      - pattern: |
          private native int parseInNativeStack(String $INPUT);
      # --- Pattern Group 2: 底層直接利用 Unsafe 分配與複寫局部執行緒堆疊記憶體 (與原生 C 對接) ---
      - pattern: $UNSAFE.putLong($STACK_ADDR, ...)
    message: "Stack-based Buffer Overflow via Native Interface (CWE-121): Passing oversized byte arrays or text objects across JNI boundaries to unvalidated static localized stack buffers can lead to memory corruption, daemon crashes, or local sandbox bypass."
    languages: [java]
    severity: ERROR
    metadata:
      cwe: ['CWE-121']

  - id: java-incorrect-authorization-cwe863
    pattern-either:
      # --- Pattern Group 1: 弱角色註解特徵 (只要包含 PreAuthorize/Secured 且內含 USER) ---
      - pattern: |
          @PreAuthorize("...USER...")
          $TYPE $FUNC(...) { ... }
      - pattern: |
          @Secured("...USER...")
          $TYPE $FUNC(...) { ... }
          
      # --- Pattern Group 2: 原生 Java EE 角色授權邏輯錯誤 (用低權限過濾敏感管理功能) ---
      - pattern: |
          if ($REQ.isUserInRole("USER")) { ... }
    message: "Incorrect Authorization (CWE-863): Broken or insufficient privilege verification detected."
    languages: [java]
    severity: ERROR
    metadata:
      cwe: ['CWE-863']

  - id: java-heap-buffer-overflow-cwe122
    pattern-either:
      # --- Pattern Group 1: JNI 原生堆積函數宣告 ---
      - pattern: private native void nativeHeapCopy(...);
      - pattern: private native void processInNativeHeap(...);
          
      # --- Pattern Group 2: 堆外記憶體動態分配直接調用 ---
      - pattern: $BUF.allocateDirect(...)
      - pattern: ByteBuffer.allocateDirect(...)
    message: "Heap-based Buffer Overflow via Native/Direct Channel (CWE-122)"
    languages: [java]
    severity: ERROR
    metadata:
      cwe: ['CWE-122']

  - id: java-improper-input-validation-cwe20
    pattern-either:
      # --- Pattern Group 1: 不安全的動態類別載入 ---
      - pattern: Class.forName($USER_INPUT)
      
      # --- Pattern Group 2: 開放式 URL 重新導向 (Open Redirect) ---
      - pattern: $RESP.sendRedirect($INPUT)
      
      # --- Pattern Group 3: 原生檔案通道中完全未經驗證的輸入傳遞 ---
      - pattern: new java.io.FileInputStream($INPUT)
    message: "Improper Input Validation (CWE-20)"
    languages: [java]
    severity: ERROR
    metadata:
      cwe: ['CWE-20']

  - id: java-improper-access-control-cwe284
    pattern-either:
      # --- Pattern Group 1: 拍平方法鏈，只要呼叫了具有權限大開含義的方法組合即攔截 ---
      - pattern: $OBJ.permitAll()
      - pattern: $OBJ.anonymous()
          
      # --- Pattern Group 2: CORS 跨域完全放權 ---
      - pattern: $RESP.setHeader("Access-Control-Allow-Origin", "*")
      - pattern: $RESP.addHeader("Access-Control-Allow-Origin", "*")
      
      # --- Pattern Group 3: 顯式的硬編碼後門/越權跳過邏輯 (CWE-284 典型硬編碼特徵) ---
      - pattern: |
          if ($USER.equals("admin")) { return true; }
    message: "Improper Access Control (CWE-284)"
    languages: [java]
    severity: ERROR
    metadata:
      cwe: ['CWE-284']

  - id: java-information-exposure-cwe200
    pattern-either:
      # --- Pattern Group 1: 異常堆疊直接輸出 ---
      - pattern: $E.printStackTrace()
      
      # --- Pattern Group 2: 任何往輸出流直接寫入 Exception 訊息的特徵 ---
      - pattern: $WRITE.print($E.getMessage())
      - pattern: $WRITE.println($E.toString())
      
      # --- Pattern Group 3: 只要日誌或主控台印出含有 password / secret 關鍵字的內容 ---
      - pattern: $LOG.info(... + $VAL)
      - pattern: System.out.println(... + $VAL)
    message: "Exposure of Sensitive Information (CWE-200)"
    languages: [java]
    severity: ERROR
    metadata:
      cwe: ['CWE-200']

  - id: java-missing-authentication-cwe306
    pattern-either:
      # --- Pattern Group 1: 權限控制直接設為 true 繞過驗證 ---
      - pattern: $CONTEXT.setAuthenticated(true)
      - pattern: $SESSION.setAttribute(..., true)
      
      # --- Pattern Group 2: 商業邏輯層面顯式的硬編碼免驗證分支 ---
      - pattern: |
          if ($USER.equals("test_user")) { ... }
      - pattern: |
          if ($SKIP == true) { ... }
    message: "Missing Authentication for Critical Function (CWE-306)"
    languages: [java]
    severity: ERROR
    metadata:
      cwe: ['CWE-306']

  - id: java-ssrf-cwe918
    pattern-either:
      # --- Pattern Group 1: 內建 URL 連線的直接字串拼接與開啟 ---
      - pattern: new java.net.URL(... + $URL_STR)
      - pattern: new URL(... + $URL_STR)
      - pattern: $URL_OBJ.openConnection()
      - pattern: $CONN_OBJ.openStream()
      
      # --- Pattern Group 2: Java 原生 HttpClient 請求構建特徵 ---
      - pattern: java.net.http.HttpRequest.newBuilder(java.net.URI.create(... + $URI_STR))
      - pattern: HttpRequest.newBuilder(URI.create(... + $URI_STR))
      - pattern: java.net.URI.create(... + $URI_STR)
    message: "Server-Side Request Forgery (CWE-918): Unvalidated user-supplied strings are directly passed into network connection API endpoints, enabling severe intranet reconnaissance or metadata exfiltration."
    languages: [java]
    severity: ERROR
    metadata:
      cwe: ['CWE-918']

  - id: java-command-injection-cwe77
    pattern-either:
      # --- Pattern Group 1: Runtime 執行系統指令與直接字串拼接 ---
      - pattern: java.lang.Runtime.getRuntime().exec(... + $CMD)
      - pattern: Runtime.getRuntime().exec(... + $CMD)
      - pattern: $RUNTIME.exec(... + $CMD)
      
      # --- Pattern Group 2: ProcessBuilder 命令陣列或字串構造 ---
      - pattern: new java.lang.ProcessBuilder(... + $CMD)
      - pattern: new ProcessBuilder(... + $CMD)
      - pattern: $BUILDER.command(... + $CMD)
    message: "Command Injection (CWE-77): Direct concatenation of unverified inputs within system executable invocation pipelines risks total server shell takeovers."
    languages: [java]
    severity: ERROR
    metadata:
      cwe: ['CWE-77']

  - id: java-idor-cwe639
    pattern-either:
      # --- Pattern Group 1: 參數名稱具有明顯「控制鍵值」特徵，且無檢查直接查詢或刪除 ---
      - pattern: |
          $TYPE $FUNC(..., String $ID, ...) {
            ...
            $REPO.findById($ID);
            ...
          }
      - pattern: |
          $TYPE $FUNC(..., Long $ACCOUNT_NUM, ...) {
            ...
            $REPO.deleteByAccount($ACCOUNT_NUM);
            ...
          }
    message: "Authorization Bypass Through User-Controlled Key / IDOR (CWE-639): Direct use of user-supplied identity keys without ownership verification can allow unauthorized horizontal privilege escalation."
    languages: [java]
    severity: ERROR
    metadata:
      cwe: ['CWE-639']

  - id: java-uncontrolled-resource-allocation-cwe770
    pattern-either:
      # --- Pattern Group 1: 依據外部傳入大小直接分配陣列/集合記憶體 ---
      - pattern: new byte[$SIZE]
      - pattern: new char[$SIZE]
      - pattern: new java.util.ArrayList<>($SIZE)
      - pattern: new ArrayList<>($SIZE)
      
      # --- Pattern Group 2: 迴圈處理 Zip 檔案解壓且缺乏大小限制 (常見 DoS 漏洞) ---
      - pattern: |
          while (($ENTRY = $ZIP.getNextEntry()) != null) {
            ...
            $OUT.write(...);
          }
    message: "Allocation of Resources Without Limits or Throttling (CWE-770): Allocating generic primitive arrays or collection objects proportional to user inputs, or unbounded streaming of archive entries, triggers denial-of-service (DoS) via memory exhaustion."
    languages: [java]
    severity: ERROR
    metadata:
      cwe: ['CWE-770']

  - id: java-improper-authentication-cwe287
    pattern-either:
      # Pattern 1: 只要在代碼中對特定寫死的敏感密碼/Token 進行 .equals() 比對，直接攔截時序攻擊
      - pattern: |
          $STR.equals("SuperSecretJavaPassword2026!")

      # Pattern 2: 認證過濾器漏洞 — 鎖定在分支中呼叫 doFilter 隨後直接 return，且該分支內缺乏上下文設定的特徵
      - pattern: |
          if ($COND) {
              $CHAIN.doFilter($REQ, $RES);
              return;
          }

      # Pattern 3: 直擊不安全的 JWT 驗證 — 只要代碼中出現比對 "none" 演算法的字串常數特徵，立即攔截
      - pattern: |
          $ALG.equalsIgnoreCase("none")
      - pattern: |
          $ALG.equals("none")

    message: "Improper Authentication (CWE-287): Flawed authentication mechanism detected in Java. Avoid using String.equals() for cryptographic keys or passwords to prevent timing attacks; use MessageDigest.isEqual() instead. Ensure Filter chains do not forward requests unconditionally in early return branches without context establishment, and never accept 'none' algorithm for JWT."
    languages: [java]
    severity: ERROR
    metadata:
      cwe: ['CWE-287']

  - id: java-improper-privilege-management-cwe269
    pattern-either:
      # Pattern 1: 直擊不安全的特權執行區塊 — 在 AccessController.doPrivileged 中直接內嵌執行外部命令或敏感參數
      - pattern: |
          AccessController.doPrivileged(new PrivilegedAction<$T>() {
              public $T run() {
                  ...
                  Runtime.getRuntime().exec(...);
                  ...
              }
          });

      # Pattern 2: 商業邏輯層面 — 只要在權限/角色指派的方法中，對特定寫死的管理員帳號/角色進行無條件放行 return true
      - pattern: |
          if ($USER.equals("super_admin")) {
              return true;
          }

      # Pattern 3: 全域狀態提權 — 直接呼叫自訂權限管理器單例的 setAdminStatus(true) 或 System.setSecurityManager(null)
      - pattern: |
          $MANAGER.setAdminStatus(true);
      - pattern: |
          System.setSecurityManager(null);

    message: "Improper Privilege Management (CWE-269): Flawed privilege management detected in Java. Avoid embedding unvalidated user inputs within 'AccessController.doPrivileged' blocks as it elevates risks of unauthorized system command execution. Ensure role checks do not contain hard-coded bypasses, and never modify global security manager states loosely."
    languages: [java]
    severity: ERROR
    metadata:
      cwe: ['CWE-269']

  - id: java-buffer-bounds-cwe119
    pattern-either:
      # Pattern 1: 直擊 sun.misc.Unsafe 的長整型底層記憶體直接寫入行為（無條件匹配）
      - pattern: |
          $UNSAFE.putLong($ADDR, $VAL)

      # Pattern 2: NIO ByteBuffer 在進行批量 get 讀取時的核心特徵
      - pattern: |
          $BUF.get($ARR)

      # Pattern 3: 傳統 Java 陣列與 System.arraycopy 的底層複製行為特徵
      - pattern: |
          System.arraycopy($SRC, $SRC_POS, $DEST, $DEST_POS, $LEN)

    message: "Improper Restriction of Operations within the Bounds of a Memory Buffer (CWE-119): Advanced unsafe buffer operations detected in Java. Ensure strict boundary checks are applied before performing low-level memory writes, NIO buffer batch operations, or native array copies."
    languages: [java]
    severity: ERROR
    metadata:
      cwe: ['CWE-119']

  - id: java-hardcoded-credentials-cwe798
    pattern-either:
      # Pattern 1: 只要字串內容完全吻合特定寫死的敏感憑證、密碼或 Token 常數值
      - pattern: |
          "SuperSecretJavaPassword2026!"
      - pattern: |
          "TL_a1b2c3d4e5f6g7h8i9j0"

      # Pattern 2: 呼叫金鑰規格建構子（如 SecretKeySpec）時，直接傳入硬編碼的 byte 陣列
      - pattern: |
          new javax.crypto.spec.SecretKeySpec(new byte[]{...}, ...)

      # Pattern 3: 在自訂物件初始化、方法調用中，參數直接內嵌包含敏感憑證特徵（如 password=）的字串
      - pattern: |
          $OBJ.connect(..., "...password=...", ...)

    message: "Use of Hard-coded Credentials (CWE-798): Hard-coded password, API key, or cryptographic key detected in Java source code. Store credentials securely using environment variables or a secure credential vault."
    languages: [java]
    severity: ERROR
    metadata:
      cwe: ['CWE-798']

  - id: java-integer-overflow-cwe190-precise
    pattern-either:
      # 只有當乘法發生在 ByteBuffer.allocate 的引數內時，才視為溢位風險
      - pattern: |
          java.nio.ByteBuffer.allocate($A * $B)
      # 只有當加法發生在陣列索引或迴圈條件中時，才視為溢位風險
      - pattern: |
          $ARR[$BASE + $OFFSET]
    message: "Integer Overflow (CWE-190): Unsafe arithmetic operation inside a buffer allocation or array index. Please validate your integer bounds."
    languages: [java]
    severity: ERROR
    metadata:
      cwe: ['CWE-190']

  - id: java-resource-consumption-cwe400
    pattern-either:
      # Pattern 1: 執行緒耗盡 — 只要 for 迴圈的終止條件直接嵌入了外部整數轉換（如 Integer.parseInt），且內部無條件不斷建立新 Thread 
      - pattern: |
          for (int $I = 0; $I < Integer.parseInt(...); $I++) {
              ...
              new Thread(...).start();
              ...
          }

      # Pattern 2: 記憶體耗盡 — 直接在 ArrayList 或者是其他常規 STL 容器的建構子參數中嵌入外部轉換函數，直擊 OOM 漏洞
      - pattern: |
          new java.util.ArrayList<>(Integer.parseInt(...))
      - pattern: |
          new java.util.HashMap<>(Integer.parseInt(...))

      # Pattern 3: 檔案描述符耗盡 — 專門鎖定在控制流分支中，開啟 FileInputStream 後直接 return，而未在該分支內調用 close 的行為
      - pattern: |
          java.io.FileInputStream $STREAM = ...;
          ...
          if ($COND) {
              return $VAL;
          }

    message: "Uncontrolled Resource Consumption (CWE-400): Unbounded dynamic Java resource allocation detected. Limit the maximum size when constructing collections from external inputs, restrict maximum active thread creation, and ensure file/network streams are explicitly scoped or closed (or use try-with-resources) to prevent Denial of Service (DoS)."
    languages: [java]
    severity: ERROR
    metadata:
      cwe: ['CWE-400']

  - id: java-hidden-functionality-cwe912
    pattern-either:
      # Pattern 1: 捕捉硬編碼特定魔術字串進行身分繞過與特權提升的特徵 (使用 ... 確保區塊完整)
      - pattern: |
          if ("admin_secret_pass".equals($USER_INPUT)) {
              ...
          }

      # Pattern 2: 捕捉透過隱藏的請求參數，直接將外部輸入送入 Runtime.exec 執行指令的特徵
      - pattern: |
          Runtime.getRuntime().exec(request.getParameter("hidden_cmd"))

      # Pattern 3: 捕捉利用特定的隱藏 System 屬性或環境變數來秘密繞過正常認證流程的特徵 (使用 ... 確保區塊完整)
      - pattern: |
          if (System.getenv("BACKDOOR_KEY").equals($SECRET_KEY)) {
              ...
          }

    message: "Hidden Functionality / Backdoor (CWE-912): Detected suspicious hidden control paths, magic string checks, or backdoor command execution triggers in Java. Remove unintended code or document all operational entry points thoroughly."
    languages: [java]
    severity: ERROR
    metadata:
      cwe: ['CWE-912']

  - id: java-untrusted-inclusion-cwe829
    pattern-either:
      # Pattern 1: 捕捉使用 URLClassLoader 動態載入外部不安全遠端 Jar 檔案的特徵
      - pattern: |
          new URLClassLoader(new URL[]{new URL($URL)})

      # Pattern 2: 捕捉使用 Class.forName 動態加載外部指定名稱之未驗證類別的特徵
      - pattern: |
          Class.forName(request.getParameter("className"))

      # Pattern 3: 捕捉在程式碼中指定或設定非安全（HTTP）的外部遠端套件儲存庫的特徵 (使用 ... 確保區塊完整)
      - pattern: |
          if ($REPO_URL.startsWith("http://")) {
              ...
          }

    message: "Inclusion of Functionality from Untrusted Control Sphere (CWE-829): Code dynamically imports, downloads, or configures software execution from untrusted sources or unencrypted channels. Verify the integrity of external components, use HTTPS for package repositories, and enforce a strict allowlist for dynamic class loading."
    languages: [java]
    severity: ERROR
    metadata:
      cwe: ['CWE-829']

  - id: java-class-pollution-cwe1321
    pattern-either:
      # Pattern 1: 捕捉使用 BeanUtils.setProperty 動態竄改類別屬性的高危特徵
      - pattern: |
          BeanUtils.setProperty($OBJ, request.getParameter("property"), request.getParameter("value"))

      # Pattern 2: 捕捉不安全的屬性注入、直接操作底層 ObjectNode 配置類別屬性的特徵
      - pattern: |
          $NODE.put("class", $VAL)

      # Pattern 3: 捕捉在自訂屬性解析邏輯中，針對內建特殊屬性（如 "class"）進行特定判斷卻未妥善阻斷的特徵 (使用 ... 確保區塊完整)
      - pattern: |
          if ("class".equals(request.getParameter("key"))) {
              ...
          }

    message: "Improper Control of Generation of Prototype Nodes ('Prototype Pollution' / Class Pollution) (CWE-1321): Unsafe dynamic property manipulation or reflection allows attackers to modify the class loader or underlying class templates (e.g., via 'class.classLoader'). Sanitize inputs and block special keywords like 'class' or 'classLoader' before processing object attributes."
    languages: [java]
    severity: ERROR
    metadata:
      cwe: ['CWE-1321']

  - id: java-cert-validation-cwe295
    pattern-either:
      # Pattern 1: 捕捉將 checkServerTrusted 留空以致盲目信任所有伺服器憑證的 X509TrustManager 特徵 (使用 ... 確保區塊完整)
      - pattern: |
          public void checkServerTrusted(X509Certificate[] chain, String authType) {
              ...
          }

      # Pattern 2: 捕捉讓 HostnameVerifier 的 verify 永遠回傳 true、完全繞過域名校驗的特徵 (使用 ... 確保區塊完整)
      - pattern: |
          public boolean verify(String hostname, SSLSession session) {
              return true;
          }

      # Pattern 3: 捕捉在不安全的 SSLContext 建立後，直接呼叫其產生不安全 SocketFactory 的特徵
      - pattern: |
          $CONTEXT.init(null, $MANAGERS, null);

    message: "Improper Certificate Validation (CWE-295): The application does not properly validate SSL/TLS certificates or hostnames, allowing potential Man-in-the-Middle (MITM) attacks. Ensure that checkServerTrusted throws CertificateException for invalid certificates and HostnameVerifier checks matching domains."
    languages: [java]
    severity: ERROR
    metadata:
      cwe: ['CWE-295']

  - id: java-weak-hash-cwe328
    pattern-either:
      # Pattern 1: 強制捕捉任何呼叫 getInstance 且參數包含 "MD5" 的特徵（無視前面的類別實作限制）
      - pattern: |
          $MD.getInstance("MD5")

      # Pattern 2: 強制捕捉任何呼叫 getInstance 且參數包含 "SHA-1" 的特徵
      - pattern: |
          $MD.getInstance("SHA-1")

      # Pattern 3: 捕捉任何形式的 md5Hex 方法呼叫，確保萬無一失
      - pattern: |
          $UTILS.md5Hex($INPUT)

    message: "Use of Weak Hash (CWE-328): The application uses a weak cryptographic hash algorithm (MD5 or SHA-1) which is vulnerable to collision attacks. Upgrade to a secure cryptographic hash function like SHA-256 or SHA-3."
    languages: [java]
    severity: ERROR
    metadata:
      cwe: ['CWE-328']
"""

# =============================================================================
# 4. C++ 自訂規則產生
# =============================================================================
cpp_rules = """\
rules:
  - id: cpp-xss-cwe79
    pattern-either:
      # --- Pattern Group 1: C++ 標準輸出流中拼湊並直接輸出 HTML ---
      - pattern: std::cout << $HTML << $INPUT
      - pattern: cout << $HTML << $INPUT

      # --- Pattern Group 2: 使用 C++ 串流或緩衝區直接對外部輸入進行格式化標籤拼接 ---
      - pattern: |
          $STREAM << $HTML << $INPUT;
      
      # --- Pattern Group 3: 成員函數或 Web 控制器直接將輸入與 HTML 標籤拼接並返回 ---
      - pattern: |
          $TYPE $FUNC(..., std::string $INPUT, ...) {
            ...
            return $HTML + $INPUT + ...;
          }
      - pattern: |
          $TYPE $FUNC(..., const char* $INPUT, ...) {
            ...
            return $HTML + $INPUT + ...;
          }
    message: "Cross-Site Scripting / XSS (CWE-79): Directly rendering raw user input into HTML structures or C++ streams inside web/CGI endpoints enables client-side script execution."
    languages: [cpp]
    severity: ERROR
    metadata:
      cwe: ['CWE-79']

  - id: cpp-sqli-cwe89
    pattern-either:
      # --- Pattern Group 1: 函數參數包含明顯輸入特徵，在內部直接以加號 (+) 拼接成 SQL ---
      - pattern: |
          $TYPE $FUNC(..., std::string $INPUT, ...) {
            ...
            std::string $SQL = $STR + $INPUT + ...;
            ...
          }
      - pattern: |
          $TYPE $FUNC(..., const std::string& $INPUT, ...) {
            ...
            std::string $SQL = $STR + $INPUT + ...;
            ...
          }

      # --- Pattern Group 2: 利用 C++ 串流 (Stream) 將外部輸入直接導向 SQL 語句特徵 ---
      - pattern: |
          $STREAM << $STR << $INPUT;

      # --- Pattern Group 3: 使用現代 C++ / fmt 格式化函數，直接將輸入填入 SQL 樣板 ---
      - pattern: std::format($FMT, ..., $INPUT, ...)
      - pattern: fmt::format($FMT, ..., $INPUT, ...)

      # --- Pattern Group 4: 資料庫物件直接在呼叫端進行拼接查詢 ---
      - pattern: $DB.execute($STR + $INPUT + ...)
      - pattern: $DB.query($STR + $INPUT + ...)
    message: "Improper Neutralization of Special Elements used in an SQL Command / SQL Injection (CWE-89): Building SQL commands via string concatenation, streams, or unparameterized formatting with raw user input allows malicious SQL command execution."
    languages: [cpp]
    severity: ERROR
    metadata:
      cwe: ['CWE-89']

  - id: cpp-csrf-cwe352
    pattern-either:
      # --- Pattern Group 1: 顯式關閉框架自帶的 CSRF 防禦過濾器或中介軟體 ---
      - pattern: $APP.registerFilter(std::make_shared<drogon::filters::CsrfFilter>(..., false))
      - pattern: $FILTER->setEnable(false)
      - pattern: $CONFIG->setEnableCsrfProtection(false)
      - pattern: $CONFIG->disable_csrf()

      # --- Pattern Group 2: 將 Cookie 的 SameSite 屬性設為 None 且未開啟 Secure 屬性 ---
      - pattern: $COOKIE.setSameSite("None")
      - pattern: $COOKIE.set_same_site("None")
    message: "Cross-Site Request Forgery / CSRF (CWE-352): Disabling global CSRF protections or setting SameSite to None permits unauthorized cross-origin state-changing actions."
    languages: [cpp]
    severity: ERROR
    metadata:
      cwe: ['CWE-352']

  - id: cpp-missing-auth-cwe862
    patterns:
      # 1. 先抓出所有敏感操作的函式定義
      - pattern-either:
          - pattern: |
              $TYPE delete_user(...) {
                ...
              }
          - pattern: |
              $TYPE update_role(...) {
                ...
              }
      # 2. 排除掉任何內部有呼叫「權限/認證/檢查」相關關鍵字的方法
      - pattern-not: |
          $TYPE $FUNC(...) {
            ...
            $AUTH.check_permission(...);
            ...
          }
      - pattern-not: |
          $TYPE $FUNC(...) {
            ...
            $AUTH.is_admin(...);
            ...
          }
      # 3. 泛用排除：只要程式碼內有包含 auth 關鍵字的任何物件呼叫就放過
      - pattern-not: |
          $TYPE $FUNC(...) {
            ...
            $AUTH.auth(...);
            ...
          }
    message: "Missing Authorization (CWE-862): The application executes a sensitive action (e.g., identity manipulation) without checking if the user possesses required privileges."
    languages: [cpp]
    severity: ERROR
    metadata:
      cwe: ['CWE-862']
      
  - id: cpp-outofbound-write-cwe787
    pattern-either:
      # --- Pattern Group 1: 宣告硬編碼大小的陣列後，在同一個區塊直接寫入（最直觀的特徵） ---
      - pattern: |
          $TYPE $ARR[$SIZE];
          ...
          $ARR[$IDX] = $VAL;

      # --- Pattern Group 2: 指標解引用且帶有自增/自減的連續寫入（未檢查長度的快進寫入） ---
      - pattern: "*$PTR++ = $VAL;"
      - pattern: "*++$PTR = $VAL;"

      # --- Pattern Group 3: 現代 C++ 容器使用不安全的 [] 進行賦值寫入 ---
      - pattern: "$VEC[$IDX] = $VAL;"
    
    # 透過全域排除，只要是用安全的 .at() 寫入就絕對放過
    pattern-not: "$VEC.at($IDX) = $VAL;"
    
    message: "Out-of-bounds Write (CWE-787): Writing data past the end or before the beginning of the intended buffer can result in corruption of data, a crash, or code execution."
    languages: [cpp]
    severity: ERROR
    metadata:
      cwe: ['CWE-787']

  - id: cpp-path-traversal-cwe22
    patterns:
      # 1. 抓出所有不安全的檔案流開啟或路徑拼接行為
      - pattern-either:
          # --- Pattern Group 1: 檔案串流物件直接在建構子或 open() 中使用加號 (+) 拼接輸入路徑 ---
          - pattern: std::ifstream $FS($BASE_DIR + $INPUT + ...);
          - pattern: std::ofstream $FS($BASE_DIR + $INPUT + ...);
          - pattern: std::fstream $FS($BASE_DIR + $INPUT + ...);
          - pattern: $FS.open($BASE_DIR + $INPUT + ...);

          # --- Pattern Group 2: 使用 C++20 std::format 或第三方 fmt 拼接路徑特徵 ---
          - pattern: |
              std::string $PATH = std::format($FMT, ..., $INPUT, ...);
              ...
              $FS.open($PATH);
          - pattern: |
              std::string $PATH = fmt::format($FMT, ..., $INPUT, ...);
              ...
              $FS.open($PATH);

          # --- Pattern Group 3: 先進行字串變數拼接，隨後立即開檔 ---
          - pattern: |
              std::string $PATH = $BASE_DIR + $INPUT;
              ...
              $FS.open($PATH);

      # 2. 排除安全點：如果代碼內包含任何路徑規整、絕對路徑化或相對路徑特徵檢查，則不予命中
      - pattern-not: |
          $TYPE $FUNC(...) {
            ...
            if ($INPUT.find("..") != ...) { ... }
            ...
          }
      - pattern-not: |
          $TYPE $FUNC(...) {
            ...
            std::filesystem::canonical(...);
            ...
          }
      - pattern-not: |
          $TYPE $FUNC(...) {
            ...
            std::filesystem::absolute(...);
            ...
          }
    message: "Improper Limitation of a Pathname to a Restricted Directory / Path Traversal (CWE-22): Appending raw user input to a file path without normalization allows attackers to access arbitrary files on the system using '../' sequences."
    languages: [cpp]
    severity: ERROR
    metadata:
      cwe: ['CWE-22']

  - id: cpp-use-after-free-cwe416
    patterns:
      - pattern-either:
          # --- Pattern Group 1: 執行 delete 釋放記憶體後，多行內再次使用該指標 ---
          - pattern: |
              delete $PTR;
              ...
              $PTR->$MEMBER = $VAL;
          - pattern: |
              delete $PTR;
              ...
              *$PTR = $VAL;
          - pattern: |
              delete[] $PTR;
              ...
              $PTR[$IDX] = $VAL;

          # --- Pattern Group 2: 物件自殺（delete this）後，在同函數後續程式碼內繼續存取成員變數 ---
          - pattern: |
              delete this;
              ...
              $MEMBER = $VAL;

      # 排除安全點：如果在 delete 之後馬上將變數重設為 nullptr，不視為直接漏洞
      - pattern-not: |
          delete $PTR;
          $PTR = nullptr;
      - pattern-not: |
          delete[] $PTR;
          $PTR = nullptr;
    message: "Use After Free (CWE-416): Referencing memory after it has been freed can lead to program crashes, data corruption, or execution of arbitrary code."
    languages: [cpp]
    severity: ERROR
    metadata:
      cwe: ['CWE-416']

  - id: cpp-outofbound-read-cwe125
    pattern-either:
      # --- Pattern Group 1 & 3: 只要任何陣列或容器（如 buffer, vector, string）使用 [] 進行讀取並賦值或當作參數 ---
      - pattern: "$VAR = $ARR[$IDX];"
      - pattern: "$FUNC(..., $ARR[$IDX], ...);"

      # --- Pattern Group 2: 指標解引用且帶有自增/自減的連續讀取 ---
      - pattern: "$VAR = *$PTR++;"
      - pattern: "$VAR = *++$PTR;"
      - pattern: "$FUNC(..., *$PTR++, ...);"
      - pattern: "$FUNC(..., *++$PTR, ...);"
    
    message: "Out-of-bounds Read (CWE-125): The program reads data past the end, or before the beginning, of the intended buffer."
    languages: [cpp]
    severity: ERROR
    metadata:
      cwe: ['CWE-125']

  - id: cpp-command-injection-cwe78
    pattern-either:
      # --- Pattern Group 1: 使用 + 或 .append() 拼接字串後直接傳入 system() ---
      - pattern: |
          $CMD = $X + $Y;
          ...
          system($CMD.c_str());
      - pattern: |
          $CMD = $X + $Y;
          ...
          system($CMD);
      - pattern: |
          $CMD.append($INPUT);
          ...
          system($CMD.c_str());

      # --- Pattern Group 2: 使用 stringstream 透過 << 運算子拼接指令後傳入 system() ---
      - pattern: |
          $SS << $INPUT;
          ...
          system($SS.str().c_str());

      # --- Pattern Group 3: 拼接字串後直接傳入 popen() 或 _popen() ---
      - pattern: |
          $CMD = $X + $Y;
          ...
          popen($CMD.c_str(), ...);
      - pattern: |
          $CMD = $X + $Y;
          ...
          _popen($CMD.c_str(), ...);

      # --- Pattern Group 4: 直接在函式參數內進行字串拼接傳入 ---
      - pattern: "system(($X + $Y).c_str());"
      - pattern: "popen(($X + $Y).c_str(), ...);"
    
    message: "OS Command Injection (CWE-78): The program constructs an OS command using externally-influenced input, allowing an attacker to execute arbitrary commands."
    languages: [cpp]
    severity: ERROR
    metadata:
      cwe: ['CWE-78']

  - id: cpp-code-injection-cwe94
    pattern-either:
      # --- Pattern Group 1: 拼接字串後直接傳入 Linux / Windows 動態庫載入函式 ---
      - pattern: |
          $PATH = $X + $Y;
          ...
          dlopen($PATH.c_str(), ...);
      - pattern: |
          $PATH = $X + $Y;
          ...
          LoadLibrary($PATH.c_str());
      - pattern: |
          $PATH = $X + $Y;
          ...
          LoadLibraryA($PATH.c_str());

      # --- Pattern Group 2: 整合 Python 嵌入式引擎，拼接字串後動態執行程式碼 ---
      - pattern: |
          $CODE = $X + $Y;
          ...
          PyRun_SimpleString($CODE.c_str());
      - pattern: "PyRun_SimpleString(($X + $Y).c_str());"

      # --- Pattern Group 3: 整合 Lua 嵌入式引擎，拼接字串後動態執行程式碼 ---
      - pattern: |
          $CODE = $X + $Y;
          ...
          luaL_dostring($L, $CODE.c_str());
      - pattern: "luaL_dostring($L, ($X + $Y).c_str());"

      # --- Pattern Group 4: 整合 V8 / JS 嵌入式引擎，拼接字串後動態編譯/執行 ---
      - pattern: |
          $CODE = $X + $Y;
          ...
          Script::Compile(..., $CODE, ...);
    
    message: "Improper Control of Generation of Code (CWE-94): The program constructs code or loads libraries using externally-influenced input, allowing an attacker to execute arbitrary code in the process context."
    languages: [cpp]
    severity: ERROR
    metadata:
      cwe: ['CWE-94']

  - id: cpp-buffer-overflow-cwe120
    pattern-either:
      # --- Pattern Group 1: 絕對禁用的不安全輸入函式gets ---
      - pattern: "gets(...);"

      # --- Pattern Group 2: 不安全的字串複製與拼接（無邊界檢查） ---
      - pattern: "strcpy($DEST, $SRC);"
      - pattern: "strcat($DEST, $SRC);"

      # --- Pattern Group 3: 不安全的格式化字串寫入（極易導致溢出） ---
      - pattern: "sprintf($DEST, $FORMAT, ...);"
      - pattern: "vsprintf($DEST, $FORMAT, ...);"

      # --- Pattern Group 4: 傳統 C 樣式的輸出入讀取（scanf 未指定長度修飾符） ---
      - pattern: "scanf($FORMAT, ...);"
      - pattern: "fscanf($FILE, $FORMAT, ...);"
      - pattern: "sscanf($BUFFER, $FORMAT, ...);"
    
    message: "Buffer Copy without Checking Size of Input (CWE-120): The program copies an input buffer without validating its size, which can result in a buffer overflow, leading to crashes or arbitrary code execution."
    languages: [cpp]
    severity: ERROR
    metadata:
      cwe: ['CWE-120']

  - id: cpp-unrestricted-file-upload-cwe434
    pattern-either:
      # --- Pattern Group 1: 網頁框架請求直接獲取 client 檔名後，未經驗證直接用做路徑儲存 ---
      - pattern: |
          $FILENAME = $REQ.get_header(...);
          ...
          $OUT.open($DIR + $FILENAME, ...);
      - pattern: |
          $FILENAME = $PART.filename;
          ...
          $OUT.open($DIR + $FILENAME, ...);
      - pattern: |
          $FILENAME = $PART.get_filename();
          ...
          fopen(($DIR + $FILENAME).c_str(), ...);

      # --- Pattern Group 2: 直接在寫入開啟檔案時進行危險的路徑/檔名拼接 ---
      - pattern: "$OUT.open($DIR + $PART.filename, ...);"
      - pattern: "fopen(($DIR + $PART.get_filename()).c_str(), ...);"

      # --- Pattern Group 3: 接受 Content-Type 並直接信任其內容作為判定或寫入本地檔名 ---
      - pattern: |
          $CTYPE = $REQ.get_header("Content-Type");
          ...
          $OUT.open($DIR + $CTYPE, ...);
    
    message: "Unrestricted Upload of File with Dangerous Type (CWE-434): The program allows the attacker to upload a file with dangerous types or extensions without sufficient validation, potentially leading to arbitrary code execution on the server."
    languages: [cpp]
    severity: ERROR
    metadata:
      cwe: ['CWE-434']

  - id: cpp-null-pointer-dereference-cwe476
    pattern-either:
      # --- Pattern Group 1: 傳統 malloc/calloc 分配後直接進行解引用或成員存取 ---
      - pattern: |
          $PTR = malloc(...);
          ...
          *$PTR = $VAL;
      - pattern: |
          $PTR = malloc(...);
          ...
          $PTR->$MEMBER = $VAL;

      # --- Pattern Group 2: dynamic_cast 轉換指標失敗後，未經檢查直接存取 ---
      - pattern: |
          $PTR = dynamic_cast<$TYPE>(...);
          ...
          $PTR->$MEMBER = $VAL;
      - pattern: |
          $PTR = dynamic_cast<$TYPE>(...);
          ...
          *$PTR = $VAL;

      # --- Pattern Group 3: 呼叫可能回傳空指標的自訂尋找/分配函式後直接使用 ---
      - pattern: |
          $PTR = $FUNC->get_ptr(...);
          ...
          $PTR->$MEMBER = $VAL;
      - pattern: |
          $PTR = $FUNC.find_node(...);
          ...
          $PTR->$MEMBER = $VAL;

      # --- Pattern Group 4: 函式引數傳入後，在第一行或未經任何判斷前直接進行解引用 ---
      - pattern: |
          $RET $METHOD(..., $TYPE* $PTR, ...) {
            ...
            $PTR->$MEMBER = $VAL;
          }
      - pattern: |
          $RET $METHOD(..., $TYPE* $PTR, ...) {
            ...
            *$PTR = $VAL;
          }
    
    message: "NULL Pointer Dereference (CWE-476): The program dereferences a pointer that it expects to be valid, but is potentially NULL, leading to a crash or undefined behavior."
    languages: [cpp]
    severity: ERROR
    metadata:
      cwe: ['CWE-476']

  - id: cpp-stack-buffer-overflow-cwe121
    pattern-either:
      # --- Pattern Group 1: 棧陣列配合不安全的 C 樣式記憶體/字串拷貝功能 ---
      - pattern: |
          $TYPE $ARR[$SIZE];
          ...
          memcpy($ARR, $SRC, $LEN);
      - pattern: |
          $TYPE $ARR[$SIZE];
          ...
          strcpy($ARR, $SRC);
      - pattern: |
          $TYPE $ARR[$SIZE];
          ...
          sprintf($ARR, $FORMAT, ...);

      # --- Pattern Group 2: 棧陣列配合 C++ 標準輸入流 cin 讀取（無寬度限制） ---
      - pattern: |
          char $ARR[$SIZE];
          ...
          std::cin >> $ARR;

      # --- Pattern Group 3: 經典的 Off-by-one 差一錯誤迴圈或直接越界寫入棧陣列 ---
      - pattern: |
          $TYPE $ARR[$SIZE];
          ...
          for (...; $I <= $SIZE; ...) {
            ...
            $ARR[$I] = $VAL;
          }
      - pattern: |
          $TYPE $ARR[$SIZE];
          ...
          $ARR[$SIZE] = $VAL;
    
    message: "Stack-based Buffer Overflow (CWE-121): A buffer allocated on the stack is overwritten with more data than it can hold, which can corrupt the return address and lead to arbitrary code execution."
    languages: [cpp]
    severity: ERROR
    metadata:
      cwe: ['CWE-121']

  - id: cpp-heap-buffer-overflow-cwe122
    pattern-either:
      # Pattern 1: 動態記憶體與不安全拷貝/寫入函式 (如 malloc/new 配上 memcpy/strcpy/sprintf)
      - pattern: |
          $PTR = malloc($SIZE);
          ...
          memcpy($PTR, $SRC, $LEN);
      - pattern: |
          $PTR = new char[$SIZE];
          ...
          strcpy($PTR, $SRC);
      - pattern: |
          $PTR = new char[$SIZE];
          ...
          sprintf($PTR, $FORMAT, ...);

      # Pattern 2: C++ 標準流不安全讀入到堆積指標 (容易忽略的盲點)
      - pattern: |
          $PTR = new char[$SIZE];
          ...
          std::cin >> $PTR;

      # Pattern 3: 邊界寫入錯誤 (包含 Off-by-one 與直接超出 new 分配的大小)
      - pattern: |
          $PTR = new $TYPE[$SIZE];
          ...
          $PTR[$SIZE] = $VAL;
      - pattern: |
          $PTR = ($TYPE *)malloc($SIZE * sizeof($TYPE));
          ...
          $PTR[$SIZE] = $VAL;

      # Pattern 4: 智慧指標或容器的底層資料指標被誤用 (如 std::vector::data())
      - pattern: |
          std::vector<$TYPE> $VEC($SIZE);
          ...
          memcpy($VEC.data(), $SRC, $LEN);

    message: "Heap-based Buffer Overflow (CWE-122): A buffer has been allocated on the heap and a sequence of operations could write data past the end of the buffer. This can result in data corruption, application crash, or remote code execution."
    languages: [cpp]
    severity: ERROR
    metadata:
      cwe: ['CWE-122']

  - id: cpp-incorrect-authorization-cwe863
    pattern-either:
      # Pattern 1: 混淆「認證(IsAuthenticated)」與「授權(HasRole/IsAdmin)」
      - pattern: |
          if ($USER->IsAuthenticated(...)) {
             ...
             $SERVICE->delete_user(...);
          }
      - pattern: |
          if ($USER->IsAuthenticated(...)) {
             ...
             $SERVICE->execute_admin_command(...);
          }

      # Pattern 2: 授權函數回傳錯誤時 Fail-open（僅記錄或忽略，沒有中斷/返回）
      - pattern: |
          if (!$AUTH->CheckAccess($USER, $ACTION)) {
             ...
          }
          ...
          $SERVICE->$SENSITIVE_FUNC(...);

      # Pattern 3: 靜態程式碼中硬編碼繞過漏洞（特殊特權名稱直接免除檢查）
      - pattern: |
          bool $CHECK_FUNC(..., $USER, ...) {
             ...
             if ($USER == "admin" || $USER == "root" || $USER == "debug") {
                return true;
             }
             ...
          }

      # Pattern 4: 參數不一致的授權檢查（檢查資源 A，卻操作資源 B）
      - pattern: |
          if ($AUTH->has_permission($USER, $RES1)) {
             ...
             $SERVICE->modify_resource($RES2);
          }

    message: "Incorrect Authorization (CWE-863): The program performs an authorization check, but the check is incorrectly implemented or configured, allowing an attacker to bypass security restrictions."
    languages: [cpp]
    severity: ERROR
    metadata:
      cwe: ['CWE-863']

  - id: cpp-improper-input-validation-cwe20
    pattern-either:
      # Pattern 1: 外部輸入直接作為記憶體分配大小 (如 malloc/new 配上 cin/get_int)
      - pattern: "new $TYPE[$REQ.get_int(...)]"
      - pattern: "malloc($REQ.get_int(...))"
      - pattern: "new $TYPE[$SIZE]"

      # Pattern 2: 外部輸入直接作為陣列/容器索引 (容易忽略的盲點)
      - pattern: "$ARR[$REQ.get_index(...)] = $VAL"
      - pattern: "$VAR = $ARR[$REQ.get_index(...)]"

      # Pattern 3: 輸入字串未過濾換行符，直接透過串流寫入日誌系統
      - pattern: "$LOG_STREAM << $REQ.get_string(...)"

      # Pattern 4: 讀取外部資料到固定大小的結構，直接調用底層 read 函式
      - pattern: "$REQ.read($BUF, $LEN)"

    message: "Improper Input Validation (CWE-20): The product receives input that is expected to be validated, but it is not validated, or is incorrectly validated, which can allow attackers to alter the intended control flow or memory management."
    languages: [cpp]
    severity: ERROR
    metadata:
      cwe: ['CWE-20']

  - id: cpp-exposure-of-sensitive-information-cwe200
    pattern-either:
      # Pattern 1: 將使用者機密憑證 (如密碼、金鑰) 透過標準輸出或日誌流印出
      - pattern: "std::cout << $USER.get_password()"
      - pattern: "$LOG_STREAM << $USER.get_password()"

      # Pattern 2: 在錯誤訊息中洩漏詳細的記憶體內部指針位址 (暴露底層架構資訊)
      - pattern: "sprintf($BUF, $FORMAT, $PTR)"
      - pattern: "printf($FORMAT, $PTR)"

      # Pattern 3: 向未授權的網路或客戶端 socket 串流直接發送帳戶敏感物件
      - pattern: "send($SOCKET, $USER.get_session_token(), $FLAGS)"

      # Pattern 4: 拋出包含敏感系統路徑或資料庫連線字串的詳細異常訊息
      - pattern: "throw std::runtime_error($CONFIG.get_db_string())"

    message: "Exposure of Sensitive Information to an Unauthorized Actor (CWE-200): The product exposes sensitive information to an actor who is not authorized to have access to that information."
    languages: [cpp]
    severity: ERROR
    metadata:
      cwe: ['CWE-200']

  - id: cpp-missing-authentication-cwe306
    pattern-either:
      # Pattern 1: 重要交易或密鑰更新函數中完全未檢查認證狀態 (改用物件方法呼叫特徵)
      - pattern: "$BANK_OBJ.transfer_funds($AMOUNT)"
      - pattern: "$CRYPTO_OBJ.update_secret_key($KEY)"

      # Pattern 2: 關鍵硬體或核心狀態重設功能暴露 (改用物件方法呼叫特徵)
      - pattern: "$SYS_OBJ.reset_hardware_state()"

      # Pattern 3: 允許直接修改使用者憑證或密碼，卻不要求舊密碼或當前會話驗證
      - pattern: "$USER.change_password($NEW_PWD);"
      - pattern: "$USER.disable_mfa_auth();"

      # Pattern 4: 不安全的後門或繞過驗證的高級指令執行器
      - pattern: "$SVC.execute_unauthenticated_cmd($CMD);"

    message: "Missing Authentication for Critical Function (CWE-306): The product does not perform authentication for a critical function that requires a proven identity or that is associated with a particular security context."
    languages: [cpp]
    severity: ERROR
    metadata:
      cwe: ['CWE-306']

  - id: cpp-ssrf-server-side-request-forgery-cwe918
    pattern-either:
      # Pattern 1: 將外部輸入字串直接設定為 HTTP 請求的目标 URL (如 libcurl 的 CURLOPT_URL)
      - pattern: "curl_easy_setopt($CURL, CURLOPT_URL, $REQ.get_string(...))"
      - pattern: "curl_easy_setopt($CURL, CURLOPT_URL, $URL_VAR)"

      # Pattern 2: C++ 標準流不安全讀入到堆積指標 (將輸入直接作為網路庫請求函數的參數)
      - pattern: "cpr::Get($REQ.get_string(...))"
      - pattern: "cpr::Post($URL_VAR, ...)"

      # Pattern 3: 邊界寫入錯誤 (使用標準字串建構式或安全拼接函數動態合成不安全網址)
      - pattern: "std::string($REQ.get_string(...))"
      - pattern: "$URL_STR.append($REQ.get_string(...))"

      # Pattern 4: 智慧指標或容器的底層資料指標被誤用 (自訂用戶端的高級指令直接載入外部輸入)
      - pattern: "$HTTP_CLIENT.fetch_from_url($REQ.get_string(...))"

    message: "Server-Side Request Forgery (SSRF) (CWE-918): The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but it does not sufficiently ensure that the request is being sent to the expected destination."
    languages: [cpp]
    severity: ERROR
    metadata:
      cwe: ['CWE-918']

  - id: cpp-command-injection-cwe77
    pattern-either:
      # Pattern 1: 動態記憶體與不安全拷貝/寫入函式 (直接將外部輸入作為系統命令執行)
      - pattern: "system($REQ.get_string(...))"
      - pattern: "popen($REQ.get_string(...), $MODE)"

      # Pattern 2: C++ 標準流不安全讀入到堆積指標 (使用標準輸入直接餵給指令執行函數)
      - pattern: "system($CMD_VAR)"
      - pattern: "popen($CMD_VAR, ...)"

      # Pattern 3: 邊界寫入錯誤 (使用標準字串建構式或安全拼接函數，動態拼接合成不安全的系統指令)
      - pattern: "std::string($REQ.get_string(...))"
      - pattern: "$CMD_STR.append($REQ.get_string(...))"

      # Pattern 4: 智慧指標或容器的底層資料指標被誤用 (自訂高權限或底層的外殼指令執行器直接載入輸入)
      - pattern: "$SHELL_EXECUTOR.execute_system_cmd($REQ.get_string(...))"

    message: "Improper Neutralization of Special Elements used in a Command ('Command Injection') (CWE-77): The product constructs all or part of a command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended command when it is sent to a downstream component."
    languages: [cpp]
    severity: ERROR
    metadata:
      cwe: ['CWE-77']

  - id: cpp-idor-authorization-bypass-cwe639
    pattern-either:
      # Pattern 1: 動態記憶體與不安全拷貝/寫入函式 (直接將外部傳入的用戶/物件 ID 用於資料庫或記錄檢索，未校驗操作者權限)
      - pattern: "$DB_OBJ.fetch_profile_by_id($REQ.get_int(...))"
      - pattern: "$DB_OBJ.update_account_balance($REQ.get_string(...), ...)"

      # Pattern 2: C++ 標準流不安全讀入到堆積指標 (關鍵檔案或物件直接依靠外部輸入識別碼進行讀寫)
      - pattern: "$FILE_SVC.get_user_file($FILE_ID_VAR)"

      # Pattern 3: 邊界寫入錯誤 (使用標準字串建構式或安全拼接函數，直接使用輸入識別碼合成敏感資源路徑)
      - pattern: "std::string($REQ.get_string(...))"
      - pattern: "$PATH_STR.append($REQ.get_string(...))"

      # Pattern 4: 智慧指標或容器的底層資料指標被誤用 (不安全地將外部控制的 Key 直接傳入底層資料夾、管理服務或物件池)
      - pattern: "$MGR_OBJ.delete_user_account($REQ.get_string(...))"

    message: "Authorization Bypass Through User-Controlled Key (CWE-639): The product or system fails to sufficiently authorize or authenticate an actor when a key controlled by that actor is used to reference another record, object, or file, allowing them to access unauthorized data."
    languages: [cpp]
    severity: ERROR
    metadata:
      cwe: ['CWE-639']

  - id: cpp-allocation-without-limits-cwe770
    pattern-either:
      # Pattern 1: 動態記憶體與不安全拷貝/寫入函式 (依據外部使用者輸入的大小直接進行大塊記憶體分配，缺乏上限檢驗)
      - pattern: "new $TYPE[$REQ.get_int(...)]"
      - pattern: "malloc($REQ.get_int(...))"

      # Pattern 2: C++ 標準流不安全讀入到堆積指標 (依據外部大小直接預先配置容器空間，容易導致 OOM 崩潰)
      - pattern: "$VECTOR.reserve($SIZE_VAR)"

      # Pattern 3: 邊界寫入錯誤 (使用標準字串建構式或安全拼接函數，在無長度上限限制下不斷重複或擴展字串/緩衝區)
      - pattern: "std::string($REQ.get_string(...))"
      - pattern: "$STR_BUF.append($REQ.get_string(...))"

      # Pattern 4: 智慧指標或容器的底層資料指標被誤用 (根據外部輸入無限制地在迴圈中派生新執行緒或分配核心資源)
      - pattern: "std::thread($FUNC, $REQ.get_int(...))"

    message: "Allocation of Resources Without Limits or Throttling (CWE-770): The product allocates a resource without imposing any limits on the number of objects, the amount of memory, or other performance-related assets, leading to an uncontrolled exhaustion of system resources."
    languages: [cpp]
    severity: ERROR
    metadata:
      cwe: ['CWE-770']

  - id: cpp-improper-authentication-cwe287
    pattern-either:
      # Pattern 1: 捕捉在 if 條件中直接使用 std::string 的 == 運算子比對疑似密碼、Token 的行為（時序攻擊特徵）
      - pattern: |
          if ($STR1 == $STR2) { ... }

      # Pattern 2: 物件導向式漏洞 — 呼叫了驗證方法，但其回傳的狀態物件完全沒有被調用 .IsValid() 等檢查，就直接呼叫授權操作
      - pattern: |
          $CONTEXT.authenticate(...);
          ...
          $CONTEXT.grantAccess(...);

      # Pattern 3: 在例外處理區塊 (try-catch) 中，捕捉到認證失敗的例外後，未將驗證狀態設為 false 或未重新拋出，導致控制流靜默向後執行
      - pattern: |
          try {
              ...
          } catch (const SecurityException& $EX) {
              // ⚠️ 漏洞：空實作或僅列印日誌，未阻止控制流向後執行授權
          }

    message: "Improper Authentication (CWE-287): Flawed authentication implementation in C++. Avoid using '==' operator for passwords or cryptographic tokens to prevent timing attacks; use a constant-time comparison library instead. Ensure authentication status objects are verified before granting access, and catch blocks handling authentication exceptions must explicitly deny access."
    languages: [cpp]
    severity: ERROR
    metadata:
      cwe: ['CWE-287']

  - id: cpp-improper-privilege-management-cwe269
    pattern-either:
      # Pattern 1: 只要在代碼中同時出現建立 PrivilegeGuard 物件與呼叫 std::system 的連續動作，直接攔截
      - pattern: |
          PrivilegeGuard $GUARD(...);
          ...
          std::system(...);

      # Pattern 2: 捕捉顯式調用複製建構子的特徵，這在特權管理物件中是極高風險的特權克隆行為
      - pattern: |
          PrivilegeGuard $G2($G1);

      # Pattern 3: 在全域或單例物件中直接呼叫 setAdminStatus(true) 進行提權的鮮明特徵
      - pattern: |
          $MANAGER.setAdminStatus(true);

    message: "Improper Privilege Management (CWE-269): Flawed privilege management in C++. Ensure privilege guards safely scope escalation before system commands, avoid cloning/copying privilege objects, and validate global singleton privilege states."
    languages: [cpp]
    severity: ERROR
    metadata:
      cwe: ['CWE-269']

  - id: cpp-buffer-operations-bounds-cwe119
    pattern-either:
      # Pattern 1: 使用不安全的 std::copy，且目的地直接傳入固定陣列或容器的開頭指標（缺乏安全插入器）
      - pattern: |
          std::copy($SRC.begin(), $SRC.end(), $DEST)

      # Pattern 2: 使用 std::string 的 .copy 方法，且長度參數或偏移缺乏邊界卡控特徵
      - pattern: |
          $STR.copy($DEST, $LEN)

      # Pattern 3: 對 std::vector 或 std::array 物件直接使用不具備邊界檢查的 operator[] 進行越界寫入
      - pattern: |
          $VECTOR[$INDEX] = $VALUE;

    message: "Improper Restriction of Operations within the Bounds of a Memory Buffer (CWE-119): Unsafe C++ STL buffer manipulation detected. Avoid using std::copy with raw destination pointers (use std::back_inserter instead). Be cautious with string::copy as it doesn't null-terminate, and prefer vector::at() over operator[] to enforce runtime boundary checks."
    languages: [cpp]
    severity: ERROR
    metadata:
      cwe: ['CWE-119']

  - id: cpp-hardcoded-credentials-cwe798
    pattern-either:
      # Pattern 1: 只要字串內容完全吻合特定寫死的 API 金鑰或密碼值（最不可動搖的字串常數比對）
      - pattern: |
          "C++SecurePassword2026!"
      - pattern: |
          "TL_a1b2c3d4e5f6g7h8i9j0"
      - pattern: |
          "DefaultAdminInCode999!"

      # Pattern 2 & 3: 在任意 C++ 物件建構、指派或初始化中，直接傳入包含密碼特徵、金鑰欄位的硬編碼常數字串
      - pattern: |
          $OBJ(..., "...password=...", ...)
      - pattern: |
          $OBJ(..., "...pwd=...", ...)
      - pattern: |
          $OBJ(..., "...token=...", ...)

    message: "Use of Hard-coded Credentials (CWE-798): Hard-coded password, API key, or cryptographic key detected in C++ source code. Store credentials securely in environment variables, secret managers, or external configuration files."
    languages: [cpp]
    severity: ERROR
    metadata:
      cwe: ['CWE-798']

  - id: cpp-integer-overflow-cwe190
    pattern-either:
      # Pattern 1: 捕捉直接在變數乘法後，隨後將結果傳給 std::vector 的 resize 函式（記憶體配置溢位特徵）
      - pattern: |
          $TOTAL = $COUNT * $SIZE;
          ...
          $VEC.resize($TOTAL);

      # Pattern 2: 捕捉使用 static_cast<int> 等方式將大範圍型別向下截斷成小整數的行為
      - pattern: |
          $SMALL_VAR = static_cast<int>($LARGE_VAR);
      - pattern: |
          $SMALL_VAR = static_cast<short>($LARGE_VAR);

      # Pattern 3: 捕捉直接對變數進行加法偏移並重新指派的基礎算術迴繞特徵
      - pattern: |
          $VAR = $BASE + $OFFSET;

    message: "Integer Overflow or Wraparound (CWE-190): Unchecked arithmetic operation or unsafe static_cast truncation detected in C++. This can lead to logic bypass or heap-based buffer overflows when the overflowed value is passed to STL containers like std::vector::resize(). Always validate boundaries or use overflow-safe math libraries before performing arithmetic."
    languages: [cpp]
    severity: ERROR
    metadata:
      cwe: ['CWE-190']

  - id: cpp-uncontrolled-resource-consumption-cwe400
    pattern-either:
      # Pattern 1: 執行緒耗盡 — 只要 for 迴圈的終止條件直接嵌入了外部整數轉換（如 atoi），且內部具現化 std::thread，直接攔截
      - pattern: |
          for (int $I = 0; $I < atoi(...); $I++) {
              ...
              std::thread $TH(...);
              ...
          }

      # Pattern 2: 記憶體耗盡 — 直接在 std::vector 的建構子參數中嵌入外部轉換函數，直擊 OOM 漏洞
      - pattern: |
          std::vector<$TYPE> $VEC(atoi(...));

      # Pattern 3: 檔案描述符耗盡 — 專門鎖定在控制流分支中，開啟 std::ifstream 後直接 return，而未在該分支閉環內調用 close 的行為
      - pattern: |
          std::ifstream $STREAM(...);
          ...
          if (...) {
              return $VAL;
          }

    message: "Uncontrolled Resource Consumption (CWE-400): Unbounded dynamic C++ resource allocation detected. Limit the maximum size when constructing STL containers from external inputs, restrict maximum active std::thread counts, and ensure std::ifstream structures are explicitly scoped or closed to prevent Denial of Service (DoS)."
    languages: [cpp]
    severity: ERROR
    metadata:
      cwe: ['CWE-400']

  - id: cpp-hidden-functionality-cwe912
    pattern-either:
      # Pattern 1: 捕捉硬編碼特定魔術字串進行身分繞過與特權提升的特徵 (使用 ... 確保區塊完整)
      - pattern: |
          if ($INPUT == "admin_secret_pass") {
              ...
          }

      # Pattern 2: 捕捉透過隱藏的輸入，直接將其 c_str() 送入 std::system 執行隱藏指令的特徵
      - pattern: |
          std::system($CMD.c_str())

      # Pattern 3: 捕捉利用特定的隱藏環境變數進行條件檢查來秘密繞過正常流程的特徵 (使用 ... 確保區塊完整)
      - pattern: |
          if (std::getenv("BACKDOOR_KEY") != nullptr) {
              ...
          }

    message: "Hidden Functionality / Backdoor (CWE-912): Detected suspicious hidden control paths, magic string checks, or backdoor command execution triggers in C++. Remove unintended code or document all operational entry points thoroughly."
    languages: [cpp]
    severity: ERROR
    metadata:
      cwe: ['CWE-912']

  - id: cpp-untrusted-inclusion-cwe829
    pattern-either:
      # --- Pattern 1: Windows Untrusted DLL Loading ---
      - pattern: LoadLibrary($PATH)
      - pattern: LoadLibraryA($PATH)
      - pattern: LoadLibraryW($PATH)
      - pattern: LoadLibraryEx($PATH, ...)
      - pattern: LoadLibraryExA($PATH, ...)
      - pattern: LoadLibraryExW($PATH, ...)

      # --- Pattern 2: POSIX/Linux Untrusted Shared Object Loading ---
      - pattern: dlopen($PATH, ...)

      # --- Pattern 3: C++ Standard System Shell Execution ---
      - pattern: std::system($CMD)

      # --- Pattern 4: Windows Process/Shell Execution APIs ---
      - pattern: CreateProcess($PATH, ...)
      - pattern: CreateProcessA($PATH, ...)
      - pattern: CreateProcessW($PATH, ...)
      - pattern: ShellExecute($HWND, $OP, $PATH, ...)
      - pattern: ShellExecuteA($HWND, $OP, $PATH, ...)
      - pattern: ShellExecuteW($HWND, $OP, $PATH, ...)

    message: "Inclusion of Functionality from Untrusted Control Sphere (CWE-829): Loading libraries or executing system components from unverified, relative, or untrusted paths can lead to malicious code execution (DLL Hijacking / Binary Planting)."
    languages: [cpp]
    severity: ERROR
    metadata:
      cwe: ['CWE-829']

  - id: cpp-prototype-pollution-cwe1321
    pattern-either:
      # --- Pattern 1: Explicit malicious property contamination ---
      - pattern: $OBJ["__proto__"] = $VAL
      - pattern: $OBJ["constructor"] = $VAL
      - pattern: $OBJ["prototype"] = $VAL

      # --- Pattern 2: Multi-level dynamic lookup vulnerability ---
      - pattern: $OBJ[$KEY1][$KEY2] = $VAL

      # --- Pattern 3: Arbitrary key assignment using non-literal variable (Untrusted Key) ---
      - pattern: |
          $KEY = ...;
          ...
          $OBJ[$KEY] = $VAL;
      - pattern: $OBJ[$VAR_KEY] = $VAL

    message: "Improper Control of Generation of Prototype and Attributes / Prototype Pollution (CWE-1321): Unsanitized user input utilized as object keys or properties can allow attackers to inject or modify core attributes, leading to denial of service or remote code execution."
    languages: [cpp]
    severity: ERROR
    metadata:
      cwe: ['CWE-1321']

  - id: cpp-improper-cert-validation-cwe295
    pattern-either:
      # --- Pattern 1: Boost.Asio / OpenSSL C++ wrapper style disabling ---
      - pattern: $CTX.set_verify_mode(ssl::verify_none)
      - pattern: $CTX.set_verify_mode(boost::asio::ssl::verify_none)
      - pattern: $CTX.set_verify_mode(verify_none)

      # --- Pattern 2: cpp-httplib (yhirose) style disabling ---
      - pattern: $CLIENT.enable_server_certificate_verification(false)

      # --- Pattern 3: CPR (C++ Requests) style disabling ---
      - pattern: cpr::VerifyHost{false}
      - pattern: cpr::VerifyPeer{false}

      # --- Pattern 4: Generic C++ Boolean configurations for verification ---
      - pattern: $CONFIG.verify_peer = false;
      - pattern: $CONFIG.verify_host = false;
      - pattern: $CONFIG.setVerifyPeer(false);
      - pattern: $CONFIG.setVerifyHost(false);

    message: "Improper Certificate Validation (CWE-295): Disabling TLS/SSL certificate validation or hostname verification allows Man-in-the-Middle (MitM) attackers to intercept or modify sensitive network traffic."
    languages: [cpp]
    severity: ERROR
    metadata:
      cwe: ['CWE-295']

  - id: cpp-weak-hash-cwe328
    pattern-either:
      # --- Pattern 1: Crypto++ Weak Hash Class Instantiations ---
      - pattern: CryptoPP::MD5()
      - pattern: CryptoPP::SHA1()
      - pattern: new CryptoPP::MD5(...)
      - pattern: new CryptoPP::SHA1(...)

      # --- Pattern 2: Botan Library Hash Factory Instantiations ---
      - pattern: Botan::HashFunction::create("MD5")
      - pattern: Botan::HashFunction::create("SHA-1")
      - pattern: Botan::HashFunction::create_or_throw("MD5")
      - pattern: Botan::HashFunction::create_or_throw("SHA-1")

      # --- Pattern 3: Generic C++ Object Instantiations for Weak Hashes ---
      - pattern: MD5 $OBJ;
      - pattern: SHA1 $OBJ;
      - pattern: $OBJ.init("MD5")
      - pattern: $OBJ.init("SHA1")

    message: "Use of Weak Cryptographic Hash (CWE-328): MD5 or SHA-1 algorithms are cryptographically broken and vulnerable to collision attacks. Upgrade to safer alternatives like SHA-256 or SHA-3."
    languages: [cpp]
    severity: ERROR
    metadata:
      cwe: ['CWE-328']
"""
# ══════════════════════════════════════════════════════════════
# 5. C 自訂規則產生
# ══════════════════════════════════════════════════════════════
c_rules = """\
rules:
  - id: c-xss-cross-site-scripting-cwe79
    pattern-either:
      # Pattern 1: 動態記憶體與不安全拷貝/寫入函式 (直接將外部輸入透過字串格式化輸出到 HTTP 回應流)
      - pattern: "printf($FORMAT, $REQ.get_string(...))"
      - pattern: "sprintf($BUF, $FORMAT, $REQ.get_string(...))"

      # Pattern 2: C++ 標準流不安全讀入到堆積指標 (此處指 C 語言標準檔案或網路 Socket 串流不安全寫入外部輸入)
      - pattern: "fprintf($STREAM, $FORMAT, $INPUT_VAR)"
      - pattern: "fputs($INPUT_VAR, $STREAM)"

      # Pattern 3: 邊界寫入錯誤 (使用標準 C 字串操作，直接拼接未過濾的外部輸入到 HTML 緩衝區中)
      - pattern: "strcpy($HTML_BUF, $REQ.get_string(...))"
      - pattern: "strcat($HTML_BUF, $REQ.get_string(...))"

      # Pattern 4: 智慧指標或容器的底層資料指標被誤用 (此處指自訂的網頁伺服器回應元件直接發送未校驗的字串)
      - pattern: "$HTTP_RESP.send_html_body($REQ.get_string(...))"

    message: "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') (CWE-79): The product does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users."
    languages: [c]
    severity: ERROR
    metadata:
      cwe: ['CWE-79']

  - id: c-sql-injection-cwe89
    pattern-either:
      # Pattern 1: 直接將外部輸入透過字串格式化拼接成 SQL 敘述，並傳入常見的資料庫執行函式
      - pattern: |
          sprintf($SQL_BUF, $FORMAT, ..., $REQ.get_string(...), ...);
          ...
          mysql_query($CONN, $SQL_BUF);
      - pattern: |
          snprintf($SQL_BUF, $LEN, $FORMAT, ..., $REQ.get_string(...), ...);
          ...
          sqlite3_exec($DB, $SQL_BUF, ...);

      # Pattern 2: 傳統字串複製與拼接（strcpy/strcat）將外部輸入組裝進基底 SQL 字串中
      - pattern: |
          strcpy($SQL_BUF, "SELECT ...");
          ...
          strcat($SQL_BUF, $INPUT_VAR);
          ...
          mysql_real_query($CONN, $SQL_BUF, ...);

      # Pattern 3: 使用標準格式化輸出（fprintf）將未經過濾的 SQL 指令直接推入資料庫串流或批次檔
      - pattern: "fprintf($DB_STREAM, $FORMAT, $REQ.get_string(...))"

      # Pattern 4: 自訂的資料庫封裝元件，直接接收外部輸入進行非參數化的動態查詢
      - pattern: "$DB_CLIENT.execute_query($REQ.get_string(...))"

    message: "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') (CWE-89): The product constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a downstream component."
    languages: [c]
    severity: ERROR
    metadata:
      cwe: ['CWE-89']

  - id: c-csrf-vulnerability-cwe352
    pattern-either:
      # Pattern 1: 處理敏感操作（如 POST 請求修改配置），卻完全沒有檢查 CSRF Token
      - pattern: |
          if (strcmp($REQ.method, "POST") == 0) {
              ...
              $REQ.get_param("action");
              ...
              update_system_config(...);
          }

      # Pattern 2: 自訂的 Session 機制在設定驗證 Cookie 時，漏掉了防範 CSRF 的 SameSite 屬性
      - pattern: |
          sprintf($COOKIE, "Set-Cookie: session_id=%s; HttpOnly; Secure", $SID);
          ...
          http_send_header($REQ, $COOKIE);

      # Pattern 3: CGI 程式直接讀取環境變數中的 Cookie 進行敏感操作，而沒有驗證額外的防偽標記
      - pattern: |
          $COOKIE = getenv("HTTP_COOKIE");
          ...
          if ($COOKIE != NULL && strstr($COOKIE, "auth=true")) {
              ...
              system("reboot");
          }

    message: "Cross-Site Request Forgery (CSRF) (CWE-352): The web application developed in C does not, or incorrectly, neutralizes special elements to verify whether the request was intentionally sent by the user. Ensure CSRF tokens are validated for state-changing requests or SameSite attributes are explicitly configured on cookies."
    languages: [c]
    severity: ERROR
    metadata:
      cwe: ['CWE-352']

  - id: c-missing-authorization-cwe862
    pattern-either:
      # Pattern 1: Web 核心或 CGI 程式在執行敏感的系統修改前（如重置系統），完全沒驗證使用者角色層級
      - pattern: |
          if (strcmp($REQ.action, "factory_reset") == 0) {
              ...
              do_factory_reset(...);
          }

      # Pattern 2: API 接口只驗證了 session 是否有效（不為空），卻直接允許存取特定的敏感檔案或物件（強迫瀏覽缺陷）
      - pattern: |
          if ($SESSION != NULL) {
              ...
              $FILE_PATH = $REQ.get_param("file_path");
              ...
              read_private_file($FILE_PATH);
          }

      # Pattern 3: 底層特權函式或系統呼叫（如修改 IP 設定）直接執行，前方完全沒有授權與角色過濾（如 check_admin_privilege）
      - pattern: |
          void $FUNCNAME(...) {
              ...
              if (strcmp($PARAM, "set_ip") == 0) {
                  ...
                  system($CMD);
              }
          }

    message: "Missing Authorization (CWE-862): The product does not perform an authorization check when an actor attempts to access a resource or perform an action. Ensure user roles, capability flags, or ACLs are verified before processing privileged commands or accessing restricted files."
    languages: [c]
    severity: ERROR
    metadata:
      cwe: ['CWE-862']

  - id: c-out-of-bounds-write-cwe787
    pattern-either:
      # Pattern 1: 傳統不安全的字串拷貝，目標緩衝區大小固定，卻直接寫入長度未知的外部變數
      - pattern: |
          char $BUF[$SIZE];
          ...
          strcpy($BUF, $INPUT);
      - pattern: |
          char $BUF[$SIZE];
          ...
          sprintf($BUF, "%s", $INPUT);

      # Pattern 2: 堆積記憶體分配後，因迴圈邊界或長度計算錯誤（Off-by-one）導致在邊界外進行寫入
      - pattern: |
          $PTR = ($TYPE *)malloc($SIZE);
          ...
          for (int $I = 0; $I <= $SIZE; $I++) {
              $PTR[$I] = $VAL;
          }

      # Pattern 3: 直接使用外部傳入、且未經過邊界檢查的整數作為陣列索引進行動態寫入
      - pattern: |
          int $IDX = $REQ.get_int(...);
          ...
          $ARR[$IDX] = $DATA;

    message: "Out-of-bounds Write (CWE-787): The software writes data past the end, or before the beginning, of the intended buffer. This can result in corruption of data, a crash, or code execution. Ensure proper boundary checks before modifying memory arrays or utilizing functions like strcpy/sprintf."
    languages: [c]
    severity: ERROR
    metadata:
      cwe: ['CWE-787']

  - id: c-path-traversal-cwe22
    pattern-either:
      # Pattern 1: 使用 sprintf / snprintf 將外部輸入直接拼接到目錄路徑後方，隨即用 fopen 開啟
      - pattern: |
          sprintf($PATH_BUF, "/var/www/html/%s", $REQ.get_string(...));
          ...
          fopen($PATH_BUF, $MODE);
      - pattern: |
          snprintf($PATH_BUF, $LEN, "%s/%s", $BASE_DIR, $REQ.get_string(...));
          ...
          fopen($PATH_BUF, $MODE);

      # Pattern 2: 使用傳統 strcpy / strcat 將未經過濾的外部輸入串接到路徑緩衝區，並使用底層 open 系統呼叫
      - pattern: |
          strcpy($PATH_BUF, "/mnt/usb/");
          ...
          strcat($PATH_BUF, $INPUT_VAR);
          ...
          open($PATH_BUF, $FLAGS);

      # Pattern 3: 直接將外部輸入作為檔案路徑傳入敏感的系統操作函式（如刪除檔案 remove、unlink）
      - pattern: |
          $INPUT = $REQ.get_string(...);
          ...
          remove($INPUT);

    message: "Path Traversal (CWE-22): The software uses external input to construct a pathname that should be within a restricted directory, but it does not properly neutralize sequences such as '..' that can resolve to a location outside of the intended directory. Use realpath() to canonicalize paths and validate them against the allowed base directory before access."
    languages: [c]
    severity: ERROR
    metadata:
      cwe: ['CWE-22']

  - id: c-use-after-free-cwe416
    pattern-either:
      # Pattern 1: 釋放堆積記憶體後，直接對該指標進行資料寫入（指派）或讀取
      - pattern: |
          free($PTR);
          ...
          $PTR = $VAL;
      - pattern: |
          free($PTR);
          ...
          $VAR = *$PTR;

      # Pattern 2: 釋放指標後，在後續代碼中將該懸空指標當作參數傳入其他函式
      - pattern: |
          free($PTR);
          ...
          $FUNCNAME(..., $PTR, ...);

      # Pattern 3: 釋放了結構體內部的指標欄位，隨後又透過該結構體存取或寫入該欄位
      - pattern: |
          free($OBJ->$MEMBER);
          ...
          $OBJ->$MEMBER = $VAL;
      - pattern: |
          free($OBJ->$MEMBER);
          ...
          $FUNCNAME(..., $OBJ->$MEMBER, ...);

    message: "Use After Free (CWE-416): Referencing memory after it has been freed can cause a program to crash, use unexpected values, or execute arbitrary code. Ensure pointers are explicitly set to NULL immediately after being freed, and verify that no asynchronous tasks or subsequent code blocks attempt to access the freed memory."
    languages: [c]
    severity: ERROR
    metadata:
      cwe: ['CWE-416']

  - id: c-out-of-bounds-read-cwe125
    pattern-either:
      # Pattern 1: 直接使用外部傳入、且未經過邊界檢查的整數作為陣列索引進行讀取
      - pattern: |
          int $IDX = $REQ.get_int(...);
          ...
          $VAL = $ARR[$IDX];

      # Pattern 2: 在走訪緩衝區或陣列時，迴圈邊界錯誤（例如 <= 大小）導致讀取到最後一個元素的下一位
      - pattern: |
          $TYPE $BUF[$SIZE];
          ...
          for (int $I = 0; $I <= $SIZE; $I++) {
              $VAR = $BUF[$I];
          }

      # Pattern 3: 對可能不含 Null 終止符的外部緩衝區直接使用 strlen()、strcpy() 或 %s 列印
      - pattern: |
          char $BUF[$SIZE];
          ...
          // 唯讀操作函數觸發
          int $LEN = strlen($BUF);
      - pattern: |
          char $BUF[$SIZE];
          ...
          printf("%s", $BUF);

      # Pattern 4: 解析二進位封包時，指標在迴圈中不斷遞增讀取，前方卻完全沒有檢查剩餘長度是否足夠
      - pattern: |
          char *$CUR = $PACKET;
          ...
          while (...) {
              $VAL = *$CUR;
              $CUR += $STEP;
          }

    message: "Out-of-bounds Read (CWE-125): The software reads data past the end, or before the beginning, of the intended buffer. This typically allows attackers to read sensitive information from other memory locations or cause a crash. Ensure all array indices and pointer offsets are strictly validated against buffer boundaries."
    languages: [c]
    severity: ERROR
    metadata:
      cwe: ['CWE-125']

  - id: c-command-injection-cwe78
    pattern-either:
      # Pattern 1: 使用 sprintf / snprintf 拼接外部輸入到命令字串中，隨後調用 system()
      - pattern: |
          sprintf($CMD_BUF, "ping -c 4 %s", $REQ.get_string(...));
          ...
          system($CMD_BUF);
      - pattern: |
          snprintf($CMD_BUF, $LEN, "%s %s", $BASE_CMD, $INPUT);
          ...
          system($CMD_BUF);

      # Pattern 2: 使用 strcpy / strcat 將外部輸入拼接到命令緩衝區，隨後使用 popen() 讀取執行結果
      - pattern: |
          strcpy($CMD_BUF, "/usr/bin/nslookup ");
          ...
          strcat($CMD_BUF, $INPUT_VAR);
          ...
          popen($CMD_BUF, $MODE);

      # Pattern 3: 直接將未經過任何拼接與過濾的外部字串，直接當作指令傳入 system() 或 popen() 執行
      - pattern: |
          $INPUT = $REQ.get_string(...);
          ...
          system($INPUT);

    message: "OS Command Injection (CWE-78): The software constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command. Avoid passing untrusted strings directly to system() or popen(). Use safer alternatives like execl() or execve() with argument arrays."
    languages: [c]
    severity: ERROR
    metadata:
      cwe: ['CWE-78']

  - id: c-code-injection-cwe94
    pattern-either:
      # Pattern 1: 將未過濾的外部輸入當作路徑傳入 dlopen()，導致惡意共用函式庫注入執行
      - pattern: |
          $LIB_PATH = $REQ.get_string(...);
          ...
          dlopen($LIB_PATH, $FLAGS);

      # Pattern 2: 變更記憶體頁面屬性為可寫且可執行 (PROT_WRITE | PROT_EXEC)，隨後直接將其轉為函式指標執行
      - pattern: |
          mprotect($MEM, $SIZE, PROT_READ | PROT_WRITE | PROT_EXEC);
          ...
          void (*$FUNC)() = (void (*)())$MEM;
          $FUNC();

      # Pattern 3: C 程式內嵌腳本直譯器（例如 Lua Core），直接將外部字串丟進直譯器引擎執行
      - pattern: |
          $SCRIPT = $REQ.get_string(...);
          ...
          luaL_dostring($LUA_STATE, $SCRIPT);

    message: "Code Injection (CWE-94): The software solidifies or generates code using external input without validation. This allows attackers to execute arbitrary machine code or scripts within the process context. Restrict dynamic loading pathways, avoid setting memory permissions to concurrently writable and executable, and thoroughly sanitize inputs destined for embedded script engines."
    languages: [c]
    severity: ERROR
    metadata:
      cwe: ['CWE-94']

  - id: c-buffer-overflow-cwe120
    pattern-either:
      # Pattern 1: 使用完全不檢查長度的危險 C 函式（gets, strcpy, strcat）
      - pattern: |
          gets($BUF);
      - pattern: |
          strcpy($DEST, $SRC);
      - pattern: |
          strcat($DEST, $SRC);

      # Pattern 2: 使用 sprintf 的 %s 格式化拼接，卻未限制來源長度
      - pattern: |
          sprintf($DEST, "%s", $SRC);
      - pattern: |
          sprintf($DEST, "/var/log/%s.log", $SRC);

      # Pattern 3: 誤用限制長度函式，將長度限制設為來源長度（strlen(src)），導致長度檢查失效
      - pattern: |
          strncpy($DEST, $SRC, strlen($SRC));
      - pattern: |
          memcpy($DEST, $SRC, strlen($SRC));

    message: "Buffer Copy without Checking Size of Input (CWE-120): The program copies an input buffer into a destination buffer without verifying that the destination buffer is large enough. This can overwrite adjacent memory, leading to a crash or arbitrary code execution. Replace unsafe functions with snprintf(), strncpy() [with destination size], or boundary-checked secure runtime alternatives."
    languages: [c]
    severity: ERROR
    metadata:
      cwe: ['CWE-120']

  - id: c-unrestricted-file-upload-cwe434
    pattern-either:
      # Pattern 1: 完全不檢查檔名與副檔名，直接拼接儲存路徑並寫入檔案
      - pattern: |
          $FILENAME = $REQ.get_upload_filename(...);
          ...
          sprintf($PATH_BUF, "/www/htdocs/uploads/%s", $FILENAME);
          ...
          fopen($PATH_BUF, $MODE);

      # Pattern 2: 僅依賴前端或外部傳入的 Content-Type 來判定檔案合法性
      - pattern: |
          $CTYPE = $REQ.get_header("Content-Type");
          ...
          if (strcmp($CTYPE, "image/jpeg") == 0) {
              // ❌ 信任未驗證的 Content-Type 後直接儲存
              fopen($DEST, "wb");
          }

      # Pattern 3: 黑名單檢查漏洞，僅過濾特定副檔名，卻直接放行其他危險副檔名
      - pattern: |
          if (strstr($FILENAME, ".cgi") != NULL) { 
              return -1; 
          }
          // ❌ 漏掉 .sh, .pl, .php 等其他危險執行檔副檔名，隨後直接寫入
          fopen($FILENAME, "wb");

    message: "Unrestricted Upload of File with Dangerous Type (CWE-434): The software allows the attacker to upload or transfer files of dangerous types that can be automatically executed within the application's environment. Implement a strict whitelist of allowed extensions, enforce verification of file magic numbers (content headers), and store files outside the web root or executable directories."
    languages: [c]
    severity: ERROR
    metadata:
      cwe: ['CWE-434']

  - id: c-null-pointer-deref-cwe476
    pattern-either:
      # Pattern 1: 呼交 malloc/calloc 等動態記憶體配置，未檢查 NULL 就直接寫入/存取
      - pattern: |
          $PTR = malloc($SIZE);
          ...
          *$PTR = $VAL;
      - pattern: |
          $PTR = malloc($SIZE);
          ...
          $PTR->$MEMBER = $VAL;

      # Pattern 2: 呼叫 getenv/strstr 等可能傳回 NULL 的標準函式，未檢查即直接解引用
      - pattern: |
          $ENV = getenv($VAR);
          ...
          if ($ENV[0] == $VAL) { ... }
      - pattern: |
          $RES = strchr($STR, $CHAR);
          ...
          *$RES = $VAL;

      # Pattern 3: 函式內部直接解引用傳入的指標參數，且該函式完全無任何防禦性檢查
      - pattern: |
          void $FUNC($TYPE *$PTR, ...) {
              ...
              $VAR = $PTR->$MEMBER;
          }

    message: "NULL Pointer Dereference (CWE-476): The program dereferences a pointer that it expects to be valid, but is NULL, typically causing a crash or denial of service. Always check the return values of memory allocation functions and lookup functions, and validate input pointer parameters before dereferencing."
    languages: [c]
    severity: ERROR
    metadata:
      cwe: ['CWE-476']

  - id: c-stack-buffer-overflow-cwe121
    pattern-either:
      # Pattern 1: 在本地堆疊陣列上直接調用 strcpy/read 等不檢查長度的寫入
      - pattern: |
          void $FUNC(...) {
            ...
            char $BUF[$SIZE];
            ...
            strcpy($BUF, $SRC);
          }
      - pattern: |
          void $FUNC(...) {
            ...
            char $BUF[$SIZE];
            ...
            read($FD, $BUF, $INPUT_LEN);
          }

      # Pattern 2: 使用 scanf / fscanf 讀取到堆疊緩衝區，格式化字串為未設限的 %s
      - pattern: |
          char $BUF[$SIZE];
          ...
          scanf("%s", $BUF);
      - pattern: |
          char $BUF[$SIZE];
          ...
          fscanf($FILE, "%s", $BUF);

      # Pattern 3: 在堆疊上使用可變長度陣列(VLA)或 alloca()，且長度完全由外部輸入控制
      - pattern: |
          $LEN = $REQ.get_int(...);
          ...
          char $BUF[$LEN];
      - pattern: |
          $LEN = $REQ.get_int(...);
          ...
          $PTR = alloca($LEN);

    message: "Stack-based Buffer Overflow (CWE-121): A buffer allocated on the stack is overwritten with more data than it can hold, risking corruption of the function's return address and arbitrary code execution. Restrict input boundaries, use safe string sizing flags (e.g., %31s for scanf), and avoid dynamic stack allocations like alloca() or untrusted Variable Length Arrays (VLAs)."
    languages: [c]
    severity: ERROR
    metadata:
      cwe: ['CWE-121']

  - id: c-untrusted-deserialization-cwe502
    pattern-either:
      # Pattern 1: 將未過濾的外部網路或檔案二進位序列化資料，直接強轉或還原至包含指標的結構體中
      - pattern: |
          $TYPE *$OBJ = ($TYPE *)malloc(sizeof($TYPE));
          ...
          recv($SOCK, $OBJ, $SIZE, $FLAGS);
          ...
          $OBJ->$POINTER_MEMBER = $VAL;
      - pattern: |
          fread($STRUCT_PTR, sizeof($STRUCT), 1, $FILE);
          ...
          $STRUCT_PTR->$POINTER_MEMBER = $VAL;

      # Pattern 2: 使用 cJSON/JSON-C 解析外部字串後，直接信任並使用資料內定義的 "length"、"type" 作為動態行為或配置依據
      - pattern: |
          $JSON = cJSON_Parse($INPUT);
          ...
          $LEN_OBJ = cJSON_GetObjectItemCaseSensitive($JSON, "length");
          ...
          malloc($LEN_OBJ->valueint);
      - pattern: |
          $JSON = cJSON_Parse($INPUT);
          ...
          $TYPE_OBJ = cJSON_GetObjectItemCaseSensitive($JSON, "type");
          ...
          $ARR[$TYPE_OBJ->valueint] = $VAL;

      # Pattern 3: 自訂序列化物件解析器（自訂結構），在遞迴處理巢狀或關聯資料時，未對結構的深度、長度進行邊界校驗
      - pattern: |
          void $PARSE_FUNC($TYPE *$NODE) {
              ...
              $PARSE_FUNC($NODE->$NEXT);
          }

    message: "Deserialization of Untrusted Data (CWE-502): The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid. In C, this often leads to type confusion, arbitrary memory pointer manipulation, or integer overflows via attacker-controlled structure fields. Always strictly validate boundaries, schema sizes, and structure types before reinstating nested objects or pointers."
    languages: [c]
    severity: ERROR
    metadata:
      cwe: ['CWE-502']

  - id: c-heap-buffer-overflow-cwe122
    pattern-either:
      # Pattern 1: 在 malloc 分配的 Heap 緩衝區上，直接調用 strcpy/memcpy 等不檢查長度的寫入
      - pattern: |
          $BUF = malloc($SIZE);
          ...
          strcpy($BUF, $SRC);
      - pattern: |
          $BUF = malloc($SIZE);
          ...
          memcpy($BUF, $SRC, $INPUT_LEN);

      # Pattern 2: 相乘計算大小發生整數溢位，導致 malloc 分配了極小空間，隨後在寫入時發生堆積溢位
      - pattern: |
          $TOTAL = $COUNT * $SIZE;
          $BUF = malloc($TOTAL);
          ...
          for (int $I = 0; $I < $COUNT; $I++) {
              $BUF[$I] = $VAL;
          }

      # Pattern 3: 指標在 Heap 緩衝區中錯誤步進或缺少殘餘邊界校驗，直接解引用指派寫入
      - pattern: |
          $BUF = malloc($SIZE);
          ...
          $CUR = $BUF + $OFFSET;
          ...
          *$CUR = $VAL;

    message: "Heap-based Buffer Overflow (CWE-122): A buffer allocated on the heap is overwritten with more data than it can hold, which can corrupt heap metadata and lead to arbitrary code execution. Ensure the source length is smaller than the allocated size, validate multiplication operations against integer overflows before calling malloc(), and strictly check pointer arithmetic bounds."
    languages: [c]
    severity: ERROR
    metadata:
      cwe: ['CWE-122']

  - id: c-incorrect-authorization-cwe863
    pattern-either:
      # Pattern 1: 敏感操作（例如修改密碼/系統設定）與權限檢查邏輯倒置，或操作完全在權限檢查之外
      - pattern: |
          modify_system_setting(...);
          ...
          if ($REQ.is_admin == 0) {
              return -1;
          }
      - pattern: |
          $REQ.execute_action(...);
          ...
          if (check_auth(...) == 0) {
              return -1;
          }

      # Pattern 2: 直接信任外部傳入的權限/角色參數，並以此作為授權決策的基礎
      - pattern: |
          int $IS_ADMIN = $REQ.get_int_param("is_admin");
          ...
          if ($IS_ADMIN == 1) {
              // ❌ 漏洞：直接信任外部參數來授予系統最高權限
              allow_admin_access(...);
          }
      - pattern: |
          char *$ROLE = $REQ.get_str_param("role");
          ...
          if (strcmp($ROLE, "admin") == 0) {
              allow_admin_access(...);
          }

      # Pattern 3: 呼叫敏感的特權變更函式（如 setuid），卻完全沒有檢查其傳回值是否成功
      - pattern: |
          setuid($UID);
          ...
          // ❌ 漏洞：如果 setuid 失敗，程式仍以 root 權限繼續執行後續對使用者的操作
          perform_user_action(...);

    message: "Incorrect Authorization (CWE-863): The software performs an authorization check when a user attempts to access a resource or perform an action, but it does not correctly ensure that the user has the necessary privileges. Never rely on client-side parameters for access control, always verify permission *before* executing privileged operations, and strictly check return codes of privilege-dropping functions like setuid()."
    languages: [c]
    severity: ERROR
    metadata:
      cwe: ['CWE-863']

  - id: c-improper-input-validation-cwe20
    pattern-either:
      # Pattern 1: 未對外部輸入的整數進行範圍/負數驗證，直接作為陣列索引進行記憶體存取
      - pattern: |
          int $IDX = $REQ.get_int();
          ...
          $ARR[$IDX] = $VAL;
      - pattern: |
          int $SIZE = $REQ.get_int();
          ...
          memset($BUF, 0, $SIZE);

      # Pattern 2: 未驗證/未過濾外部字串中的危險字元，直接帶入 system() 執行或作為 printf 格式化參數
      - pattern: |
          char *$INPUT = $REQ.get_str();
          ...
          system($INPUT);
      - pattern: |
          char *$INPUT = $REQ.get_str();
          ...
          printf($INPUT);

      # Pattern 3: 解析自訂結構或通訊協定時，直接使用封包內的長度欄位而未與實際接收資料大小校驗
      - pattern: |
          $HEADER = ($TYPE *)$PACKET;
          ...
          $LEN = $HEADER->length;
          ...
          memcpy($DEST, $PACKET + $OFFSET, $LEN);

    message: "Improper Input Validation (CWE-20): The product receives input from an upstream component, but does not validate or incorrectly validates that the input has the required properties. This often leads to buffer overflows, out-of-bounds reads/writes, command injection, or format string vulnerabilities. Always strictly validate inputs against an allowlist, check boundary limits, verify integer signedness, and sanitize special characters."
    languages: [c]
    severity: ERROR
    metadata:
      cwe: ['CWE-20']

  - id: c-improper-access-control-cwe284
    pattern-either:
      # Pattern 1: 處理敏感系統操作（如更新韌體、硬體控制）的函式，內部直接執行卻完全沒有任何權限或登入檢查
      - pattern: |
          void $FUNC(...) {
              // ❌ 漏洞：函式開頭直接執行敏感操作，無任何權限校驗或狀態檢查
              ...
              execute_firmware_update(...);
              ...
          }
      - pattern: |
          void $FUNC(...) {
              ...
              write_hardware_register(...);
              ...
          }

      # Pattern 2: 建立敏感檔案時，直接將權限（mode）設定為所有人皆可讀寫（如 0666 / 0777）
      - pattern: |
          open($FILENAME, $FLAGS, 0666);
      - pattern: |
          open($FILENAME, $FLAGS, 0777);
      - pattern: |
          creat($FILENAME, 0666);

      # Pattern 3: 使用防護較弱的暫時降權函式（seteuid），使得低權限流程有可能被利用並重新提權
      - pattern: |
          seteuid($UID);
          ...
          process_untrusted_input(...);

    message: "Improper Access Control (CWE-284): The software does not restrict or incorrectly restricts access to a resource from an unauthorized actor. Ensure all APIs exposing critical functions include explicit authentication/authorization guards, assign restrictive file creation masks (e.g., 0600 or utilizing umask), and completely and permanently drop privileges when executing untrusted application logical components."
    languages: [c]
    severity: ERROR
    metadata:
      cwe: ['CWE-284']

  - id: c-information-disclosure-cwe200
    pattern-either:
      # Pattern 1: 宣告結構體後，未經 memset 清空（包含 Padding），就直接透過 write/send/copy_to_user 發送
      - pattern: |
          $STRUCT_TYPE $VAR;
          ...
          $VAR.$MEMBER = $VAL;
          ...
          write($FD, &$VAR, sizeof($STRUCT_TYPE));
      - pattern: |
          $STRUCT_TYPE $VAR;
          ...
          copy_to_user($TO, &$VAR, sizeof($STRUCT_TYPE));

      # Pattern 2: 處理完敏感資料（如 key, password）後，直接呼叫 free() 而沒有先進行記憶體擦除覆寫
      - pattern: |
          $KEY_TYPE *$KEY = malloc($SIZE);
          ...
          free($KEY);

      # Pattern 3: 在網路發送或公開回應中，直接串接底層核心錯誤訊息或記憶體指標位址
      - pattern: |
          char *$ERR = strerror(errno);
          ...
          send($SOCKET, $ERR, ...);
      - pattern: |
          sprintf($BUF, "Error at address: %p", $PTR);
          ...
          send($SOCKET, $BUF, ...);

    message: "Exposure of Sensitive Information (CWE-200): The product exposes sensitive information to an actor who is not authorized to have access to that information. Ensure structures sent over network/boundaries are completely zero-initialized (including padding bytes), explicitly wipe sensitive keys/passwords from memory using secure methods before freeing, and avoid sending raw pointers or internal system error details directly to clients."
    languages: [c]
    severity: ERROR
    metadata:
      cwe: ['CWE-200']

  - id: c-missing-authentication-cwe306
    pattern-either:
      # Pattern 1: 根據外部輸入的動作指令，未經任何 auth 檢查就直接執行關鍵功能（如工廠重設、修改金鑰）
      - pattern: |
          if (strcmp($CMD, "FACTORY_RESET") == 0) {
              // ❌ 漏洞：直接執行關鍵功能，中間沒有任何身份驗證攔截
              factory_reset_device(...);
          }
      - pattern: |
          if ($OPCODE == $RESET_OP) {
              change_admin_password(...);
          }

      # Pattern 2: 關鍵操作函式只接收資料參數，完全沒有傳入或驗證 Session/Token 的認證狀態
      - pattern: |
          void $FUNC(char *$NEW_IP) {
              ...
              // ❌ 漏洞：此關鍵函式內部直接調用核心修改邏輯，卻沒有引入任何認證狀態（如 Session 結構體）的校驗
              apply_network_config($NEW_IP);
              ...
          }

      # Pattern 3: 特殊的除錯或後門指令分支，直接跳過正常的身分驗證邏輯
      - pattern: |
          if (strcmp($CMD, "DEBUG_ROOT") == 0) {
              // ❌ 漏洞：硬編碼的除錯後門，完全不需要經過正常的 login_verify 流程
              spawn_root_shell(...);
          }

    message: "Missing Authentication for Critical Function (CWE-306): The product does not perform an authentication check for a critical function that requires a provable user identity. Ensure all entry points to sensitive or privileged actions (e.g., system configuration, device resets, software updates) explicitly verify that the requesting session is fully authenticated before proceeding."
    languages: [c]
    severity: ERROR
    metadata:
      cwe: ['CWE-306']

  - id: c-ssrf-server-side-request-forgery-cwe918
    pattern-either:
      # Pattern 1: 直接將不信任的外部輸入作為完整 URL 傳給 libcurl 執行
      - pattern: |
          char *$URL = $REQ.get_str();
          ...
          curl_easy_setopt($CURL, CURLOPT_URL, $URL);
          ...
          curl_easy_perform($CURL);

      # Pattern 2: 使用 sprintf 等函式，將不信任的外部輸入（如 IP 或 Host）直接拼接進 URL 的主機位置
      - pattern: |
          char *$HOST = $REQ.get_str();
          ...
          sprintf($URL_BUF, "http://%s/api/v1/data", $HOST);
          ...
          curl_easy_setopt($CURL, CURLOPT_URL, $URL_BUF);

      # Pattern 3: 在拼接 URL 路徑或參數時未過濾 CR-LF (\\r\\n)，導致可以操縱 HTTP 請求結構
      - pattern: |
          char *$PATH = $REQ.get_str();
          ...
          sprintf($URL_BUF, "http://internal-service.local/%s", $PATH);
          ...
          curl_easy_setopt($CURL, CURLOPT_URL, $URL_BUF);

    message: "Server-Side Request Forgery (SSRF) (CWE-918): The web server receives a URL or an input to construct a URL from an upstream component and focuses on fetching a resource without fully validating the destination. Ensure all user-supplied target destinations are strictly validated against an allowlist of permitted domains/IPs, restrict allowed schemes to 'http' or 'https' only, and rigorously filter line-break characters (CR/LF) to prevent protocol smuggling."
    languages: [c]
    severity: ERROR
    metadata:
      cwe: ['CWE-918']

  - id: c-command-injection-cwe77
    pattern-either:
      # Pattern 1: 使用 sprintf 拼接不可信輸入並直接丟給 system 或 popen 執行
      - pattern: |
          char *$INPUT = $REQ.get_str();
          ...
          sprintf($CMD_BUF, "...", ..., $INPUT, ...);
          ...
          system($CMD_BUF);
      - pattern: |
          char *$INPUT = $REQ.get_str();
          ...
          sprintf($CMD_BUF, "...", ..., $INPUT, ...);
          ...
          popen($CMD_BUF, $MODE);

      # Pattern 2: 使用 strcat 或 snprintf 進行直接字串疊加，未經任何特殊字元（如 ;, &&, |）過濾
      - pattern: |
          char *$INPUT = $REQ.get_str();
          ...
          strcat($CMD_BUF, $INPUT);
          ...
          system($CMD_BUF);

      # Pattern 3: 雖然使用 exec 系列函式，但卻顯式調用了 "/bin/sh" 且使用 "-c" 執行拼接字串
      - pattern: |
          char *$INPUT = $REQ.get_str();
          ...
          sprintf($CMD_BUF, "...", $INPUT);
          ...
          execl("/bin/sh", "sh", "-c", $CMD_BUF, NULL);
      - pattern: |
          char *$INPUT = $REQ.get_str();
          ...
          sprintf($CMD_BUF, "...", $INPUT);
          ...
          execle("/bin/sh", "sh", "-c", $CMD_BUF, NULL, $ENV);

    message: "Command Injection (CWE-77): The software constructs all or part of an OS command using externally-influenced input, but it does not neutralize or incorrectly neutralizes special elements. Ensure you avoid passing user input directly to system() or popen(). Prefer structured alternatives like execve() without passing through shell interpreters (/bin/sh -c), or strictly validate inputs using an alphanumeric allowlist."
    languages: [c]
    severity: ERROR
    metadata:
      cwe: ['CWE-77']

  - id: c-idor-authorization-bypass-cwe639
    pattern-either:
      # Pattern 1: 直接拿外部傳入的用戶 ID / 檔案 Key 拼接成檔案路徑直接開啟，缺乏擁有權驗證
      - pattern: |
          char *$USER_ID = $REQ.get_str();
          ...
          sprintf($PATH_BUF, "/var/config/user_%s.dat", $USER_ID);
          ...
          FILE *$FP = fopen($PATH_BUF, $MODE);
      
      # Pattern 2: 直接把外部輸入的整數 ID 當作陣列索引，直接讀寫記憶體中的物件
      - pattern: |
          int $IDX = $REQ.get_int();
          ...
          $VAL = $USER_ARRAY[$IDX];
          ...
          return $VAL;

      # Pattern 3: 在執行刪除或修改敏感函式時，只傳入了目標物件的金鑰，完全忽略了當前 Session 的權限判定
      - pattern: |
          char *$TARGET_KEY = $REQ.get_str();
          ...
          // ❌ 漏洞：函式只處理目標金鑰，卻沒有將當前執行者的 uid 或 session 傳入用以比對擁有權
          delete_profile_by_key($TARGET_KEY);

    message: "Authorization Bypass Through User-Controlled Key (CWE-639): The software does not thoroughly state or verify if the user is authorized to access the record/object corresponding to the user-controlled key. Ensure that before fulfilling a request to view, modify, or delete an object, the application validates that the active session identity has explicit ownership or privilege over that specific object ID."
    languages: [c]
    severity: ERROR
    metadata:
      cwe: ['CWE-639']

  - id: c-unbounded-resource-allocation-cwe770
    pattern-either:
      # Pattern 1: 直接將不可信的輸入當作長度傳給 malloc/calloc，且前方沒有最大值限制檢查
      - pattern: |
          int $SZ = $REQ.get_int();
          ...
          // ❌ 漏洞：沒有檢查 $SZ 是否大於 MAX_ALLOWED_SIZE，直接配置記憶體
          char *$BUF = (char *)malloc($SZ);
      - pattern: |
          int $COUNT = $REQ.get_int();
          ...
          int *$BUF = calloc($COUNT, $SIZE);

      # Pattern 2: 由外部輸入控制的迴圈計數器，缺乏安全上限限制
      - pattern: |
          int $LIMIT = $REQ.get_int();
          ...
          // ❌ 漏洞：迴圈迭代次數完全由外部控制，可能導致 CPU 耗盡
          for (int $I = 0; $I < $LIMIT; $I++) {
              $FUNC(...);
          }

      # Pattern 3: 使用變長陣列 (VLA) 或 alloca，其大小由外部輸入決定
      - pattern: |
          int $SZ = $REQ.get_int();
          ...
          // ❌ 漏洞：在堆疊上分配不受控的大小，極易觸發 Stack Overflow
          char $ARR[$SZ];
      - pattern: |
          int $SZ = $REQ.get_int();
          ...
          char *$BUF = alloca($SZ);

    message: "Allocation of Resources Without Limits or Throttling (CWE-770): The software allocates a resource based on an unsubstantiated or overly large user input without imposing an upper bound constraint or throttling mechanism. Ensure all size parameters, loop bounds, and buffer allocations derived from untrusted sources are rigorously validated against a safe, maximum threshold before allocation or execution."
    languages: [c]
    severity: ERROR
    metadata:
      cwe: ['CWE-770']

  - id: c-improper-authentication-cwe287
    pattern-either:
      # Pattern 1: 只要在 if 條件中直接使用 strcmp / strncmp 比對外部輸入與憑證，不論變數叫什麼，直接攔截（時序攻擊風險）
      - pattern: |
          if (strcmp($STR1, $STR2) == 0) { ... }
      - pattern: |
          if (strncmp($STR1, $STR2, $LEN) == 0) { ... }

      # Pattern 2: 呼叫了帶有 auth / verify / login 關鍵字的驗證函式，後面卻緊接著執行 grant_access 且中途毫無任何 if 判定
      - pattern: |
          verify_user_password(...);
          grant_access(...);

      # Pattern 3: 使用 memcmp 比對金鑰時，長度參數直接套用了 strlen，這在純 C AST 中是非常鮮明的錯誤特徵
      - pattern: |
          memcmp($K1, $K2, strlen(...))

    message: "Improper Authentication (CWE-287): Flawed authentication implementation detected. Avoid using 'strcmp' for security-sensitive comparisons due to timing attacks. Always check the return value of authentication functions before granting access, and ensure 'memcmp' length is not bounded by 'strlen'."
    languages: [c]
    severity: ERROR
    metadata:
      cwe: ['CWE-287']

  - id: c-improper-privilege-management-cwe269
    pattern-either:
      # Pattern 1: 呼叫了改變特權的系統函式，卻直接當成獨立陳述句，完全沒有用 if 檢查傳回值
      - pattern: |
          setuid($UID);
      - pattern: |
          seteuid($UID);
      - pattern: |
          setgid($GID);

      # Pattern 2: 程式碼中顯式提升特權為 root (0) 後，直接呼叫了敏感檔案操作，但該函式結束前卻完全沒有降權
      - pattern: |
          seteuid(0);
          do_sensitive_file_write(...);

      # Pattern 3: 錯誤的降權順序 — 先呼叫了 setuid 降回普通用戶，後面才呼叫 setgid，此時 setgid 定會失敗
      - pattern: |
          setuid(getuid());
          setgid($GID);

    message: "Improper Privilege Management (CWE-269): Flawed privilege drop or elevation logic detected. Always check the return value of setuid/seteuid/setgid to ensure the privilege operation succeeded. Ensure setgid() is called before setuid() when dropping privileges completely."
    languages: [c]
    severity: ERROR
    metadata:
      cwe: ['CWE-269']

  - id: c-buffer-operation-bounds-cwe119
    pattern-either:
      # Pattern 1: 使用完全不檢查邊界的標準字串操作函式（strcpy / strcat）
      - pattern: |
          strcpy($DEST, $SRC)
      - pattern: |
          strcat($DEST, $SRC)

      # Pattern 2: 使用 memcpy 或 sprintf 進行資料複製與格式化，且缺乏長度限制安全防護
      - pattern: |
          memcpy($DEST, $SRC, $LEN)
      - pattern: |
          sprintf($DEST, "%s", ...)

      # Pattern 3: 指標加法偏移或陣列下標直接指派，且右側緊隨賦值操作（直接的記憶體越界寫入特徵）
      - pattern: |
          *($PTR + $INDEX) = $VALUE;
      - pattern: |
          $ARR[$INDEX] = $VALUE;

    message: "Improper Restriction of Operations within the Bounds of a Memory Buffer (CWE-119): Unsafe buffer manipulation detected. Avoid using 'strcpy', 'strcat', or unsafe 'sprintf'. Always validate lengths before calling 'memcpy' or performing direct pointer/array index indexing to prevent arbitrary memory corruption."
    languages: [c]
    severity: ERROR
    metadata:
      cwe: ['CWE-119']

  - id: c-hardcoded-credentials-cwe798
    pattern-either:
      # Pattern 1: 只要字串內容完全吻合特定寫死的 API 金鑰或密碼值（最經典的字串常數比對）
      - pattern: |
          "AIzaSyA1234567890-B_ExampleKeyString"
      - pattern: |
          "SuperAdminPassword2026!"

      # Pattern 2: 只要呼叫了金鑰初始化函式（不論裡面帶什麼參數、傳入什麼陣列，只要調用此特徵就攔截）
      - pattern: |
          fake_initialize_crypto(...)

      # Pattern 3: 在任意函式呼叫中，直接傳入包含 password= 或 pwd= 的硬編碼字串
      - pattern: |
          $FUNC(..., "...password=...", ...)
      - pattern: |
          $FUNC(..., "...pwd=...", ...)

    message: "Use of Hard-coded Credentials (CWE-798): Hard-coded password, API key, or cryptographic key detected in source code. Store credentials securely in environment variables or external configuration files."
    languages: [c]
    severity: ERROR
    metadata:
      cwe: ['CWE-798']

  - id: c-integer-overflow-cwe190
    pattern-either:
      # Pattern 1: 捕捉直接進行乘法並指派給變數的特徵（常見於未限制的 malloc 大小計算）
      - pattern: |
          $VAR = $COUNT * $SIZE;

      # Pattern 2: 捕捉直接對變數進行 += 累加的特徵（常見於計數器或長度累加）
      - pattern: |
          $VAR += $INPUT;

      # Pattern 3: 捕捉直接在變數上進行加法並賦值的特徵
      - pattern: |
          $VAR = $BASE + $OFFSET;

    message: "Integer Overflow or Wraparound (CWE-190): Unchecked arithmetic operation on integers may lead to wraparound (e.g., positive value becoming negative or zero). Always validate inputs against maximum boundaries (e.g., INT_MAX) before performing arithmetic, especially when the result is used for memory allocation or array indexing."
    languages: [c]
    severity: ERROR
    metadata:
      cwe: ['CWE-190']

  - id: c-uncontrolled-resource-consumption-cwe400
    pattern-either:
      # Pattern 1: 記憶體配置函式（malloc）的參數直接綁定外部整數轉換函數（如 atoi），直接攔截 OOM 風險
      - pattern: |
          malloc(atoi(...));

      # Pattern 2: 迴圈的結束條件直接受控制於任意外部轉換變數，且缺乏上限檢查
      - pattern: |
          for (int $I = 0; $I < atoi(...); $I++) { ... }

      # Pattern 3: 專門鎖定在控制流分支中，開啟檔案後直接返回（return），而完全沒有在該分支閉環內呼叫 fclose 的行為
      - pattern: |
          FILE* $FP = fopen(...);
          ...
          if (...) {
              return $VAL;
          }

    message: "Uncontrolled Resource Consumption (CWE-400): Unbounded resource allocation or loop execution detected. Ensure inputs governing memory allocation size, loop iterations, or file handlers are checked against maximum upper bounds to prevent Denial of Service (DoS)."
    languages: [c]
    severity: ERROR
    metadata:
      cwe: ['CWE-400']

  - id: c-hidden-functionality-cwe912
    pattern-either:
      # --- Pattern 1: Hardcoded magic password backdoor via string comparison ---
      - pattern: strcmp($VAR, "backdoor_secret_pass") == 0
      - pattern: strcmp($VAR, "admin_override_master") == 0
      - pattern: strncmp($VAR, "backdoor_secret_pass", $LEN) == 0
      - pattern: strncmp($VAR, "admin_override_master", $LEN) == 0

      # --- Pattern 2: Undocumented environment variables triggering execution ---
      - pattern: |
          $ENV = getenv("ENABLE_SECRET_BACKDOOR");
          ...
          if ($ENV) {
            ...
          }

      # --- Pattern 3: Hardcoded magic constant value bypass ---
      - pattern: |
          if ($VAR == 0xBAADC0DE) {
            ...
          }

    message: "Hidden Functionality / Backdoor (CWE-912): Hardcoded magic strings, master passwords, or undocumented environment variables can bypass normal authentication mechanisms, creating severe architectural vulnerabilities."
    languages: [c]
    severity: ERROR
    metadata:
      cwe: ['CWE-912']

  - id: c-untrusted-inclusion-cwe829
    pattern-either:
      # --- Pattern 1: Dynamic Library Loading (Windows & POSIX) ---
      - pattern: LoadLibraryA($PATH)
      - pattern: LoadLibraryW($PATH)
      - pattern: LoadLibraryExA($PATH, ...)
      - pattern: LoadLibraryExW($PATH, ...)
      - pattern: dlopen($PATH, ...)

      # --- Pattern 2: Command Execution APIs capable of untrusted binary inclusion ---
      - pattern: system($CMD)
      - pattern: popen($CMD, ...)
      - pattern: winexec($CMD, ...)

      # --- Pattern 3: Windows Process Spawning APIs ---
      - pattern: CreateProcessA($APP, ...)
      - pattern: CreateProcessW($APP, ...)
      - pattern: ShellExecuteA(..., $OP, $FILE, ...)
      - pattern: ShellExecuteW(..., $OP, $FILE, ...)

    message: "Inclusion of Functionality from Untrusted Control Sphere (CWE-829): Loading external binaries, libraries, or scripts from potentially untrusted or unverified paths can lead to Arbitrary Code Execution (ACE) via hijacking or path manipulation."
    languages: [c]
    severity: ERROR
    metadata:
      cwe: ['CWE-829']

  - id: c-attribute-pollution-cwe1321
    pattern-either:
      # --- Pattern 1: Hardcoded dangerous pollution keywords in assignment ---
      - pattern: json_object_set($OBJ, "__proto__", $VAL)
      - pattern: json_object_set($OBJ, "prototype", $VAL)
      - pattern: json_object_set($OBJ, "constructor", $VAL)
      - pattern: dict_set_property($OBJ, "__proto__", $VAL)

      # --- Pattern 2: Multi-level dynamic property access without validation ---
      - pattern: |
          $NODE = dict_get_node($OBJ, $K1);
          dict_set_property($NODE, $K2, $VAL);

      # --- Pattern 3: Unvalidated dynamic user-controlled key injection ---
      - pattern: dict_set_property($OBJ, $USER_KEY, $USER_VAL)
      - pattern: json_object_set($OBJ, $USER_KEY, $USER_VAL)

    message: "Improper Control of Attribute/Property Pollution (CWE-1321): Unvalidated user-controlled keys or sensitive words (like '__proto__', 'constructor') are passed into dynamic object/dictionary property setters. This can lead to internal state tampering or configuration bypass."
    languages: [c]
    severity: ERROR
    metadata:
      cwe: ['CWE-1321']

  - id: c-improper-cert-validation-cwe295
    pattern-either:
      # --- Pattern 1: Libcurl Disabling Verification (0 / FALSE) ---
      - pattern: curl_easy_setopt($CURL, CURLOPT_SSL_VERIFYPEER, 0)
      - pattern: curl_easy_setopt($CURL, CURLOPT_SSL_VERIFYHOST, 0)
      - pattern: curl_easy_setopt($CURL, CURLOPT_SSL_VERIFYPEER, FALSE)
      - pattern: curl_easy_setopt($CURL, CURLOPT_SSL_VERIFYHOST, FALSE)

      # --- Pattern 2: OpenSSL Callback Always Approving Bad Certs ---
      - pattern: |
          int $FUNC(int $OK, X509_STORE_CTX *$CTX) {
            ...
            return 1;
          }

      # --- Pattern 3: GnuTLS Disabling Peer Verification Option ---
      - pattern: gnutls_ssl_set_verify_flags($SESSION, GNUTLS_VERIFY_DISABLE)

    message: "Improper Certificate Validation (CWE-295): Disabling SSL/TLS certificate or hostname verification exposes the application to Man-in-the-Middle (MitM) attacks. Ensure peer certificates are properly verified against a trusted CA bundle."
    languages: [c]
    severity: ERROR
    metadata:
      cwe: ['CWE-295']

  - id: c-weak-hash-cwe328
    pattern-either:
      # --- Pattern 1: Legacy OpenSSL Direct Hash APIs ---
      - pattern: MD5($DATA, $LEN, $MD)
      - pattern: SHA1($DATA, $LEN, $MD)

      # --- Pattern 2: OpenSSL Init Context APIs ---
      - pattern: MD5_Init($CTX)
      - pattern: SHA1_Init($CTX)

      # --- Pattern 3: OpenSSL EVP High-Level Message Digests ---
      - pattern: EVP_md5()
      - pattern: EVP_sha1()

      # --- Pattern 4: Generic/Custom C Handlers or Identifiers ---
      - pattern: $OBJ.init("MD5")
      - pattern: $OBJ.init("SHA1")

    message: "Use of Weak Cryptographic Hash (CWE-328): MD5 or SHA-1 algorithms are mathematically broken and prone to collision attacks. Upgrade to secure alternatives like EVP_sha256() or EVP_sha3_256()."
    languages: [c]
    severity: ERROR
    metadata:
      cwe: ['CWE-328']
"""
# ══════════════════════════════════════════════════════════════
# 6. C# 自訂規則產生
# ══════════════════════════════════════════════════════════════

cs_xss_rules = """\
rules:
  - id: csharp-xss-cross-site-scripting-cwe79
    pattern-either:
      # Pattern 1: 呼叫任何物件的 Raw 方法（例如 Html.Raw 或類似的自訂對象）
      - pattern: $HELPER.Raw($INPUT)

      # Pattern 2: 直接呼叫 WriteAsync 且內部包含字串拼接
      - pattern: $RESP.WriteAsync($X + $INPUT)

      # Pattern 3: 帶有 await 的 WriteAsync 且內部包含字串拼接
      - pattern: await $RESP.WriteAsync($X + $INPUT)

      # Pattern 4: 建立 ContentResult 物件且屬性包含 Content 拼接與 text/html
      - pattern: |
          new ContentResult {
            Content = $X + $INPUT,
            ContentType = "text/html"
          }
      - pattern: |
          new ContentResult {
            ContentType = "text/html",
            Content = $X + $INPUT
          }

    message: "Cross-Site Scripting (XSS) (CWE-79): Untrusted input is rendered directly to the output without proper encoding. Ensure inputs are encoded using HtmlEncoder, or sanitized properly."
    languages: [csharp]
    severity: ERROR
    metadata:
      cwe: ['CWE-79']

  - id: csharp-sqli-sql-injection-cwe89
    pattern-either:
      # Pattern 1: ADO.NET SqlCommand 建立時直接傳入字串拼接或插值
      - pattern: new FakeSqlCommand($X + $INPUT, ...)
      - pattern: new FakeSqlCommand($"...{$INPUT}...", ...)

      # Pattern 2: 任何物件呼叫 Query/Execute 族群方法且內部包含字串拼接或插值
      - pattern: $TARGET.Query($X + $INPUT, ...)
      - pattern: $TARGET.Query($"...{$INPUT}...", ...)
      - pattern: $TARGET.Execute($X + $INPUT, ...)
      - pattern: $TARGET.Execute($"...{$INPUT}...", ...)

      # Pattern 3: Entity Framework 原始 SQL 查詢/執行方法
      - pattern: $TARGET.FromSqlRaw($X + $INPUT, ...)
      - pattern: $TARGET.FromSqlRaw($"...{$INPUT}...", ...)
      - pattern: $TARGET.ExecuteSqlRaw($X + $INPUT, ...)
      - pattern: $TARGET.ExecuteSqlRaw($"...{$INPUT}...", ...)

    message: "SQL Injection (SQLi) (CWE-89): Input is concatenated directly into a SQL query string. Use parameterized queries or ORM parameters to safeguard database operations."
    languages: [csharp]
    severity: ERROR
    metadata:
      cwe: ['CWE-89']

  - id: csharp-csrf-cross-site-request-forgery-cwe352
    patterns:
      # 1. 抓取所有帶有任何屬性修飾的方法
      - pattern: |
          [$ATTR]
          public $TYPE $METHOD(...) { ... }
      
      # 2. 限定這個屬性必須是變更資料的動詞 (HttpPost, HttpDelete, HttpPut 或 IgnoreAntiforgeryToken)
      - metavariable-regex:
          metavariable: $ATTR
          regex: (?i)(HttpPost|HttpDelete|HttpPut|IgnoreAntiforgeryToken)

      # 3. 強制排除：如果屬性裡面已經包含了安全防護標籤，則判定為安全
      - pattern-not: |
          [ValidateAntiForgeryToken]
          public $TYPE $METHOD(...) { ... }
      - pattern-not: |
          [$ANY, ValidateAntiForgeryToken]
          public $TYPE $METHOD(...) { ... }
      - pattern-not: |
          [ValidateAntiForgeryToken, $ANY]
          public $TYPE $METHOD(...) { ... }

    message: "Cross-Site Request Forgery (CSRF) (CWE-352): A method that modifies data (POST/PUT/DELETE) is missing Anti-Forgery Token validation. Apply [ValidateAntiForgeryToken] or [AutoValidateAntiforgeryToken] globally."
    languages: [csharp]
    severity: ERROR
    metadata:
      cwe: ['CWE-352']

  - id: csharp-auth-missing-authorization-cwe862
    patterns:
      # 1. 抓取所有帶有路由屬性或匿名屬性的方法
      - pattern-either:
          - pattern: |
              [$ATTR]
              public $TYPE $METHOD(...) { ... }
          - pattern: |
              [AllowAnonymous]
              public $TYPE $METHOD(...) { ... }
      
      # 2. 限定必須是常見的 Web API / MVC 路由進入點
      - metavariable-regex:
          metavariable: $ATTR
          regex: (?i)(HttpGet|HttpPost|HttpPut|HttpDelete|Route)

      # 3. 終極排除：列舉所有可能出現在方法上方的 Authorize 組合（包含帶參數與不帶參數）
      - pattern-not: |
          [Authorize]
          public $TYPE $METHOD(...) { ... }
      - pattern-not: |
          [Authorize(...)]
          public $TYPE $METHOD(...) { ... }
      - pattern-not: |
          [Authorize] [$ANY]
          public $TYPE $METHOD(...) { ... }
      - pattern-not: |
          [Authorize(...)] [$ANY]
          public $TYPE $METHOD(...) { ... }
      - pattern-not: |
          [$ANY, Authorize]
          public $TYPE $METHOD(...) { ... }
      - pattern-not: |
          [$ANY, Authorize(...)]
          public $TYPE $METHOD(...) { ... }

    message: "Missing Authorization (CWE-862): This HTTP endpoint lacks an [Authorize] attribute. Ensure appropriate role-based or policy-based authorization is enforced."
    languages: [csharp]
    severity: ERROR
    metadata:
      cwe: ['CWE-862']

  - id: csharp-buffer-overflow-out-of-bounds-write-cwe787
    pattern-either:
      # Pattern 1: 在 unsafe 區塊中，直接對指標進行未經驗證的陣列下標或加法偏移寫入
      - pattern: |
          *($PTR + $INDEX) = $VALUE;
      - pattern: |
          $PTR[$INDEX] = $VALUE;

      # Pattern 2: 使用 Marshal.Copy 寫入 Unmanaged 緩衝區時，長度或偏移量直接使用外部傳入的變數
      - pattern: |
          FakeMarshal.Copy($SRC, $SRC_IDX, $DEST, $LENGTH);

      # Pattern 3: 使用 stackalloc 建立固定大小緩衝區，卻用未經邊界檢查的變數寫入
      - pattern: |
          int* $BUF = stackalloc int[$SIZE];
          ...
          $BUF[$INDEX] = $VALUE;

    message: "Out-of-bounds Write (CWE-787): Unsafe pointer manipulation or unmanaged memory copy detected without explicit bounds checking. This can lead to memory corruption or buffer overflows."
    languages: [csharp]
    severity: ERROR
    metadata:
      cwe: ['CWE-787']

  - id: csharp-path-traversal-cwe22
    pattern-either:
      # Pattern 1: 呼叫 FakeFile 的讀寫方法時直接使用字串拼接或插值
      - pattern: FakeFile.ReadAllText($X + $INPUT, ...)
      - pattern: FakeFile.ReadAllText($"...{$INPUT}...", ...)
      - pattern: FakeFile.WriteAllText($X + $INPUT, ...)
      - pattern: FakeFile.WriteAllText($"...{$INPUT}...", ...)

      # Pattern 2: 建立 FakeFileStream 時直接傳入拼接或插值路徑
      - pattern: new FakeFileStream($X + $INPUT, ...)
      - pattern: new FakeFileStream($"...{$INPUT}...", ...)

      # Pattern 3: 呼叫結合路徑的方法時誤用拼接
      - pattern: FakePath.Combine($X, $Y + $INPUT, ...)
      - pattern: FakePath.Combine($X, $"...{$INPUT}...", ...)

    message: "Path Traversal (CWE-22): Input is directly concatenated into a file path. An attacker could use '../' to access sensitive files outside the intended directory."
    languages: [csharp]
    severity: ERROR
    metadata:
      cwe: ['CWE-22']

  - id: csharp-memory-use-after-free-cwe416
    pattern-either:
      # Pattern 1: 使用 FakeMarshal 釋放指標後，又直接對該指標解引用（Dereference）或下標寫入值
      - pattern: |
          FakeMarshal.FreeHGlobal($PTR);
          ...
          *($PTR + $INDEX) = $VALUE;
      - pattern: |
          FakeMarshal.FreeHGlobal($PTR);
          ...
          $PTR[$INDEX] = $VALUE;

      # Pattern 2: 使用 FakeMarshal 釋放指標後，又將該指標傳入其他方法使用
      - pattern: |
          FakeMarshal.FreeHGlobal($PTR);
          ...
          $FUNC(..., $PTR, ...);

      # Pattern 3: 控制代碼（Handle）被顯式釋放或關閉後，又嘗試調用其內部的資源方法
      - pattern: |
          $HANDLE.Dispose();
          ...
          $HANDLE.$METHOD(...);

    message: "Use After Free (CWE-416): Attempted to access or modify a pointer/resource after it has been freed or disposed. This can lead to memory corruption, crashes, or arbitrary code execution."
    languages: [csharp]
    severity: ERROR
    metadata:
      cwe: ['CWE-416']

  - id: csharp-buffer-overflow-out-of-bounds-read-cwe125
    pattern-either:
      # Pattern 1: 在 unsafe 區塊中，直接透過指標進行未經驗證的加法偏移讀取或下標讀取
      - pattern: |
          $VAR = *($PTR + $INDEX);
      - pattern: |
          $VAR = $PTR[$INDEX];
      - pattern: |
          return *($PTR + $INDEX);
      - pattern: |
          return $PTR[$INDEX];

      # Pattern 2: 使用 Marshal.Copy 將 Unmanaged 記憶體讀出至陣列時，長度直接使用外部輸入
      - pattern: |
          FakeMarshal.Copy($SRC, $DEST, $DEST_IDX, $LENGTH);

      # Pattern 3: 在指標循環（如迴圈）中，終止條件使用了未經核對的邊界變數
      - pattern: |
          for (...; $START < $LIMIT; ...) {
              ...
              $VAR = $PTR[$START];
              ...
          }

    message: "Out-of-bounds Read (CWE-125): Unsafe pointer access or unmanaged memory copy detected without proper bounds verification. This can lead to information disclosure or application crashes."
    languages: [csharp]
    severity: ERROR
    metadata:
      cwe: ['CWE-125']

  - id: csharp-os-command-injection-cwe78
    pattern-either:
      # Pattern 1: 呼叫 FakeProcess.Start 時，直接拼接指令或參數
      - pattern: FakeProcess.Start($CMD, $ARGS + $INPUT)
      - pattern: FakeProcess.Start($CMD, $"...{$INPUT}...")
      - pattern: FakeProcess.Start($INPUT + $ARGS)
      - pattern: FakeProcess.Start($"...{$INPUT}...")

      # Pattern 2: 設定 FakeProcessStartInfo 屬性時，對 FileName 或 Arguments 進行字串拼接/插值
      - pattern: |
          $INFO.FileName = $INPUT + $X;
      - pattern: |
          $INFO.FileName = $"...{$INPUT}...";
      - pattern: |
          $INFO.Arguments = $X + $INPUT;
      - pattern: |
          $INFO.Arguments = $"...{$INPUT}...";

    message: "OS Command Injection (CWE-78): Unsanitized user input is used to construct OS commands. An attacker can inject malicious commands executed with the application's privileges."
    languages: [csharp]
    severity: ERROR
    metadata:
      cwe: ['CWE-78']

  - id: csharp-code-injection-cwe94
    pattern-either:
      # Pattern 1: 使用 CSharpScript 動態評估包含字串拼接或插值的程式碼字串
      - pattern: FakeCSharpScript.EvaluateAsync($CODE + $INPUT, ...)
      - pattern: FakeCSharpScript.EvaluateAsync($"...{$INPUT}...", ...)

      # Pattern 2: 呼叫腳本引擎（如 CSScript）直接載入或編譯拼接後的動態程式碼
      - pattern: $ENGINE.CompileCode($X + $INPUT, ...)
      - pattern: $ENGINE.CompileCode($"...{$INPUT}...", ...)

      # Pattern 3: 動態 LINQ 擴充方法或運算式解析器直接傳入未參數化的拼接字串
      - pattern: $QUERY.Where($X + $INPUT, ...)
      - pattern: $QUERY.Where($"...{$INPUT}...", ...)

    message: "Code Injection (CWE-94): Unsanitized input is used to construct or compile dynamic code/expressions. This can allow attackers to execute arbitrary code within the application context."
    languages: [csharp]
    severity: ERROR
    metadata:
      cwe: ['CWE-94']

  - id: csharp-buffer-overflow-unbounded-copy-cwe120
    pattern-either:
      # Pattern 1: P/Invoke 宣告或直接呼叫不安全的原生 C 函式（如 strcpy）進行複製
      - pattern: FakeNativeMethods.strcpy($DEST, $SRC)
      - pattern: FakeNativeMethods.sprintf($DEST, $FORMAT, ...)

      # Pattern 2: 在 unsafe 區塊中，利用迴圈將一個指標內容複製到另一個指標，但終止條件未限制在目的端的大小內
      - pattern: |
          while (*$SRC != $TERM) {
              *$DEST = *$SRC;
              $DEST++;
              $SRC++;
          }

      # Pattern 3: 使用 FakeMarshal.Copy 或類似 API 將陣列複製到 Unmanaged 記憶體，長度直接使用來源陣列長度，卻未檢查目的端緩衝區大小
      - pattern: |
          FakeMarshal.Copy($SRC, $SRC_IDX, $DEST, $SRC.Length);

    message: "Buffer Copy without Checking Size of Input (CWE-120): Copying data to a buffer without validating the input size can overwrite adjacent memory, leading to crashes or arbitrary code execution."
    languages: [csharp]
    severity: ERROR
    metadata:
      cwe: ['CWE-120']

  - id: csharp-file-upload-unrestricted-dangerous-type-cwe434
    pattern-either:
      # Pattern 1: 僅依賴 IFormFile.ContentType 來做安全檢查 (Content-Type 極易被客戶端偽造)
      - pattern: |
          if ($FILE.ContentType == $X) {
              ...
          }
      - pattern: |
          if ($FILE.ContentType.Equals(...)) {
              ...
          }

      # Pattern 2: 儲存檔案時，直接拼接外部傳入的原始檔名 (FILE.FileName)，且中途未呼叫任何副檔名安全檢查
      - pattern: |
          string $PATH = FakePath.Combine($DIR, $FILE.FileName);
          ...
          $FILE.CopyToAsync(...);

      # Pattern 3: 直接將不安全的 IFormFile 原始檔名寫入硬碟或目標流
      - pattern: |
          using (var $STREAM = new FakeFileStream(..., $FILE.FileName, ...)) {
              ...
          }

    message: "Unrestricted Upload of File with Dangerous Type (CWE-434): The application performs dangerous file upload operations without strictly validating file extensions or content magic numbers on the server side. Do not trust Content-Type or original FileName directly."
    languages: [csharp]
    severity: ERROR
    metadata:
      cwe: ['CWE-434']

  - id: csharp-null-pointer-dereference-cwe476
    pattern-either:
      # Pattern 1: 使用 C# 的 "as" 關鍵字進行轉型（失敗時會回傳 null），卻沒有進行 null 檢查就直接存取成員
      - pattern: |
          var $VAR = $OBJ as $TYPE;
          ...
          $VAR.$MEMBER(...);
      - pattern: |
          var $VAR = $OBJ as $TYPE;
          ...
          $VAR.$PROPERTY;

      # Pattern 2: 呼叫了明確告知可能回傳 null 的 LINQ 方法（如 FirstOrDefault），隨後未經檢查直接解引用
      - pattern: |
          var $VAR = $LIST.FirstOrDefault(...);
          ...
          $VAR.$MEMBER(...);
      - pattern: |
          var $VAR = $LIST.FirstOrDefault(...);
          ...
          $VAR.$PROPERTY;

      # Pattern 3: 程式碼內部自己寫了 `if ($VAR == null)` 的邏輯，卻在 null 的條件分支內（或完全沒 return 的外部）直接讀取它
      - pattern: |
          if ($VAR == null) {
              ...
              $VAR.$MEMBER(...);
          }

    message: "Null Pointer Dereference (CWE-476): The object is dereferenced without a prior null check after an operation that can result in a null value (such as 'as' casting, FirstOrDefault, or an explicit null comparison). This will throw a NullReferenceException and may cause a Denial of Service (DoS)."
    languages: [csharp]
    severity: ERROR
    metadata:
      cwe: ['CWE-476']

  - id: csharp-buffer-overflow-stack-based-cwe121
    pattern-either:
      # Pattern 1: 使用 stackalloc 分配固定大小的堆疊空間，隨後卻使用未經檢查的 index 進行指標寫入
      - pattern: |
          $TYPE* $BUF = stackalloc $TYPE[$SIZE];
          ...
          *($BUF + $INDEX) = $VALUE;
      - pattern: |
          $TYPE* $BUF = stackalloc $TYPE[$SIZE];
          ...
          $BUF[$INDEX] = $VALUE;

      # Pattern 2: 在 stackalloc 分配的空間中進行指標逐位元寫入（如 while 迴圈），但其終止條件未與緩衝區大小掛鉤
      - pattern: |
          byte* $DEST = stackalloc byte[$SIZE];
          ...
          while (*$SRC != $TERM) {
              *$DEST = *$SRC;
              $DEST++;
              $SRC++;
          }

      # Pattern 3: 直接使用未經校驗或外部傳入的變數作為 stackalloc 的大小限制，可能導致堆疊耗盡或邊界計算溢位
      - pattern: |
          $TYPE* $BUF = stackalloc $TYPE[$USER_INPUT];

    message: "Stack-based Buffer Overflow (CWE-121): Unsafe stackalloc buffer manipulation detected. Writing beyond stack-allocated memory boundaries or allocating unbounded stack size can lead to stack corruption, unexpected crashes, or remote code execution."
    languages: [csharp]
    severity: ERROR
    metadata:
      cwe: ['CWE-121']

  - id: csharp-deserialization-untrusted-data-cwe502
    pattern-either:
      # Pattern 1: Newtonsoft.Json (Json.NET) 設定了 TypeNameHandling 且大於 None（此配置允許 JSON 中攜帶型別資訊，極度危險）
      - pattern: |
          $SETTINGS.TypeNameHandling = FakeTypeNameHandling.$ALL;
          ...
          FakeJsonConvert.DeserializeObject(..., $SETTINGS);
      - pattern: |
          $SETTINGS.TypeNameHandling = FakeTypeNameHandling.$ALL;
          ...
          FakeJsonConvert.DeserializeObject<$TYPE>(..., $SETTINGS);

      # Pattern 2: 使用已被官方強烈警告、本質上完全不安全的 BinaryFormatter 進行不安全的反序列化
      - pattern: |
          FakeBinaryFormatter $BF = new FakeBinaryFormatter(...);
          ...
          $BF.Deserialize(...);

      # Pattern 3: 使用自帶型別宣告載入的 NetDataContractSerializer 處理惡意資料流
      - pattern: |
          FakeNetDataContractSerializer $NDCS = new FakeNetDataContractSerializer(...);
          ...
          $NDCS.ReadObject(...);

    message: "Deserialization of Untrusted Data (CWE-502): Insecure deserialization configurations or tools (such as BinaryFormatter, NetDataContractSerializer, or Newtonsoft.Json with TypeNameHandling enabled) can allow attackers to execute arbitrary code. Ensure strict type validation or safer formatters like System.Text.Json are used."
    languages: [csharp]
    severity: ERROR
    metadata:
      cwe: ['CWE-502']

  - id: csharp-buffer-overflow-heap-based-cwe122
    pattern-either:
      # Pattern 1: 在 Unmanaged Heap 配置空間後，直接對指標進行加法偏移寫入或下標寫入，且缺乏邊界檢查
      - pattern: |
          IntPtr $HGLOBAL = FakeMarshal.AllocHGlobal($SIZE);
          ...
          *($PTR + $INDEX) = $VALUE;
      - pattern: |
          IntPtr $HGLOBAL = FakeMarshal.AllocHGlobal($SIZE);
          ...
          $PTR[$INDEX] = $VALUE;

      # Pattern 2: 在 Heap 記憶體區塊中進行指標逐位寫入（如 while 迴圈），但其終止條件並未與 Heap 配置的大小掛鉤
      - pattern: |
          IntPtr $HGLOBAL = FakeMarshal.AllocHGlobal($SIZE);
          ...
          while (*$SRC != $TERM) {
              *$DEST = *$SRC;
              $DEST++;
              $SRC++;
          }

      # Pattern 3: 使用 Marshal.Copy 將資料寫入 Heap 指標時，長度直接塞來源陣列的 Length，而完全沒有校驗 Heap 實際分配的大小
      - pattern: |
          IntPtr $HGLOBAL = FakeMarshal.AllocHGlobal($SIZE);
          ...
          FakeMarshal.Copy($SRC, $SRC_IDX, $HGLOBAL, $SRC.Length);

    message: "Heap-based Buffer Overflow (CWE-122): Unsafe Heap allocation or pointer manipulation detected without explicit bounds validation. Overwriting heap memory can lead to data corruption, heap layout manipulation, or arbitrary code execution."
    languages: [csharp]
    severity: ERROR
    metadata:
      cwe: ['CWE-122']

  - id: csharp-auth-incorrect-authorization-cwe863
    pattern-either:
      # Pattern 1: 同一方法上同時存在 [Authorize] 與 [AllowAnonymous]，導致授權檢查被直接忽略
      - pattern: |
          [Authorize, AllowAnonymous]
          public $TYPE $METHOD(...) { ... }
      - pattern: |
          [AllowAnonymous, Authorize]
          public $TYPE $METHOD(...) { ... }
      - pattern: |
          [Authorize(...), AllowAnonymous]
          public $TYPE $METHOD(...) { ... }

      # Pattern 2: 在同一個自訂 Controller 類別中，方法層級宣告 [AllowAnonymous] 卻試圖保護敏感路由
      - pattern: |
          [AllowAnonymous]
          [HttpPost($ROUTE)]
          public $TYPE $METHOD(...) { ... }

      # Pattern 3: 自訂授權檢查中，使用了硬編碼的敏感字串（如 "Admin"）進行不安全的基礎字串比對，容易引發邏輯不對稱
      - pattern: |
          if ($USER.Identity.Name == "Admin") {
              ...
          }

    message: "Incorrect Authorization (CWE-863): An incorrect authorization configuration or logical conflict (such as combining [Authorize] and [AllowAnonymous], or using hardcoded username checks) can bypass intended security access controls."
    languages: [csharp]
    severity: ERROR
    metadata:
      cwe: ['CWE-863']

  - id: csharp-improper-input-validation-cwe20
    pattern-either:
      # Pattern 1: 外部數值輸入直接做為動態資源配置或陣列初始化的長度，且中途沒有任何 if 範圍校驗
      - pattern: |
          public $TYPE $METHOD(..., int $INPUT, ...) {
              ...
              var $BUF = new $SUBTYPE[$INPUT];
              ...
          }

      # Pattern 2: 開放式重新導向 (Open Redirection) — 直接將外部傳入的網址字串帶入 Redirect 方法，缺乏本地網域或白名單驗證
      - pattern: |
          public $TYPE $METHOD(..., string $URL, ...) {
              ...
              return FakeRedirect($URL);
          }

      # Pattern 3: 反射（Reflection）或動態物件建立時，直接依賴外部傳入的型別名稱字串，未經過白名單過濾
      - pattern: |
          public $TYPE $METHOD(..., string $TYPENAME, ...) {
              ...
              Type.GetType($TYPENAME);
              ...
          }

    message: "Improper Input Validation (CWE-20): The application receives input from an untrusted source without fully validating its format, length, range, or destination. This can lead to resource exhaustion, Open Redirection, or unauthorized reflection execution."
    languages: [csharp]
    severity: ERROR
    metadata:
      cwe: ['CWE-20']

  - id: csharp-improper-access-control-cwe284
    pattern-either:
      # Pattern 1: 命名包含 Admin/Secure 且繼承自 ControllerBase 的類別，卻完全沒有宣告 [Authorize] 特徵屬性
      - pattern: |
          class $ADMINCONTROLLER : FakeControllerBase {
              ...
              public $TYPE $METHOD(...) { ... }
          }

      # Pattern 2: 在類別中將敏感的加密、憑證、金鑰或金流變數配置為 public static，允許整個應用程式的任何元件任意串改
      - pattern: |
          public static string $SECRET_KEY = ...;
      - pattern: |
          public static byte[] $CRYPTO_KEY = ...;

      # Pattern 3: 在公開對外暴露的服務合約（ServiceContract）中，方法層級完全沒有設定任何安全限制
      - pattern: |
          [FakeServiceContract]
          public interface $SERVICE {
              [FakeOperationContract]
              $TYPE $METHOD(...);
          }

    message: "Improper Access Control (CWE-284): The application fails to properly restrict access to sensitive controllers, data fields, or service contracts. Ensure [Authorize] filters are applied or restrict variable visibility with narrower access modifiers (e.g., internal/private)."
    languages: [csharp]
    severity: ERROR
    metadata:
      cwe: ['CWE-284']

  - id: csharp-information-exposure-cwe200
    pattern-either:
      # Pattern 1: 在 catch 區塊中，直接將異常物件的 ToString()、Message 或 StackTrace 當作回應回傳給客戶端
      - pattern: |
          catch (Exception $EX) {
              ...
              return FakeBadRequest($EX.ToString());
          }
      - pattern: |
          catch (Exception $EX) {
              ...
              return FakeBadRequest($EX.StackTrace);
          }

      # Pattern 2: 在日誌或回應中，直接串接或讀取含有 ConnectionString、Password、Secret 等敏感關鍵字的組態欄位
      - pattern: |
          FakeLogger.Log($X + $CONFIG.ConnectionString);
      - pattern: |
          FakeLogger.Log($"...{$CONFIG.ConnectionString}...");

      # Pattern 3: 直接將含有敏感字串的內部環境變數或組態物件序列化並輸出
      - pattern: |
          return FakeJson($CONFIG.GetSection("ConnectionStrings"));

    message: "Exposure of Sensitive Information (CWE-200): Explict leak of internal exceptions (such as StackTrace) or infrastructure secrets (such as ConnectionStrings) detected. This can expose system architecture to attackers, facilitating further exploitation."
    languages: [csharp]
    severity: ERROR
    metadata:
      cwe: ['CWE-200']

  - id: csharp-auth-missing-authentication-cwe306
    pattern-either:
      # Pattern 1: 帶有 [FakeHttpPost(...)] 卻「沒有」[Authorize] 的裸奔敏感方法
      - pattern: |
          [FakeHttpPost($ROUTE)]
          public $TYPE $METHOD(...) { ... }

      # Pattern 2: 帶有 [AllowAnonymous] 且內部呼叫了敏感交易或核心操作的方法
      - pattern: |
          [AllowAnonymous]
          [FakeHttpPost($ROUTE)]
          public $TYPE $METHOD(...)
          {
              ...
              $SERVICE.TransferFunds(...);
              ...
          }
      - pattern: |
          [AllowAnonymous]
          [FakeHttpPost($ROUTE)]
          public $TYPE $METHOD(...)
          {
              ...
              $SERVICE.ExecuteCriticalAction(...);
              ...
          }

    message: "Missing Authentication for Critical Function (CWE-306): A critical function or sensitive endpoint is missing appropriate [Authorize] protection, or is explicitly open via [AllowAnonymous]. This allows unauthenticated users to execute administrative or business-critical operations."
    languages: [csharp]
    severity: ERROR
    metadata:
      cwe: ['CWE-306']

  - id: csharp-ssrf-httpclient-cwe918
    pattern-either:
      # Pattern 1: 直接在 HttpClient 方法（如 GetAsync / GetStringAsync）中進行字串拼接或插值
      - pattern: $CLIENT.GetAsync($X + $INPUT, ...)
      - pattern: $CLIENT.GetAsync($"...{$INPUT}...", ...)
      - pattern: $CLIENT.GetStringAsync($X + $INPUT, ...)
      - pattern: $CLIENT.GetStringAsync($"...{$INPUT}...", ...)

      # Pattern 2: 在建構 Uri 物件時進行字串拼接或插值（這通常是發送請求的前置步驟）
      - pattern: new Uri($X + $INPUT, ...)
      - pattern: new Uri($"...{$INPUT}...", ...)

      # Pattern 3: 使用傳統的 WebRequest.Create 進行字串拼接或插值
      - pattern: FakeWebRequest.Create($X + $INPUT, ...)
      - pattern: FakeWebRequest.Create($"...{$INPUT}...", ...)

    message: "Server-Side Request Forgery (CWE-918): Unsanitized user input is used to construct a target URL for server-side network requests. An attacker can manipulate this input to scan internal networks, access private services, or exploit metadata APIs."
    languages: [csharp]
    severity: ERROR
    metadata:
      cwe: ['CWE-918']

  - id: csharp-command-injection-cwe77
    pattern-either:
      # Pattern 1: 直接在 Process.Start 靜態方法中拼接或插值執行參數
      - pattern: FakeProcess.Start($CMD, $X + $INPUT, ...)
      - pattern: FakeProcess.Start($CMD, $"...{$INPUT}...", ...)

      # Pattern 2: 透過 ProcessStartInfo 屬性指派時，將拼接字串餵給 Arguments
      - pattern: |
          $INFO.Arguments = $X + $INPUT;
      - pattern: |
          $INFO.Arguments = $"...{$INPUT}...";

      # Pattern 3: 直接將拼接後的惡意字串當作 FileName（可能直接執行被包裝的惡意 shell 指令）
      - pattern: |
          $INFO.FileName = $X + $INPUT;
      - pattern: |
          $INFO.FileName = $"...{$INPUT}...";

    message: "Command Injection (CWE-77): Unsanitized user input is used to construct system commands or arguments. Attackers can inject command separators (e.g., ';', '&&', '|') to execute arbitrary shell commands on the server."
    languages: [csharp]
    severity: ERROR
    metadata:
      cwe: ['CWE-77']

  - id: csharp-idor-authorization-bypass-cwe639
    pattern-either:
      # Pattern 1: 方法直接接收外部輸入的 id 參數，隨後直接調用 Repository 獲取物件並回傳，中途完全沒有比對當前登入者身分
      - pattern: |
          public $TYPE $METHOD(..., int $ID, ...) {
              ...
              var $RES = $REPO.GetById($ID);
              ...
              return FakeOk($RES);
          }

      # Pattern 2: 在更新或刪除操作中，直接使用前端傳來的物件屬性（如 accountId）進行持久化，而未校驗目前連線使用者的擁有權
      - pattern: |
          public $TYPE $METHOD(..., FakeOrder $ORDER, ...) {
              ...
              $REPO.Update($ORDER);
              ...
          }

      # Pattern 3: 自訂 SQL 查詢中，直接將前端傳入的參數作為單一過濾條件，完全缺乏多租戶或身分關係隔離 (例如 And UserId = CurrentUser)
      - pattern: |
          string $QUERY = FakeString.Format("SELECT * FROM Orders WHERE Id = {0}", $INPUT);

    message: "Authorization Bypass Through User-Controlled Key (CWE-639 / IDOR): The application direct accesses resources based on user-supplied keys without cross-checking if the current authenticated user owns that resource. Ensure you add an ownership check (e.g., query by both resource ID and current user ID)."
    languages: [csharp]
    severity: ERROR
    metadata:
      cwe: ['CWE-639']

  - id: csharp-resource-limit-allocation-cwe770
    pattern-either:
      # Pattern 1: 直接使用外部傳入的 size 變數初始化陣列，沒有任何小於最大上限的檢查
      - pattern: |
          public $TYPE $METHOD(..., int $SIZE, ...) {
              ...
              var $ARR = new $T[$SIZE];
              ...
          }

      # Pattern 2: 在 Task.Delay 或 Thread.Sleep 中直接傳入外部可控的毫秒數，可能導致執行緒被無限期鎖定
      - pattern: |
          FakeTask.Delay($MS);

      # Pattern 3: 直接以外部傳入的變數作為迴圈的終止條件，進行高耗能操作（如密碼 Hash、讀取等）且中途無上限檢查
      - pattern: |
          public $TYPE $METHOD(..., int $COUNT, ...) {
              ...
              for (int $I = 0; $I < $COUNT; $I++) {
                  ...
                  $FX.ExpensiveOperation(...);
                  ...
              }
              ...
          }

    message: "Allocation of Resources Without Limits or Throttling (CWE-770): User-controlled input is used directly to determine the amount of resources (memory allocation, execution loops, or delay timers) to allocate. This can easily lead to Denial of Service (DoS) via resource exhaustion."
    languages: [csharp]
    severity: ERROR
    metadata:
      cwe: ['CWE-770']

  - id: csharp-improper-authentication-cwe287
    pattern-either:
      # Pattern 1: 弱點登入流向 — 撈出使用者後，直接核發 Token 且方法體內完全沒有比對密碼
      - pattern: |
          public $TYPE $METHOD(..., string $USER, string $PASS, ...)
          {
              var $U = $REPO.FindUser($USER);
              return FakeOk($AUTH.IssueToken($U));
          }

      # Pattern 2: 直接讀取完全可被偽造的 HTTP Header 字串來進行身分識別與登入
      - pattern: |
          string $UID = $REQ.GetHeaderValue("X-User-ID");
          ...
          FakeSignIn($UID);

      # Pattern 3: JWT 驗證安全參數配置錯誤，將關鍵的 ValidateIssuerSigningKey 設為 false
      - pattern: |
          $PARAMS.ValidateIssuerSigningKey = false;

    message: "Improper Authentication (CWE-287): The application implements a flawed authentication mechanism, such as omitting password validation before token issuance, relying on untrusted HTTP headers for identity, or disabling JWT signing key validation."
    languages: [csharp]
    severity: ERROR
    metadata:
      cwe: ['CWE-287']

  - id: csharp-improper-privilege-management-cwe269
    pattern-either:
      # Pattern 1: 呼叫 Impersonate() 提升權限，直接將其指派給獨立變數（未依賴安全自動釋放的 using 關鍵字結構）
      - pattern: |
          var $CTX = $ID.Impersonate();
      - pattern: |
          FakeWindowsImpersonationContext $CTX = $ID.Impersonate();

      # Pattern 2: 角色動態變更 — 直接讀取前端傳入的權限字串（如 newRole），無條件加入使用者權限庫中
      - pattern: |
          public $TYPE $METHOD(..., string $NEWROLE, ...)
          {
              ...
              $USER.AddRole($NEWROLE);
              ...
          }

      # Pattern 3: 直接對執行緒的安全主體進行強行覆寫（不論右側建構子帶有何種參數組合）
      - pattern: |
          FakeThread.CurrentPrincipal = new FakeGenericPrincipal(...);

    message: "Improper Privilege Management (CWE-269): The application improperly manages privileges, such as failing to revoke impersonated tokens, dynamically allowing untrusted actors to self-assign high-privileged roles, or forced global thread principal elevation. This can lead to horizontal or vertical privilege escalation."
    languages: [csharp]
    severity: ERROR
    metadata:
      cwe: ['CWE-269']

  - id: csharp-buffer-operation-bounds-cwe119
    pattern-either:
      # Pattern 1: 在 unsafe 區塊中，直接對指標進行未經保護的加法偏移或索引寫入
      - pattern: |
          $TYPE* $PTR = ...;
          ...
          *($PTR + $INDEX) = $VALUE;
      - pattern: |
          $TYPE* $PTR = ...;
          ...
          $PTR[$INDEX] = $VALUE;

      # Pattern 2: 使用不安全的 System.Runtime.CompilerServices.Unsafe 工具強轉指標或結構，繞過邊界檢查
      - pattern: |
          FakeUnsafe.AsRef<$TYPE>($PTR);
      - pattern: |
          FakeMemoryMarshal.Cast<$T1, $T2>($SPAN);

      # Pattern 3: 使用 Marshal.Copy 將陣列寫入原生緩衝區時，直接使用變數長度，缺乏邊界比對
      - pattern: |
          FakeMarshal.Copy($SRC, $SRC_IDX, $DEST_PTR, $LEN);

    message: "Improper Restriction of Operations within the Bounds of a Memory Buffer (CWE-119): Unsafe pointer operations, unchecked Marshal.Copy lengths, or dangerous Span type casting detected. These operations bypass CLR managed safety and can corrupt memory or cause application crashes."
    languages: [csharp]
    severity: ERROR
    metadata:
      cwe: ['CWE-119']

  - id: csharp-hardcoded-credentials-cwe798
    pattern-either:
      # Pattern 1: 直接鎖定包含 Password= 的硬編碼字串賦值（這是最經典且最不可動搖的字串比對）
      - pattern: |
          string $VAR = "...Password=...";

      # Pattern 2: 捕獲程式碼中直接將明確的 API 密鑰字串賦值給任意變數
      - pattern: |
          string $VAR = "AIzaSyA1234567890-B_ExampleKeyString";
      - pattern: |
          string $VAR = "SuperSecurePassword123!";

      # Pattern 3: 最底層的物件建構特徵，不論裡面帶什麼參數，只要呼叫該安全金鑰類別就直接攔截
      - pattern: |
          new FakeSymmetricSecurityKey(...)

    message: "Use of Hard-coded Credentials (CWE-798): Hard-coded credentials, connection strings, or cryptographic keys detected. Store credentials securely in appsettings.json or Environment Variables."
    languages: [csharp]
    severity: ERROR
    metadata:
      cwe: ['CWE-798']

  - id: csharp-integer-overflow-cwe190
    pattern-either:
      # Pattern 1: 捕捉直接進行整數乘法並指派給變數的特徵（常見於未限制的緩衝區大小計算）
      - pattern: |
          $VAR = $COUNT * $SIZE;

      # Pattern 2: 捕捉直接對變數進行累加的特徵（常見於未校驗的計數器或金額累加）
      - pattern: |
          $VAR += $INPUT;

      # Pattern 3: 基礎的數學函式（如 Math.Abs）在處理特定極端值（如 int.MinValue）時會因為溢位維持負數
      - pattern: |
          FakeMath.Abs(...)

    message: "Integer Overflow or Wraparound (CWE-190): Unchecked arithmetic operation on integers may lead to wraparound. Ensure inputs are validated against maximum boundaries (e.g., int.MaxValue) or use checked blocks to catch OverflowException."
    languages: [csharp]
    severity: ERROR
    metadata:
      cwe: ['CWE-190']

  - id: csharp-uncontrolled-resource-consumption-cwe400
    pattern-either:
      # Pattern 1: 建立 Regex 物件時只傳入 pattern，沒有傳入第三個參數 MatchTimeout，極易遭受 ReDoS 攻擊
      - pattern: |
          new FakeRegex($PATT)
      - pattern: |
          new FakeRegex($PATT, $OPTS)

      # Pattern 2: 檔案或資料流操作中，未經大小檢查直接調用全載入方法（如 ReadAllBytes）
      - pattern: |
          FakeFile.ReadAllBytes($PATH)
      - pattern: |
          FakeFile.ReadAllText($PATH)

      # Pattern 3: 遞迴處理函數中，缺乏對深度（depth）計數器的上限判定，直接進行下層遞迴呼叫
      - pattern: |
          public $TYPE $METHOD(..., int $DEPTH, ...)
          {
              ...
              $METHOD(..., $DEPTH + 1, ...);
              ...
          }

    message: "Uncontrolled Resource Consumption (CWE-400): Found potential resource exhaustion vectors such as Regex without MatchTimeout, unbounded file reads, or unbounded recursive calls. This can easily be exploited to cause a Denial of Service (DoS)."
    languages: [csharp]
    severity: ERROR
    metadata:
      cwe: ['CWE-400']

  - id: csharp-backdoor-magic-param-cwe912
    pattern-either:
      # --- Pattern 1: Hardcoded secret query parameters in ASP.NET Context ---
      - pattern: |
          if ($REQ.Query["$PARAM"] == "$SECRET") {
              ...
          }
      - pattern: |
          if ($REQ.QueryString.Contains("$SECRET")) {
              ...
          }

      # --- Pattern 2: Checking request parameters against hardcoded magic values ---
      - pattern: |
          if ($VAR == "admin_backdoor" || $VAR == "debug_override_pass") {
              ...
          }

      # --- Pattern 3: Hidden command-line or model property backdoor triggers ---
      - pattern: |
          if ($MODEL.Role == "BackdoorAdmin" || $MODEL.SecretKey == "SkeletonKey") {
              ...
          }

    message: "HttpParameterContamination / Hidden Backdoor Functionality (CWE-912): Detecting hardcoded magic parameters or backdoor keys that bypass regular authentication/authorization controls. Remove hidden control mechanisms from production code."
    languages: [csharp]
    severity: ERROR
    metadata:
      cwe: ['CWE-912']

  - id: csharp-untrusted-inclusion-cwe829
    pattern-either:
      # --- Pattern 1: Dynamic Assembly Loading from arbitrary paths/inputs ---
      - pattern: System.Reflection.Assembly.LoadFrom($PATH)
      - pattern: System.Reflection.Assembly.LoadFile($PATH)
      - pattern: Assembly.LoadFrom($PATH)
      - pattern: Assembly.LoadFile($PATH)

      # --- Pattern 2: Insecure Dynamic XML/XAML Parsing and Loading ---
      - pattern: System.Windows.Markup.XamlReader.Load($STREAM)
      - pattern: XamlReader.Load($STREAM)

      # --- Pattern 3: Explicitly loading features over insecure HTTP channels ---
      - pattern: |
          $CLIENT.DownloadFile("http://" + $URL, $DEST);
          ...
          Assembly.LoadFrom($DEST);

    message: "Inclusion of Functionality from Untrusted Control Sphere (CWE-829): Dynamic loading of assemblies, unvalidated XAML, or plugins from untrusted sources or insecure channels can lead to Arbitrary Code Execution (RCE). Validate files before inclusion or enforce strong name signing."
    languages: [csharp]
    severity: ERROR
    metadata:
      cwe: ['CWE-829']

  - id: csharp-property-pollution-cwe1321
    pattern-either:
      # --- Pattern 1: Unsafe loop mapping key-value pairs using reflection without verification ---
      - pattern: |
          foreach (var $KEY in $DICT.Keys) {
              ...
              var $PROP = $OBJ.GetType().GetProperty($KEY);
              $PROP.SetValue($OBJ, $DICT[$KEY]);
          }

      # --- Pattern 2: Checking string patterns for proto/constructor but missing proper enforcement ---
      - pattern: |
          if ($KEY == "__proto__" || $KEY == "constructor") {
              // Missing return or exception, continuing execution leading to pollution
              ...
          }

      # --- Pattern 3: Explicitly configuring unsafe TypeNameHandling in Newtonsoft.Json ---
      - pattern: |
          var $SETTINGS = new JsonSerializerSettings();
          ...
          $SETTINGS.TypeNameHandling = TypeNameHandling.All;

    message: "Improper Control of Object Attributes / Property Pollution (CWE-1321): Dynamically setting object properties via reflection using unvalidated user keys, or enabling unsafe JSON TypeNameHandling, allows attackers to pollute application state or achieve remote code execution."
    languages: [csharp]
    severity: ERROR
    metadata:
      cwe: ['CWE-1321']

  - id: csharp-improper-cert-validation-cwe295
    pattern-either:
      # --- Pattern 1: Global ServicePointManager bypass using Lambda expressions ---
      - pattern: ServicePointManager.ServerCertificateValidationCallback += ($S, $CERT, $CHAIN, $ERRORS) => true
      - pattern: ServicePointManager.ServerCertificateValidationCallback = ($S, $CERT, $CHAIN, $ERRORS) => true

      # --- Pattern 2: HttpClientHandler custom callback bypass ---
      - pattern: |
          new HttpClientHandler {
              ...,
              ServerCertificateCustomValidationCallback = ($REQ, $CERT, $CHAIN, $ERRORS) => true,
              ...
          }
      - pattern: $HANDLER.ServerCertificateCustomValidationCallback = ($REQ, $CERT, $CHAIN, $ERRORS) => true

      # --- Pattern 3: Explicitly assigning a delegate that blindly returns true ---
      - pattern: |
          bool $FUNC(object $S, X509Certificate $CERT, X509Chain $CHAIN, SslPolicyErrors $ERRORS) {
              return true;
          }

      # --- Pattern 4: WCF CertificateValidationMode set to None ---
      - pattern: $X.ServiceCertificate.Authentication.CertificateValidationMode = X509CertificateValidationMode.None
      - pattern: $X.ServiceCertificate.Authentication.CertificateValidationMode = 0

    message: "Improper Certificate Validation (CWE-295): Trusting all certificates blindly by returning true or setting validation mode to None disables TLS protection and exposes the application to Man-in-the-Middle (MITM) attacks."
    languages: [csharp]
    severity: ERROR
    metadata:
      cwe: ['CWE-295']

  - id: csharp-weak-hash-cwe328
    pattern-either:
      # --- Pattern 1: Direct instantiation of weak hash providers ---
      - pattern: new System.Security.Cryptography.MD5CryptoServiceProvider(...)
      - pattern: new System.Security.Cryptography.SHA1CryptoServiceProvider(...)
      - pattern: new System.Security.Cryptography.SHA1Managed(...)
      - pattern: new MD5CryptoServiceProvider(...)
      - pattern: new SHA1CryptoServiceProvider(...)
      - pattern: new SHA1Managed(...)

      # --- Pattern 2: Factory creation methods ---
      - pattern: System.Security.Cryptography.MD5.Create(...)
      - pattern: System.Security.Cryptography.SHA1.Create(...)
      - pattern: MD5.Create(...)
      - pattern: SHA1.Create(...)

      # --- Pattern 3: CryptoConfig and HashAlgorithm name-based resolution ---
      - pattern: System.Security.Cryptography.HashAlgorithm.Create("$HASH")
      - pattern: System.Security.Cryptography.CryptoConfig.CreateFromName("$HASH")
      - pattern: HashAlgorithm.Create("$HASH")
      - pattern: CryptoConfig.CreateFromName("$HASH")
    metavariable-regex:
      # Capture variations of MD5 and SHA1 string identifiers (case-insensitive)
      $HASH: '^(?i)(md5|sha1|system\.security\.cryptography\.(md5|sha1))$'

    message: "Use of Weak Cryptographic Hash (CWE-328): MD5 and SHA-1 algorithms are cryptographically broken and vulnerable to collision attacks. Upgrade to safer alternatives like SHA-256, SHA-384, or SHA-512."
    languages: [csharp]
    severity: ERROR
    metadata:
      cwe: ['CWE-328']
"""

# ══════════════════════════════════════════════════════════════
# 7. php 自訂規則產生
# ══════════════════════════════════════════════════════════════
php_rules = """\
rules:
  - id: php-xss-taint-cwe79
    languages: [php]
    severity: ERROR
    message: "Cross-site Scripting (CWE-79): Unsanitized user input reaches a web output statement. Wrap input in htmlspecialchars() or htmlentities() before rendering."
    mode: taint

    # --- Sources ---
    pattern-sources:
      - pattern: $_GET
      - pattern: $_POST
      - pattern: $_REQUEST
      - pattern: $_COOKIE
      - pattern: $_SERVER
      - pattern: $_GET[...]
      - pattern: $_POST[...]

    # --- Sanitizers ---
    pattern-sanitizers:
      - pattern: htmlspecialchars(...)
      - pattern: htmlentities(...)
      - pattern: intval(...)
      - pattern: floatval(...)

    # --- Sinks (修正：不使用 echo ...，改用 Metavariables) ---
    pattern-sinks:
      - pattern: echo $ANY;
      - pattern: print($ANY);
      - pattern: print $ANY;
      - pattern: printf(...)
      - pattern: vprintf(...)
      - pattern: echo(...);

    metadata:
      cwe: ['CWE-79']

  - id: php-sql-injection-cwe89
    pattern-either:
      # Pattern 1: PDO 執行不安全的拼接 SQL 或動態字串解析
      - pattern: "$PDO->query(\\"...\\".$INPUT, ...)"
      - pattern: "$PDO->query(\\"... $INPUT ...\\", ...)"
      - pattern: "$PDO->exec(\\"...\\".$INPUT)"
      - pattern: "$PDO->exec(\\"... $INPUT ...\\")"

      # Pattern 2: mysqli 執行不安全的拼接 SQL 或動態字串解析
      - pattern: "$CONN->query(\\"...\\".$INPUT, ...)"
      - pattern: "$CONN->query(\\"... $INPUT ...\\", ...)"
      - pattern: "mysqli_query($CONN, \\"...\\".$INPUT, ...)"
      - pattern: "mysqli_query($CONN, \\"... $INPUT ...\\", ...)"

      # Pattern 3: 使用 sprintf 或 printf 格式化 SQL 字串時直接代入未過濾參數
      - pattern: "$CONN->query(sprintf(\\"...\\", ..., $INPUT, ...))"
      - pattern: "mysqli_query($CONN, sprintf(\\"...\\", ..., $INPUT, ...))"
      - pattern: "$PDO->query(sprintf(\\"...\\", ..., $INPUT, ...))"

    message: "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') (CWE-89): The application constructs SQL queries by directly concatenating or interpolating untrusted input into SQL statements. This allows malicious actors to execute arbitrary SQL commands. Always use prepared statements with parameterized queries (e.g., PDO prepare and execute) to safely separate SQL code from data."
    languages: [php]
    severity: ERROR
    metadata:
      cwe: ['CWE-89']

  - id: php-csrf-protection-missing-cwe352
    pattern-either:
      # Pattern 1: 任何將未保護的 POST/REQUEST 賦值給敏感變數的行為（可匹配所有欄位名稱）
      - pattern: "$PASSWORD = $_POST[$KEY]"
      - pattern: "$EMAIL = $_POST[$KEY]"
      - pattern: "$ROLE = $_POST[$KEY]"
      - pattern: "$ACTION = $_REQUEST[$KEY]"

      # Pattern 2: 任何在資料庫寫入或框架方法中，直接代入未保護的 POST/REQUEST 欄位
      - pattern: "$this->saveToDatabase($_POST[$EMAIL_KEY], $_POST[$PASS_KEY])"
      - pattern: "mysqli_query($CONN, \\"...\\".$_POST[$KEY])"
      - pattern: "$PDO->exec(\\"...\\".$_POST[$KEY])"

    message: "Cross-Site Request Forgery (CSRF) (CWE-352): The application performs sensitive state-changing operations directly using $_POST or $_REQUEST parameters without verifying a unique, session-backed CSRF token. Always validate a secure CSRF token before processing any state-changing requests."
    languages: [php]
    severity: ERROR
    metadata:
      cwe: ['CWE-352']

  - id: php-missing-authorization-cwe862
    pattern-either:
      # Pattern 1: 直接使用未經授權檢查的 ID 進行資料庫刪除、更新或敏感操作 (IDOR / 缺失物件級授權)
      - pattern: "$CONN->query(\\"DELETE FROM \\".$TABLE.\\" WHERE id = \\".$_GET[$ID])"
      - pattern: "mysqli_query($CONN, \\"DELETE FROM \\".$TABLE.\\" WHERE id = \\".$_GET[$ID])"
      - pattern: "$PDO->exec(\\"DELETE FROM \\".$TABLE.\\" WHERE id = \\".$_GET[$ID])"
      - pattern: "$CONN->query(\\"UPDATE \\".$TABLE.\\" SET ... WHERE id = \\".$_POST[$ID])"

      # Pattern 2: 在敏感的修改密碼、重設權限或刪除使用者方法中，直接傳入未經身分與權限驗證的輸入
      - pattern: "$this->deleteUser($_GET[$USER_ID])"
      - pattern: "$this->changeUserRole($_POST[$USER_ID], $_POST[$ROLE])"
      - pattern: "$this->updateUserPassword($_POST[$USER_ID], $_POST[$PASSWORD])"

      # Pattern 3: 動態引入（include/require）後台或管理員專屬檔案，卻無任何 Role 或 Session 授權檢查
      - pattern: "include($_GET[$PAGE])"
      - pattern: "require($_GET[$PAGE])"
      - pattern: "include_once($_GET[$PAGE])"
      - pattern: "require_once($_GET[$PAGE])"

    message: "Missing Authorization (CWE-862): The application performs sensitive state-changing operations, database modifications, or dynamic file inclusion without validating if the current authenticated user has the explicit authorization to perform these actions on the target resource. Always implement robust role-based access control (RBAC) or attribute-based access control (ABAC) before handling user-supplied identifiers or dynamic paths."
    languages: [php]
    severity: ERROR
    metadata:
      cwe: ['CWE-862']

  - id: php-out-of-bounds-write-cwe787
    pattern-either:
      # Pattern 1: FFI 記憶體複製 (memcpy) 時，直接使用未經邊界驗證的外部輸入長度
      - pattern: "FFI::memcpy($DST, $_GET[$KEY], $_GET[$LEN])"
      - pattern: "FFI::memcpy($DST, $_POST[$KEY], $_POST[$LEN])"
      - pattern: "FFI::memcpy($DST, $SRC, $_GET[$LEN])"
      - pattern: "FFI::memcpy($DST, $SRC, $_POST[$LEN])"

      # Pattern 2: 在 FFI C 陣列/指標上，直接使用未經範圍檢查的外部變數作為索引 (Index) 進行寫入
      - pattern: "$C_ARRAY[$_GET[$KEY]] = $VAL"
      - pattern: "$C_ARRAY[$_POST[$KEY]] = $VAL"
      - pattern: "$C_ARRAY[(int)$_GET[$KEY]] = $VAL"
      - pattern: "$C_ARRAY[(int)$_POST[$KEY]] = $VAL"

      # Pattern 3: 對二進位緩衝區/字串操作時，直接使用外部輸入的長度來填充或寫入，缺乏邊界防護
      - pattern: "substr_replace($BUF, $_POST[$INPUT], $_POST[$OFFSET], $_POST[$LEN])"
      - pattern: "substr_replace($BUF, $_GET[$INPUT], $_GET[$OFFSET], $_GET[$LEN])"

    message: "Out-of-bounds Write (CWE-787): The application writes data past the end, or before the beginning, of the intended buffer. In PHP, this typically occurs when using FFI (Foreign Function Interface) to interact with C libraries, or when manually performing offset-based writes on raw byte structures. Always validate that any offset, index, or write length is strictly within the allocated boundary of the destination buffer."
    languages: [php]
    severity: ERROR
    metadata:
      cwe: ['CWE-787']

  - id: php-path-traversal-cwe22
    pattern-either:
      # Pattern 1: 檔案讀取/操作函數直接拼接來自 $_GET 或 $_POST/$_REQUEST 的輸入，無安全過濾
      - pattern: "file_get_contents(\\"...\\".$_GET[$KEY], ...)"
      - pattern: "file_get_contents(\\"...\\".$_POST[$KEY], ...)"
      - pattern: "file_get_contents(\\"...\\".$_REQUEST[$KEY], ...)"
      - pattern: "file_get_contents(\\"... $_GET[$KEY] ...\\", ...)"
      - pattern: "file_get_contents(\\"... $_POST[$KEY] ...\\", ...)"
      
      # Pattern 2: 檔案寫入/刪除函數直接使用未過濾的外部路徑輸入
      - pattern: "file_put_contents(\\"...\\".$_GET[$KEY], ...)"
      - pattern: "file_put_contents(\\"...\\".$_POST[$KEY], ...)"
      - pattern: "unlink(\\"...\\".$_GET[$KEY])"
      - pattern: "unlink(\\"...\\".$_POST[$KEY])"

      # Pattern 3: 開啟檔案控制代碼（fopen）直接拼接非信任輸入
      - pattern: "fopen(\\"...\\".$_GET[$KEY], ...)"
      - pattern: "fopen(\\"...\\".$_POST[$KEY], ...)"
      - pattern: "fopen(\\"... $_GET[$KEY] ...\\", ...)"
      - pattern: "fopen(\\"... $_POST[$KEY] ...\\", ...)"

      # Pattern 4: 傳統的 include/require 直接拼接入侵路徑 (容易結合 RCE/LFI)
      - pattern: "include(\\"...\\".$_GET[$KEY])"
      - pattern: "include(\\"...\\".$_POST[$KEY])"
      - pattern: "require(\\"...\\".$_GET[$KEY])"
      - pattern: "require(\\"...\\".$_POST[$KEY])"

    message: "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') (CWE-22): The application constructs file paths by directly concatenating user-supplied input (e.g., $_GET or $_POST) without proper sanitization. This allows attackers to traverse the file system, read sensitive files (e.g., /etc/passwd), or overwrite system configurations. Always use functions like basename() to extract only the filename, or validate paths against a strict whitelist."
    languages: [php]
    severity: ERROR
    metadata:
      cwe: ['CWE-22']

  - id: php-use-after-free-cwe416
    pattern-either:
      # Pattern 1: 底層 FFI 指標釋放後再度寫入或讀取
      - pattern: "FFI::free($PTR); ... $PTR->$FIELD = $VAL;"
      - pattern: "FFI::free($PTR); ... $VAL = $PTR->$FIELD;"

      # Pattern 2: Socket / Stream 等資源關閉後再度寫入或傳送
      - pattern: "$SOCKET->close(); ... $SOCKET->write(...);"
      - pattern: "$SOCKET->close(); ... $SOCKET->send(...);"
      - pattern: "fclose($HANDLE); ... fwrite($HANDLE, ...);"
      - pattern: "fclose($HANDLE); ... fread($HANDLE, ...);"

      # Pattern 3: 物件被 unset 註銷後仍調用其方法
      - pattern: "unset($OBJ); ... $OBJ->$METHOD(...);"

    message: "Use After Free (CWE-416): The application attempts to use a resource or memory pointer after it has been explicitly freed, closed, or unset. This can lead to undefined behavior, memory corruption, or application crashes. Ensure that all references to freed or closed resources are immediately nullified or no longer accessed."
    languages: [php]
    severity: ERROR
    metadata:
      cwe: ['CWE-416']

  - id: php-out-of-bounds-read-cwe125
    pattern-either:
      # Pattern 1: FFI 記憶體複製時，直接由外部參數決定讀取長度
      - pattern: "FFI::memcpy($DST, $SRC, $_GET[$KEY])"
      - pattern: "FFI::memcpy($DST, $SRC, $_POST[$KEY])"
      - pattern: "FFI::memcpy($DST, $SRC, $_REQUEST[$KEY])"

      # Pattern 2: 在 FFI C 陣列或指標上，使用未經範圍檢查的外部變數作為索引進行讀取
      - pattern: "$VAL = $C_ARRAY[$_GET[$KEY]]"
      - pattern: "$VAL = $C_ARRAY[$_POST[$KEY]]"
      - pattern: "$VAL = $C_ARRAY[(int)$_GET[$KEY]]"
      - pattern: "$VAL = $C_ARRAY[(int)$_POST[$KEY]]"

      # Pattern 3: 對二進位字串切片或讀取時，直接代入外部輸入的 Offset 與 Length
      - pattern: "substr($BUF, $_GET[$OFFSET], $_GET[$LEN])"
      - pattern: "substr($BUF, $_POST[$OFFSET], $_POST[$LEN])"

    message: "Out-of-bounds Read (CWE-125): The application reads data past the end, or before the beginning, of the intended buffer. This typically occurs when interacting with C libraries via FFI without checking memory limits, or when manually parsing binary data/substrings using untrusted offsets. Always validate that any index, offset, or read length is within the safe boundaries of the buffer before accessing it."
    languages: [php]
    severity: ERROR
    metadata:
      cwe: ['CWE-125']

  - id: php-os-command-injection-cwe78
    pattern-either:
      # Pattern 1: system() 執行拼接或直接解析的外部輸入
      - pattern: "system(\\"...\\".$_GET[$KEY], ...)"
      - pattern: "system(\\"...\\".$_POST[$KEY], ...)"
      - pattern: "system(\\"... $_GET[$KEY] ...\\", ...)"
      - pattern: "system(\\"... $_POST[$KEY] ...\\", ...)"

      # Pattern 2: exec() 執行拼接或直接解析的外部輸入
      - pattern: "exec(\\"...\\".$_GET[$KEY], ...)"
      - pattern: "exec(\\"...\\".$_POST[$KEY], ...)"
      - pattern: "exec(\\"... $_GET[$KEY] ...\\", ...)"
      - pattern: "exec(\\"... $_POST[$KEY] ...\\", ...)"

      # Pattern 3: shell_exec() 執行拼接或直接解析的外部輸入
      - pattern: "shell_exec(\\"...\\".$_GET[$KEY])"
      - pattern: "shell_exec(\\"...\\".$_POST[$KEY])"
      - pattern: "shell_exec(\\"... $_GET[$KEY] ...\\")"
      - pattern: "shell_exec(\\"... $_POST[$KEY] ...\\")"

      # Pattern 4: passthru() 執行拼接或直接解析的外部輸入
      - pattern: "passthru(\\"...\\".$_GET[$KEY], ...)"
      - pattern: "passthru(\\"...\\".$_POST[$KEY], ...)"
      - pattern: "passthru(\\"... $_GET[$KEY] ...\\", ...)"
      - pattern: "passthru(\\"... $_POST[$KEY] ...\\", ...)"

    message: "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') (CWE-78): The application constructs OS commands by directly concatenating or interpolating untrusted inputs into command execution functions (such as system, exec, shell_exec, passthru). This allows malicious actors to execute arbitrary commands on the server. Always sanitize inputs using escapeshellarg() or escapeshellcmd(), or ideally, avoid using OS shell functions by utilizing native PHP APIs."
    languages: [php]
    severity: ERROR
    metadata:
      cwe: ['CWE-78']

  - id: php-code-injection-cwe94
    pattern-either:
      # ==================== 1. eval() 漏洞匹配 ====================
      # 情況 A: 單獨傳入外部輸入
      - pattern: "eval($_GET[$KEY])"
      - pattern: "eval($_POST[$KEY])"
      - pattern: "eval($_REQUEST[$KEY])"
      # 情況 B: 外部輸入在拼接鏈的【最末端】
      - pattern: "eval($SRC . $_GET[$KEY])"
      - pattern: "eval($SRC . $_POST[$KEY])"
      - pattern: "eval($SRC . $_REQUEST[$KEY])"
      # 情況 C: 外部輸入在拼接鏈的【中段】
      - pattern: "eval($SRC . $_GET[$KEY] . $DST)"
      - pattern: "eval($SRC . $_POST[$KEY] . $DST)"
      - pattern: "eval($SRC . $_REQUEST[$KEY] . $DST)"
      # 情況 D: 外部輸入在拼接鏈的【最前端】
      - pattern: "eval($_GET[$KEY] . $DST)"
      - pattern: "eval($_POST[$KEY] . $DST)"
      - pattern: "eval($_REQUEST[$KEY] . $DST)"
      # 情況 E: 雙引號內直接進行變數解析
      - pattern: "eval(\\"... $_GET[$KEY] ...\\")"
      - pattern: "eval(\\"... $_POST[$KEY] ...\\")"

      # ==================== 2. assert() 漏洞匹配 ====================
      # 情況 A: 單獨傳入
      - pattern: "assert($_GET[$KEY], ...)"
      - pattern: "assert($_POST[$KEY], ...)"
      - pattern: "assert($_REQUEST[$KEY], ...)"
      # 情況 B: 在最末端
      - pattern: "assert($SRC . $_GET[$KEY], ...)"
      - pattern: "assert($SRC . $_POST[$KEY], ...)"
      - pattern: "assert($SRC . $_REQUEST[$KEY], ...)"
      # 情況 C: 在中段
      - pattern: "assert($SRC . $_GET[$KEY] . $DST, ...)"
      - pattern: "assert($SRC . $_POST[$KEY] . $DST, ...)"
      - pattern: "assert($SRC . $_REQUEST[$KEY] . $DST, ...)"
      # 情況 D: 在最前端
      - pattern: "assert($_GET[$KEY] . $DST, ...)"
      - pattern: "assert($_POST[$KEY] . $DST, ...)"
      - pattern: "assert($_REQUEST[$KEY] . $DST, ...)"
      # 情況 E: 雙引號內直接進行變數解析
      - pattern: "assert(\\"... $_GET[$KEY] ...\\", ...)"
      - pattern: "assert(\\"... $_POST[$KEY] ...\\", ...)"

      # ==================== 3. create_function() 漏洞匹配 ====================
      - pattern: "create_function($ARGS, $_GET[$KEY])"
      - pattern: "create_function($ARGS, $_POST[$KEY])"
      - pattern: "create_function($ARGS, $SRC . $_GET[$KEY])"
      - pattern: "create_function($ARGS, $SRC . $_POST[$KEY])"
      - pattern: "create_function($ARGS, $SRC . $_GET[$KEY] . $DST)"
      - pattern: "create_function($ARGS, $SRC . $_POST[$KEY] . $DST)"
      - pattern: "create_function($ARGS, $_GET[$KEY] . $DST)"
      - pattern: "create_function($ARGS, $_POST[$KEY] . $DST)"
      - pattern: "create_function($ARGS, \\"... $_GET[$KEY] ...\\")"
      - pattern: "create_function($ARGS, \\"... $_POST[$KEY] ...\\")"

      # ==================== 4. preg_replace() /e 模式漏洞匹配 ====================
      - pattern: "preg_replace(\\"/.../e\\", $_GET[$KEY], ...)"
      - pattern: "preg_replace(\\"/.../e\\", $_POST[$KEY], ...)"
      - pattern: "preg_replace(\\"/.../e\\", $SRC . $_GET[$KEY], ...)"
      - pattern: "preg_replace(\\"/.../e\\", $SRC . $_POST[$KEY], ...)"
      - pattern: "preg_replace(\\"/.../e\\", $SRC . $_GET[$KEY] . $DST, ...)"
      - pattern: "preg_replace(\\"/.../e\\", $SRC . $_POST[$KEY] . $DST, ...)"

    message: "Improper Control of Generation of Code ('Code Injection') (CWE-94): The application passes untrusted input directly into functions that evaluate strings as PHP code (such as eval, assert, create_function, or preg_replace with the /e modifier). This allows attackers to execute arbitrary PHP code on the server."
    languages: [php]
    severity: ERROR
    metadata:
      cwe: ['CWE-94']

  - id: php-buffer-overflow-cwe120
    pattern-either:
      # Pattern 1: FFI 呼叫 C 的 strcpy/strcat 等不安全函式，且目的地緩衝區大小未經檢查
      - pattern: "$FFI->strcpy($DST, $_GET[$KEY])"
      - pattern: "$FFI->strcpy($DST, $_POST[$KEY])"
      - pattern: "$FFI->strcat($DST, $_GET[$KEY])"
      - pattern: "$FFI->strcat($DST, $_POST[$KEY])"

      # Pattern 2: FFI 呼叫 C 的 sprintf 寫入緩衝區，使用了外部格式化或直接代入外部輸入
      - pattern: "$FFI->sprintf($DST, $_GET[$KEY], ...)"
      - pattern: "$FFI->sprintf($DST, $_POST[$KEY], ...)"
      - pattern: "$FFI->sprintf($DST, \\"%s\\", $_GET[$KEY])"
      - pattern: "$FFI->sprintf($DST, \\"%s\\", $_POST[$KEY])"

      # Pattern 3: 在 FFI C 結構體的固定長度欄位中，直接指派外部輸入，可能導致記憶體越界寫入
      - pattern: "$STRUCT->$FIELD = $_GET[$KEY]"
      - pattern: "$STRUCT->$FIELD = $_POST[$KEY]"

    message: "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') (CWE-120): The application copies dynamic input into a fixed-size buffer without verifying that the input size is smaller than the destination buffer. When using PHP FFI, directly calling unsafe functions like strcpy, strcat, sprintf, or assigning dynamic inputs to fixed FFI struct arrays can result in memory corruption and arbitrary code execution. Always validate input length or use bounding functions like strncpy, snprintf, or FFI::memcpy with explicit length checks."
    languages: [php]
    severity: ERROR
    metadata:
      cwe: ['CWE-120']

  - id: php-unrestricted-file-upload-cwe434
    pattern-either:
      # Pattern 1: 直接使用 $_FILES['...']['name'] 作為 move_uploaded_file 的目標路徑（未做副檔名安全檢查）
      - pattern: "move_uploaded_file($_FILES[$KEY][\\"tmp_name\\"], $DIR . $_FILES[$KEY][\\"name\\"])"
      - pattern: "move_uploaded_file($_FILES[$KEY][\\"tmp_name\\"], \\"...\\".$_FILES[$KEY][\\"name\\"])"

      # Pattern 2: 僅依靠不安全的 $_FILES['...']['type'] (MIME Type) 來判斷檔案合法性並進行移動
      - pattern: "if ($_FILES[$KEY][\\"type\\"] == \\"...\\") { ... move_uploaded_file(...); ... }"
      - pattern: "if (in_array($_FILES[$KEY][\\"type\\"], $ALLOWED)) { ... move_uploaded_file(...); ... }"

      # Pattern 3: 在 move_uploaded_file 之前，僅使用 pathinfo($_FILES['...']['name'], PATHINFO_EXTENSION) 取得副檔名卻直接將該不安全檔名寫入目標目錄
      - pattern: "move_uploaded_file($_FILES[$KEY][\\"tmp_name\\"], $DIR . pathinfo($_FILES[$KEY][\\"name\\"], ...))"

    message: "Unrestricted Upload of File with Dangerous Type (CWE-434): The application allows uploading files with potentially dangerous extensions or relies solely on client-controlled MIME types for validation. This can lead to arbitrary PHP code execution on the server. Always validate the file extension against a strict whitelist (e.g., using pathinfo), generate a randomized filename, and store uploaded files outside the web root or disable PHP execution in the upload directory."
    languages: [php]
    severity: ERROR
    metadata:
      cwe: ['CWE-434']

  - id: php-stack-buffer-overflow-cwe121
    pattern-either:
      # Pattern 1: FFI 動態分配堆疊/局部字元陣列後，直接調用 strcpy 寫入未過濾的外部輸入
      - pattern: "$VAR = $FFI->new(\\"char[$SIZE]\\"); ...; $FFI->strcpy($VAR, $_GET[$KEY]);"
      - pattern: "$VAR = $FFI->new(\\"char[$SIZE]\\"); ...; $FFI->strcpy($VAR, $_POST[$KEY]);"

      # Pattern 2: FFI 宣告局部/棧結構體，並直接向其固定大小欄位寫入未經驗證長度的外部輸入
      - pattern: "$STRUCT = $FFI->new(\\"struct $TYPE\\"); ...; $STRUCT->$FIELD = $_GET[$KEY];"
      - pattern: "$STRUCT = $FFI->new(\\"struct $TYPE\\"); ...; $STRUCT->$FIELD = $_POST[$KEY];"

      # Pattern 3: FFI 分配堆疊字元陣列後，使用 sprintf 進行不安全格式化，且未限制寫入長度
      - pattern: "$VAR = $FFI->new(\\"char[$SIZE]\\"); ...; $FFI->sprintf($VAR, \\"%s\\", $_GET[$KEY]);"
      - pattern: "$VAR = $FFI->new(\\"char[$SIZE]\\"); ...; $FFI->sprintf($VAR, \\"%s\\", $_POST[$KEY]);"

    message: "Stack-based Buffer Overflow (CWE-121): The application allocates a fixed-size buffer or structure on the FFI stack and copies untrusted input into it without validating its length. This can overwrite adjacent stack memory, leading to program crashes or arbitrary code execution in the context of the PHP process. Ensure to validate input lengths using strlen() before copying, or utilize boundary-safe alternatives like snprintf or explicit length checks."
    languages: [php]
    severity: ERROR
    metadata:
      cwe: ['CWE-121']

  - id: php-untrusted-deserialization-cwe502
    pattern-either:
      # Pattern 1: 直接對外部輸入進行反序列化 (GET, POST, REQUEST, COOKIE)
      - pattern: "unserialize($_GET[$KEY])"
      - pattern: "unserialize($_POST[$KEY])"
      - pattern: "unserialize($_REQUEST[$KEY])"
      - pattern: "unserialize($_COOKIE[$KEY])"

      # Pattern 2: 先將外部輸入進行拼接或動態賦值後，再傳入 unserialize()
      - pattern: "$VAL = $_GET[$KEY]; ...; unserialize($VAL);"
      - pattern: "$VAL = $_POST[$KEY]; ...; unserialize($VAL);"
      - pattern: "$VAL = $_REQUEST[$KEY]; ...; unserialize($VAL);"
      - pattern: "$VAL = $_COOKIE[$KEY]; ...; unserialize($VAL);"

      # Pattern 3: 透過不安全的 options 設定（如未將 allowed_classes 設為 false）來解析外部輸入
      - pattern: "unserialize($_GET[$KEY], [\\"allowed_classes\\" => true])"
      - pattern: "unserialize($_POST[$KEY], [\\"allowed_classes\\" => true])"
      - pattern: "unserialize($VAL, [\\"allowed_classes\\" => true])"

    message: "Deserialization of Untrusted Data (CWE-502): Passing untrusted input to unserialize() can lead to arbitrary code execution (RCE) via object injection and PHP magic methods. Avoid using unserialize() on user-controlled data. If serialization is necessary, use safer alternatives such as json_decode() / json_encode(), or explicitly set 'allowed_classes' to false in the unserialize() options."
    languages: [php]
    severity: ERROR
    metadata:
      cwe: ['CWE-502']

  - id: php-heap-buffer-overflow-cwe122
    pattern-either:
      # Pattern 1: FFI 動態分配堆積記憶體（不指定為棧變數，通常為 owned: false 或未指定且手動管理生命週期），並直接呼叫 strcpy 寫入外部輸入
      - pattern: "$HEAPPTR = $FFI->new(\\"char[$SIZE]\\", false); ...; $FFI->strcpy($HEAPPTR, $_GET[$KEY]);"
      - pattern: "$HEAPPTR = $FFI->new(\\"char[$SIZE]\\", false); ...; $FFI->strcpy($HEAPPTR, $_POST[$KEY]);"

      # Pattern 2: 透過 FFI 直接調用 C 標準庫的 malloc/calloc 分配堆積空間，並複製未經驗證長度的外部輸入
      - pattern: "$HEAPPTR = $FFI->malloc($SIZE); ...; $FFI->strcpy($HEAPPTR, $_GET[$KEY]);"
      - pattern: "$HEAPPTR = $FFI->malloc($SIZE); ...; $FFI->strcpy($HEAPPTR, $_POST[$KEY]);"
      - pattern: "$HEAPPTR = $FFI->malloc($SIZE); ...; $FFI->memcpy($HEAPPTR, $_GET[$KEY], $LEN);"
      - pattern: "$HEAPPTR = $FFI->malloc($SIZE); ...; $FFI->memcpy($HEAPPTR, $_POST[$KEY], $LEN);"

      # Pattern 3: 向 FFI 堆積上的結構體（如動態分配的 struct）固定大小欄位中直接寫入未經長度限制的外部輸入
      - pattern: "$STRUCT = $FFI->new(\\"struct $TYPE\\", false); ...; $STRUCT->$FIELD = $_GET[$KEY];"
      - pattern: "$STRUCT = $FFI->new(\\"struct $TYPE\\", false); ...; $STRUCT->$FIELD = $_POST[$KEY];"

    message: "Heap-based Buffer Overflow (CWE-122): The application allocates a fixed-size buffer on the heap using FFI (such as via FFI::new with owned: false, or direct malloc/calloc calls) and copies untrusted input into it without limiting the size of the copied data. This can corrupt heap metadata, causing memory corruption, crashes, or potentially arbitrary code execution. Always validate the input length before writing to dynamic heap allocations, or use FFI::memcpy with an explicitly verified safe length."
    languages: [php]
    severity: ERROR
    metadata:
      cwe: ['CWE-122']

  - id: php-incorrect-authorization-cwe863
    pattern-either:
      # Pattern 1: 直接使用使用者可控制的 ID 進行資料庫更新/刪除，卻完全沒有從 Session 中比對所有權
      - pattern: "$DB->query(\\"UPDATE ... WHERE id = \\" . $_GET[$KEY])"
      - pattern: "$DB->query(\\"DELETE FROM ... WHERE id = \\" . $_GET[$KEY])"
      - pattern: "$DB->execute(\\"UPDATE ... WHERE id = ?\\", [$_GET[$KEY]])"
      - pattern: "$DB->execute(\\"DELETE FROM ... WHERE id = ?\\", [$_GET[$KEY]])"

      # Pattern 2: 僅檢查使用者是否登入 (如 isset($_SESSION['user_id']))，便直接允許執行管理員敏感操作（垂直越權）
      - pattern: "if (isset($_SESSION[\\"user_id\\"])) { ... $DB->query(\\"DELETE FROM users ...\\"); ... }"
      - pattern: "if ($_SESSION[\\"logged_in\\"] === true) { ... $DB->execute(\\"UPDATE system_settings ...\\"); ... }"

      # Pattern 3: 依賴前端可控制的 Cookie 或 POST 欄位來判斷是否為管理員（授權源信任錯誤）
      - pattern: "if ($_COOKIE[\\"role\\"] === \\"admin\\") { ... }"
      - pattern: "if ($_POST[\\"is_admin\\"] == true) { ... }"

    message: "Incorrect Authorization (CWE-863): The application fails to properly perform authorization checks on restricted resources or actions. This can allow regular users to access, modify, or delete resources belonging to other users (IDOR), or perform administrative functions. Always perform server-side checks verifying that the authenticated user owns the requested resource or possesses the required role before executing sensitive logic."
    languages: [php]
    severity: ERROR
    metadata:
      cwe: ['CWE-863']

  - id: php-sensitive-info-exposure-cwe200
    pattern-either:
      # Pattern 1: Direct output of detailed database or system exception messages
      - pattern: "echo $ERR->getMessage(...);"
      - pattern: "print($ERR->getMessage(...));"
      - pattern: "print_r($ERR->getMessage(...));"
      - pattern: "die($ERR->getMessage(...));"

      # Pattern 2: Exposing environment variables or sensitive superglobals to the output
      - pattern: "var_dump($_ENV);"
      - pattern: "print_r($_ENV);"
      - pattern: "var_dump($_SERVER);"
      - pattern: "print_r($_SERVER);"

      # Pattern 3: Returning raw database credentials or API keys directly in output/responses
      - pattern: "echo $CONNECTION_STRING;"
      - pattern: "echo $API_KEY;"

      # Pattern 4: Printing PHP configuration details via phpinfo() in non-development contexts
      - pattern: "phpinfo();"
    message: "Exposure of Sensitive Information to an Unauthorized Actor (CWE-200): The application prints raw system/exception messages, environment variables, configuration data, or hardcoded credentials directly. This can leak system paths, database structures, or internal credentials to attackers."
    languages: [php]
    severity: WARNING
    metadata:
      cwe: ['CWE-200']

  - id: php-missing-authentication-cwe306
    pattern-either:
      # Pattern 1: Sensitive database mutation methods without checking Session/Auth first in the scope
      - pattern: |
          function $FUNC(...) {
            ...
            $DB->execute("UPDATE...", ...);
          }
      - pattern: |
          function $FUNC(...) {
            ...
            $DB->execute("DELETE FROM...", ...);
          }

      # Pattern 2: Critical system action performed directly on request parameters without validation check
      - pattern: |
          function $FUNC(...) {
            ...
            $USER->changePassword($_POST[$PWD]);
          }

      # Pattern 3: Financial transaction processing without authorization gates
      - pattern: |
          function $FUNC(...) {
            ...
            $PAYMENT->transferFunds(...);
          }
    # Exclude safe patterns that perform validation checking before executing sensitive operations
    pattern-not-either:
      - pattern: |
          function $FUNC(...) {
            ...
            if (!isset($_SESSION[$VAR])) {
              ...
            }
            ...
          }
      - pattern: |
          function $FUNC(...) {
            ...
            if (!$AUTH->isLoggedIn(...)) {
              ...
            }
            ...
          }
      - pattern: |
          function $FUNC(...) {
            ...
            $this->requireAuth(...);
            ...
          }

    message: "Missing Authentication for Critical Function (CWE-306): Detected critical actions (updating DB, changing passwords, or transferring funds) being executed without visible authentication or session checks."
    languages: [php]
    severity: ERROR
    metadata:
      cwe: ['CWE-306']

  - id: php-ssrf-cwe918
    pattern-either:
      # Pattern 1: Unsanitized user input directly passed to cURL URL option
      - pattern: |
          $URL = $_GET[$VAR];
          ...
          curl_setopt($CH, CURLOPT_URL, $URL);
      - pattern: |
          $URL = $_POST[$VAR];
          ...
          curl_setopt($CH, CURLOPT_URL, $URL);
      - pattern: "curl_setopt($CH, CURLOPT_URL, $_GET[$VAR]);"
      - pattern: "curl_setopt($CH, CURLOPT_URL, $_POST[$VAR]);"

      # Pattern 2: Reading or getting contents from user-controlled URLs directly
      - pattern: "file_get_contents($_GET[$VAR]);"
      - pattern: "file_get_contents($_POST[$VAR]);"

      # Pattern 3: Copying files from user-controlled source URLs
      - pattern: "copy($_GET[$VAR], $DEST);"
      - pattern: "copy($_POST[$VAR], $DEST);"
    
    # Exclude patterns that perform safety validation checks
    pattern-not-either:
      # Safe check 1: Validate host using a whitelist array check
      - pattern: |
          $URL = $_GET[$VAR];
          ...
          if (in_array($URL, $WHITELIST, true)) {
            ...
            curl_setopt($CH, CURLOPT_URL, $URL);
          }
      # Safe check 2: Strict prefix verification (enforcing target subdirectory/domain)
      - pattern: |
          $URL = $_GET[$VAR];
          ...
          if (strpos($URL, "https://api.trusted.com/") === 0) {
            ...
            file_get_contents($URL);
          }

    message: "Server-Side Request Forgery (SSRF) (CWE-918): User-controlled input is directly used to construct a network request URL. This can allow attackers to abuse the server to scan internal networks, access metadata services, or perform unauthorized external requests."
    languages: [php]
    severity: ERROR
    metadata:
      cwe: ['CWE-918']

  - id: php-idor-cwe639
    # CWE-639 / IDOR: trace a request-controlled object key to data-access
    # APIs.  Ownership checks are application-specific, so they cannot be
    # inferred safely from nearby session or authorization code.
    mode: taint
    pattern-sources:
      - pattern-either:
          - pattern: $_GET[...]
          - pattern: $_POST[...]
          - pattern: $_REQUEST[...]
    pattern-sinks:
      - pattern-either:
          # Pattern 1: PDO / database-wrapper query and prepared-query APIs.
          - pattern: $DB->query(...)
          - pattern: $DB->prepare(...)
          - pattern: $DB->execute(...)
          # Pattern 2: mysqli query and prepare APIs.
          - pattern: mysqli_query(...)
          - pattern: mysqli_prepare(...)
          # Pattern 3: Doctrine / repository direct object lookup APIs.
          - pattern: $REPOSITORY->find(...)
          - pattern: $REPOSITORY->findOneBy(...)
          # Pattern 4: Laravel Eloquent static and builder lookup APIs.
          - pattern: $MODEL::find(...)
          - pattern: $MODEL::findOrFail(...)
          - pattern: $QUERY->find(...)
          - pattern: $QUERY->findOrFail(...)
          - pattern: $QUERY->where(...)
          # Pattern 5: Common custom repository lookup convention.
          - pattern: $REPOSITORY->findById(...)

    message: "Authorization Bypass Through User-Controlled Key (CWE-639 / IDOR): A request-controlled value reaches a database or ORM resource lookup. Verify that the current authenticated user is authorized to access the specific object, for example by scoping the query with both object ID and current user ID."
    languages: [php]
    severity: ERROR
    metadata:
      cwe: ['CWE-639']

  - id: php-improper-access-control-cwe284
    patterns:
      - pattern-either:
          # Pattern 1: 以 GET/POST/REQUEST/Cookie/Header 的值作為授權判斷，
          # 然後執行刪除、寫入、管理或設定變更等敏感操作。
          - patterns:
              - pattern-inside: |
                  if ($_GET[...]) {
                    ...
                  }
              - pattern-either:
                  - pattern: $DB->exec(...)
                  - pattern: $DB->query(...)
                  - pattern: $DB->execute(...)
                  - pattern: mysqli_query(...)
                  - pattern: unlink(...)
                  - pattern: file_put_contents(...)
                  - pattern: $SERVICE->deleteUser(...)
                  - pattern: $SERVICE->changeUserRole(...)
                  - pattern: $SERVICE->updateSettings(...)
          - patterns:
              - pattern-inside: |
                  if ($_POST[...]) {
                    ...
                  }
              - pattern-either:
                  - pattern: $DB->exec(...)
                  - pattern: $DB->query(...)
                  - pattern: $DB->execute(...)
                  - pattern: mysqli_query(...)
                  - pattern: unlink(...)
                  - pattern: file_put_contents(...)
                  - pattern: $SERVICE->deleteUser(...)
                  - pattern: $SERVICE->changeUserRole(...)
                  - pattern: $SERVICE->updateSettings(...)
          - patterns:
              - pattern-inside: |
                  if ($_REQUEST[...]) {
                    ...
                  }
              - pattern-either:
                  - pattern: $DB->exec(...)
                  - pattern: $DB->query(...)
                  - pattern: $DB->execute(...)
                  - pattern: mysqli_query(...)
                  - pattern: unlink(...)
                  - pattern: file_put_contents(...)
                  - pattern: $SERVICE->deleteUser(...)
                  - pattern: $SERVICE->changeUserRole(...)
                  - pattern: $SERVICE->updateSettings(...)
          - patterns:
              - pattern-inside: |
                  if ($_COOKIE[...]) {
                    ...
                  }
              - pattern-either:
                  - pattern: $DB->exec(...)
                  - pattern: $DB->query(...)
                  - pattern: $DB->execute(...)
                  - pattern: mysqli_query(...)
                  - pattern: unlink(...)
                  - pattern: file_put_contents(...)
                  - pattern: $SERVICE->deleteUser(...)
                  - pattern: $SERVICE->changeUserRole(...)
                  - pattern: $SERVICE->updateSettings(...)
          - patterns:
              - pattern-inside: |
                  if ($_SERVER[...]) {
                    ...
                  }
              - pattern-either:
                  - pattern: $DB->exec(...)
                  - pattern: $DB->query(...)
                  - pattern: $DB->execute(...)
                  - pattern: mysqli_query(...)
                  - pattern: unlink(...)
                  - pattern: file_put_contents(...)
                  - pattern: $SERVICE->deleteUser(...)
                  - pattern: $SERVICE->changeUserRole(...)
                  - pattern: $SERVICE->updateSettings(...)

          # Pattern 2: Client-controlled input is directly assigned as a role
          # or administrative privilege.
          - pattern: $USER->setRole($_GET[...])
          - pattern: $USER->setRole($_POST[...])
          - pattern: $USER->setRole($_REQUEST[...])
          - pattern: $USER->role = $_GET[...]
          - pattern: $USER->role = $_POST[...]
          - pattern: $USER->role = $_REQUEST[...]
          - pattern: $USER->is_admin = $_GET[...]
          - pattern: $USER->is_admin = $_POST[...]
          - pattern: $USER->is_admin = $_REQUEST[...]

          # Pattern 3: Unrestricted mass assignment can set role/is_admin and
          # other security-sensitive fields supplied by the client.
          - pattern: $MODEL::create($_POST)
          - pattern: $MODEL::create($_REQUEST)
          - pattern: $MODEL->fill($_POST)
          - pattern: $MODEL->fill($_REQUEST)
          - pattern: $MODEL->update($_POST)
          - pattern: $MODEL->update($_REQUEST)

          # Pattern 4: ACL grants access to every subject.
          - pattern: $ACL->allow($SUBJECT, $RESOURCE, "all")
          - pattern: $ACL->allow($SUBJECT, $RESOURCE, "*")
          - pattern: $ACL->grant($SUBJECT, $RESOURCE, "all")
          - pattern: $ACL->grant($SUBJECT, $RESOURCE, "*")

          # Pattern 5: World-writable files/directories weaken the intended
          # access-control policy.
          - pattern: chmod($PATH, 0777)
          - pattern: mkdir($PATH, 0777)
          - pattern: mkdir($PATH, 0777, true)

    message: "Improper Access Control (CWE-284): The application uses client-controlled data to authorize a sensitive action, permits client-controlled privilege assignment, or configures an overly permissive ACL/file mode. Enforce authorization with a server-side session identity and a trusted RBAC/ABAC policy; never trust request parameters, cookies, or headers as proof of privilege."
    languages: [php]
    severity: ERROR
    metadata:
      cwe: ['CWE-284']

  - id: php-command-injection-cwe77
    # Track externally influenced data to command-execution APIs.
    mode: taint
    pattern-sources:
      - pattern-either:
          # HTTP request sources
          - pattern: $_GET[...]
          - pattern: $_POST[...]
          - pattern: $_REQUEST[...]
          - pattern: $_COOKIE[...]
          - pattern: $_SERVER[...]
          - pattern: $_FILES[...]

          # PHP input APIs and CLI arguments
          - pattern: filter_input(...)
          - pattern: filter_input_array(...)
          - pattern: $argv[...]

          # Common PHP framework request objects
          - pattern: $REQUEST->input(...)
          - pattern: $REQUEST->query(...)
          - pattern: $REQUEST->post(...)

    # These functions quote shell metacharacters. They do not replace a strict
    # allowlist when only a limited set of commands or arguments is valid.
    pattern-sanitizers:
      - pattern-either:
          - pattern: escapeshellarg(...)
          - pattern: escapeshellcmd(...)

    pattern-sinks:
      - pattern-either:
          # Pattern 1: Native PHP shell command execution functions
          - pattern: system(...)
          - pattern: exec(...)
          - pattern: shell_exec(...)
          - pattern: passthru(...)

          # Pattern 2: Process creation and interactive process APIs
          - pattern: popen(...)
          - pattern: proc_open(...)
          - pattern: pcntl_exec(...)
          - pattern: expect_popen(...)

          # Pattern 3: PHP shell-execution backtick operator
          - pattern: |
              `$COMMAND`

          # Pattern 4: Common application command/process wrappers
          - pattern: $RUNNER->run(...)
          - pattern: $RUNNER->execute(...)
          - pattern: $PROCESS->run(...)
          - pattern: $PROCESS->start(...)

    message: "Command Injection (CWE-77): Externally influenced input reaches a command execution API without confirmed command-specific validation. Do not construct command strings from request, cookie, header, upload, or CLI input. Prefer native PHP/library APIs; otherwise use a strict allowlist and quote every individual shell argument with escapeshellarg()."
    languages: [php]
    severity: ERROR
    metadata:
      cwe: ['CWE-77']

  - id: php-improper-authentication-cwe287
    pattern-either:
      # Pattern 1: Request-controlled flags are trusted as proof of identity.
      - pattern: |
          if ($_GET[...]) {
            ...
          }
      - pattern: |
          if ($_POST[...]) {
            ...
          }
      - pattern: |
          if ($_REQUEST[...]) {
            ...
          }
      - pattern: |
          if ($_COOKIE[...]) {
            ...
          }
      - pattern: |
          if ($_SERVER[...]) {
            ...
          }

      # Pattern 2: Loose comparison of untrusted credentials/tokens permits
      # type-juggling authentication bypasses.
      - pattern: |
          if ($_GET[...] == $EXPECTED) {
            ...
          }
      - pattern: |
          if ($_POST[...] == $EXPECTED) {
            ...
          }
      - pattern: |
          if ($_REQUEST[...] == $EXPECTED) {
            ...
          }
      - pattern: |
          if ($_COOKIE[...] == $EXPECTED) {
            ...
          }
      - pattern: |
          if ($EXPECTED == $_GET[...]) {
            ...
          }
      - pattern: |
          if ($EXPECTED == $_POST[...]) {
            ...
          }
      - pattern: |
          if ($EXPECTED == $_REQUEST[...]) {
            ...
          }
      - pattern: |
          if ($EXPECTED == $_COOKIE[...]) {
            ...
          }

      # Pattern 3: Weak password-hash comparison using loose equality.
      - pattern: |
          if (md5($_GET[...]) == $EXPECTED_HASH) {
            ...
          }
      - pattern: |
          if (md5($_POST[...]) == $EXPECTED_HASH) {
            ...
          }
      - pattern: |
          if (sha1($_GET[...]) == $EXPECTED_HASH) {
            ...
          }
      - pattern: |
          if (sha1($_POST[...]) == $EXPECTED_HASH) {
            ...
          }

      # Pattern 4: Token membership check without strict type comparison.
      - pattern: in_array($_GET[...], $VALID_TOKENS)
      - pattern: in_array($_POST[...], $VALID_TOKENS)
      - pattern: in_array($_REQUEST[...], $VALID_TOKENS)
      - pattern: in_array($_COOKIE[...], $VALID_TOKENS)

      # Pattern 5: JWT decoded with no key or with the unsafe "none" algorithm.
      - pattern: JWT::decode($TOKEN, null, ...)
      - pattern: JWT::decode($TOKEN, $KEY, ["none"])

    message: "Improper Authentication (CWE-287): The application treats client-controlled data as proof of identity, uses a type-juggling-prone credential comparison, or accepts an inadequately verified token. Authenticate with a server-side session or verified signed token; use password_verify() for passwords and hash_equals() or strict comparisons for secrets."
    languages: [php]
    severity: ERROR
    metadata:
      cwe: ['CWE-287']

  - id: php-improper-privilege-management-cwe269
    pattern-either:
      # Pattern 1: Direct assignment of administrator/superuser privileges.
      - pattern: $USER->role = "admin"
      - pattern: $USER->role = "administrator"
      - pattern: $USER->role = "superuser"
      - pattern: $USER->is_admin = true
      - pattern: $USER->is_superuser = true
      - pattern: $USER->assignRole("admin")
      - pattern: $USER->assignRole("administrator")
      - pattern: $USER->assignRole("superuser")
      - pattern: $USER->syncRoles(["admin"])
      - pattern: $USER->syncRoles(["administrator"])
      - pattern: $USER->givePermissionTo(...)
      - pattern: $USER->grantRole(...)

      # Pattern 2: Client-controlled data directly selects a role or privilege.
      - pattern: $USER->role = $_GET[...]
      - pattern: $USER->role = $_POST[...]
      - pattern: $USER->role = $_REQUEST[...]
      - pattern: $USER->is_admin = $_GET[...]
      - pattern: $USER->is_admin = $_POST[...]
      - pattern: $USER->is_admin = $_REQUEST[...]
      - pattern: $USER->assignRole($_GET[...])
      - pattern: $USER->assignRole($_POST[...])
      - pattern: $USER->assignRole($_REQUEST[...])
      - pattern: $USER->syncRoles($_POST[...])
      - pattern: $USER->givePermissionTo($_POST[...])
      - pattern: $USER->grantRole($_POST[...])

      # Pattern 3: Login directly as a request-selected account.
      - pattern: Auth::loginUsingId($_GET[...])
      - pattern: Auth::loginUsingId($_POST[...])
      - pattern: Auth::loginUsingId($_REQUEST[...])

      # Pattern 4: Raising process privileges to root or accepting a
      # request-controlled UID/GID.
      - pattern: posix_setuid(0)
      - pattern: posix_seteuid(0)
      - pattern: posix_setgid(0)
      - pattern: posix_setegid(0)
      - pattern: posix_setuid($_GET[...])
      - pattern: posix_setuid($_POST[...])
      - pattern: posix_seteuid($_GET[...])
      - pattern: posix_seteuid($_POST[...])
      - pattern: posix_setgid($_GET[...])
      - pattern: posix_setgid($_POST[...])
      - pattern: posix_setegid($_GET[...])
      - pattern: posix_setegid($_POST[...])

    message: "Improper Privilege Management (CWE-269): The application grants, selects, or elevates privileges without a trusted server-side authorization decision. Apply least privilege, restrict role and permission changes to dedicated authorized workflows, and never derive account identity, roles, or POSIX UID/GID from request data."
    languages: [php]
    severity: ERROR
    metadata:
      cwe: ['CWE-269']

  - id: php-native-buffer-boundary-cwe119
    # PHP itself manages string/array bounds. This rule is deliberately scoped
    # to FFI and C-library calls, where PHP data crosses into native memory.
    mode: taint
    pattern-sources:
      - pattern-either:
          - pattern: $_GET[...]
          - pattern: $_POST[...]
          - pattern: $_REQUEST[...]
          - pattern: $_COOKIE[...]
          - pattern: $_FILES[...]
          - pattern: $argv[...]

    pattern-sinks:
      - pattern-either:
          # Pattern 1: PHP FFI raw-memory copy and move operations.
          - pattern: FFI::memcpy(...)
          - pattern: FFI::memmove(...)
          - pattern: FFI::memset(...)

          # Pattern 2: FFI reads a native buffer using a caller-supplied length.
          - pattern: FFI::string(...)

          # Pattern 3: Unsafe C string and formatted-output functions exposed
          # through an FFI-loaded shared library.
          - pattern: $LIBRARY->strcpy(...)
          - pattern: $LIBRARY->strcat(...)
          - pattern: $LIBRARY->sprintf(...)
          - pattern: $LIBRARY->vsprintf(...)
          - pattern: $LIBRARY->gets(...)

          # Pattern 4: Native C memory functions exposed as instance methods.
          - pattern: $LIBRARY->memcpy(...)
          - pattern: $LIBRARY->memmove(...)
          - pattern: $LIBRARY->memset(...)

    message: "Improper Restriction of Operations within the Bounds of a Memory Buffer (CWE-119): Untrusted data reaches an FFI or native C memory/string operation. Validate copy lengths against the actual destination allocation, avoid strcpy/strcat/gets, and use bounded native APIs such as snprintf or explicit checked lengths."
    languages: [php]
    severity: ERROR
    metadata:
      cwe: ['CWE-119']

  - id: php-integer-overflow-cwe190
    # PHP integers convert to float on overflow, but explicit casts, loop bounds,
    # and allocation sizes remain vulnerable to wraparound and heavy resource utilization.
    mode: taint
    pattern-sources:
      - pattern-either:
          - pattern: $_GET[...]
          - pattern: $_POST[...]
          - pattern: $_REQUEST[...]
          - pattern: $_COOKIE[...]
          - pattern: $_FILES[...]
          - pattern: $argv[...]

    pattern-sinks:
      - pattern-either:
          # Pattern 1: Loop boundary calculations using unchecked arithmetic on tainted inputs
          - pattern: for ($I = $INIT; $I < $SINK + $VAL; $I++) { ... }
          - pattern: for ($I = $INIT; $I < $SINK * $VAL; $I++) { ... }

          # Pattern 2: Explicit integer cast forcing a wraparound / truncation
          - pattern: (int)($SINK + $VAL)
          - pattern: (int)($SINK * $VAL)

          # Pattern 3: Dynamic repeat allocation controls using unchecked arithmetic
          - pattern: str_repeat($STR, $SINK * $VAL)
          - pattern: str_repeat($STR, $SINK + $VAL)

    pattern-sanitizers:
      - pattern-either:
          # Exclude variables checked against a maximum boundary
          - pattern: |
              if ($VAR < $MAX) {
                ...
              }

    message: "Integer Overflow or Wraparound (CWE-190): Untrusted user input flows into arithmetic operations that define loop limits, memory allocation limits, or are explicitly cast to integers. Validate input bounds before performing arithmetic operations."
    languages: [php]
    severity: WARNING
    metadata:
      cwe: ['CWE-190']

  - id: php-file-inclusion-cwe829
    # Matches File Inclusion (LFI/RFI) vulnerabilities where untrusted inputs
    # flow directly into include/require statements without path sanitization.
    mode: taint
    pattern-sources:
      - pattern-either:
          - pattern: $_GET
          - pattern: $_POST
          - pattern: $_REQUEST
          - pattern: $_COOKIE
          - pattern: $_SERVER
          - pattern: $argv

    pattern-sinks:
      - pattern-either:
          # Match include and require language constructs
          - pattern: include(...)
          - pattern: include_once(...)
          - pattern: require(...)
          - pattern: require_once(...)

    pattern-sanitizers:
      - pattern-either:
          # Match standard sanitization functions that strip paths
          - pattern: basename(...)
          - pattern: pathinfo(...)

    message: "Inclusion of Functionality from Untrusted Control Sphere (CWE-829): Untrusted user input is directly used in file inclusion statements. This can lead to Local File Inclusion (LFI) or Remote File Inclusion (RFI) vulnerabilities."
    languages: [php]
    severity: ERROR
    metadata:
      cwe: ['CWE-829']

  - id: php-prototype-pollution-cwe1321
    # Matches Prototype Pollution-like vulnerabilities in PHP where untrusted keys
    # flow directly into recursive merge, extend, or deep-assignment properties.
    mode: taint
    pattern-sources:
      - pattern-either:
          - pattern: $_GET
          - pattern: $_POST
          - pattern: $_REQUEST
          - pattern: $_COOKIE
          - pattern: $_SERVER

    pattern-sinks:
      - pattern-either:
          # Sink 1: Deep property assignment using dynamic, nested user keys
          - pattern: $OBJ[$KEY1][$KEY2] = $VAL
          - pattern: $OBJ->{$KEY1}->{$KEY2} = $VAL
          
          # Sink 2: Custom recursive merge or extend operations on object properties
          - pattern: array_merge_recursive($ARR, $SINK)
          - pattern: $UTILS->extend($OBJ, $SINK)

    pattern-sanitizers:
      - pattern-either:
          # Ensure keys containing prototype pollution payloads are rejected
          - pattern: |
              if ($KEY === "__proto__" || $KEY === "prototype" || $KEY === "constructor") {
                ...
              }
          - pattern: |
              if (in_array($KEY, ["__proto__", "prototype", "constructor"])) {
                ...
              }

    message: "Improper Controlled Modification of Object Prototype Attributes ('Prototype Pollution') (CWE-1321): Untrusted input keys flow into deep property assignments or recursive merge operations without validating against prototype attributes (e.g., __proto__, prototype, constructor)."
    languages: [php]
    severity: ERROR
    metadata:
      cwe: ['CWE-1321']

  - id: php-improper-cert-validation-cwe295
    # Detects improper SSL/TLS certificate validation settings in cURL, 
    # stream contexts, and Guzzle HTTP clients.
    mode: taint
    pattern-sources:
      - pattern-either:
          # Match insecure configuration values (false, 0)
          - pattern: "false"
          - pattern: "0"

    pattern-sinks:
      - pattern-either:
          # Sink 1: cURL insecure peer/host verification
          - pattern: curl_setopt($CH, CURLOPT_SSL_VERIFYPEER, $SINK)
          - pattern: curl_setopt($CH, CURLOPT_SSL_VERIFYHOST, $SINK)
          - pattern: curl_setopt_array($CH, [..., CURLOPT_SSL_VERIFYPEER => $SINK, ...])
          - pattern: curl_setopt_array($CH, [..., CURLOPT_SSL_VERIFYHOST => $SINK, ...])

          # Sink 2: Stream Context insecure peer/name verification
          - pattern: stream_context_create([..., "ssl" => [..., "verify_peer" => $SINK, ...], ...])
          - pattern: stream_context_create([..., "ssl" => [..., "verify_peer_name" => $SINK, ...], ...])

          # Sink 3: Guzzle HTTP client disabling verification
          - pattern: new GuzzleHttp\\Client([..., "verify" => $SINK, ...])
          - pattern: $CLIENT->request(..., ..., [..., "verify" => $SINK, ...])

    message: "Improper Certificate Validation (CWE-295): SSL/TLS certificate verification is explicitly disabled. This allows man-in-the-middle (MITM) attacks. Ensure CURLOPT_SSL_VERIFYPEER, CURLOPT_SSL_VERIFYHOST, Guzzle's 'verify', and stream context 'verify_peer' are enabled."
    languages: [php]
    severity: ERROR
    metadata:
      cwe: ['CWE-295']

  - id: php-weak-hash-cwe328
    # Detects the use of weak cryptographic hash algorithms (MD5, SHA-1)
    # used on sensitive or user-controlled data.
    mode: taint
    pattern-sources:
      - pattern-either:
          - pattern: $_GET
          - pattern: $_POST
          - pattern: $_REQUEST
          - pattern: $_COOKIE
          - pattern: $_SERVER
          - pattern: $PASSWORD
          - pattern: $SECRET

    pattern-sinks:
      - pattern-either:
          # Sink 1: Direct weak hashing functions
          - pattern: md5($SINK)
          - pattern: sha1($SINK)

          # Sink 2: Dynamic hash/hmac functions with weak algorithm arguments
          - pattern: hash("md5", $SINK)
          - pattern: hash("sha1", $SINK)
          - pattern: hash_hmac("md5", $SINK, ...)
          - pattern: hash_hmac("sha1", $SINK, ...)

    message: "Use of Weak Cryptographic Algorithm (CWE-328): MD5 and SHA-1 are cryptographically broken and prone to collision attacks. Use secure alternatives like bcrypt, Argon2 (via password_hash), or SHA-256/SHA-512 (via hash/hash_hmac)."
    languages: [php]
    severity: ERROR
    metadata:
      cwe: ['CWE-328']
"""

# ══════════════════════════════════════════════════════════════
# 8. typescript 自訂規則產生
# ══════════════════════════════════════════════════════════════
ts_rules = """\
rules:
  - id: ts-xss-cross-site-scripting-cwe79
    pattern-either:
      # Pattern 1: 直接指派給 innerHTML 或 outerHTML
      - pattern: $EL.innerHTML = $INPUT
      - pattern: $EL.outerHTML = $INPUT

      # Pattern 2: 呼叫 document 原生寫入方法
      - pattern: document.write($INPUT)
      - pattern: document.writeln($INPUT)

      # Pattern 3: 呼叫 eval 執行動態程式碼
      - pattern: eval($INPUT)

      # Pattern 4: 變更瀏覽器網址進行 javascript: 偽協定注入
      - pattern: location.href = $INPUT
      - pattern: window.location = $INPUT

      # Pattern 5: 抓取任何物件字面量中包含 dangerouslySetInnerHTML 的結構
      - pattern: "{ ..., dangerouslySetInnerHTML: $VAL, ... }"
      # 如果你在 TSX/JSX 標籤內使用，則可以用這行（選用）：
      # - pattern: <$TAG dangerouslySetInnerHTML={$VAL} />

      # Pattern 6: 後端 Express 響應直接串接輸出（使用 ... 允許任何形式的拼接與變數）
      - pattern: $RES.send(...)
      - pattern: $RES.write(...)

    message: "Cross-Site Scripting (XSS) (CWE-79): Untrusted input is rendered directly to the web page or output stream without proper escaping or sanitization. Use DOMPurify, secure modern framework binding, or robust encoding libraries."
    languages: [typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-79']

  - id: ts-sqli-sql-injection-cwe89
    pattern-either:
      # Pattern 1: pg (PostgreSQL) 模組直接執行拼接或樣板字串
      - pattern: $CLIENT.query($X + $INPUT, ...)
      - pattern: $CLIENT.query(`...${$INPUT}...`, ...)

      # Pattern 2: mysql2 模組直接執行拼接或樣板字串
      - pattern: $CONN.query($X + $INPUT, ...)
      - pattern: $CONN.query(`...${$INPUT}...`, ...)
      - pattern: $CONN.execute($X + $INPUT, ...)
      - pattern: $CONN.execute(`...${$INPUT}...`, ...)

      # Pattern 3: TypeORM 框架中使用危險的 Raw SQL 方法（如 query 或 whereRaw 拼接）
      - pattern: $REPO.query($X + $INPUT)
      - pattern: $REPO.query(`...${$INPUT}...`)
      - pattern: $QB.where($X + $INPUT)
      - pattern: $QB.where(`...${$INPUT}...`)

      # Pattern 4: Prisma 框架中使用不安全的 $queryRawUnsafe
      - pattern: $PRISMA.$queryRawUnsafe($X + $INPUT)
      - pattern: $PRISMA.$queryRawUnsafe(`...${$INPUT}...`)

      # Pattern 5: Sequelize 框架中直接傳入拼接字串給 query 方法
      - pattern: |
          $SEQ.query($X + $INPUT, {
            type: ...
          })
      - pattern: |
          $SEQ.query(`...${$INPUT}...`, {
            type: ...
          })

    message: "SQL Injection (CWE-89): Untrusted input is dynamically concatenated into a SQL query string. Use parameterized queries, prepared statements, or safe ORM mechanisms instead."
    languages: [typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-89']

  - id: ts-csrf-cross-site-request-forgery-cwe352
    pattern-either:
      # Pattern 1: 偵測呼叫了 cookieParser 的 Express 初始化（移除多行層次，改用單行強匹配防崩潰）
      - pattern: "$APP.use(cookieParser(...))"

      # Pattern 2: Cookie 設定中將 sameSite 設為 "none"（用引號包覆防 AST 解析出錯）
      - pattern: "res.cookie($NAME, $VAL, { ..., sameSite: 'none', ... })"
      - pattern: "res.cookie($NAME, $VAL, { ..., sameSite: 'none', secure: false, ... })"

      # Pattern 3: Express-session 配置中將 cookie.sameSite 設為 false 或 none
      - pattern: "session({ ..., cookie: { ..., sameSite: false, ... }, ... })"
      - pattern: "session({ ..., cookie: { ..., sameSite: 'none', ... }, ... })"

      # Pattern 4: 停用了特定安全性套件中的 CSRF 保護，或設定寬鬆的忽略方法
      - pattern: $PROTECT.disableCsrf()
      - pattern: "csrf({ ..., ignoreMethods: $METHODS, ... })"

    message: "Cross-Site Request Forgery (CSRF) (CWE-352): The application configuration lacks CSRF protection mechanisms or explicitly downgrades Cookie SameSite attributes, allowing unauthorized commands to be transmitted from trusted users. Ensure proper CSRF tokens or SameSite=Strict/Lax configurations are enforced."
    languages: [typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-352']

  - id: ts-missing-authorization-cwe862
    pattern-either:
      # Pattern 1: NestJS 控制器中定義了敏感端點（如 @Delete, @Post, @Put），卻完全漏掉權限守衛（如 @UseGuards, @Roles）
      - pattern: |
          @Controller(...)
          class $CLASS {
            ...
            @Delete(...)
            $METHOD(...) { ... }
          }
      - pattern: |
          @Controller(...)
          class $CLASS {
            ...
            @Put(...)
            $METHOD(...) { ... }
          }

      # Pattern 2: 路由方法中直接調用資料庫敏感操作，卻未在其前置鏈上或內部呼叫任何授權檢查方法
      - pattern: |
          $APP.delete($ROUTE, (req, res) => {
            ...
            $DB.deleteRecord(...);
            ...
          })

      # Pattern 3: 在 GraphQL 的 Mutation 解析器（Resolver）方法中，完全沒有加入任何權限裝飾器
      - pattern: |
          @Resolver(...)
          class $RESOLVER {
            ...
            @Mutation(...)
            $MUTATION(...) { ... }
          }

      # Pattern 4: 自訂的敏感業務逻辑方法（例如管理員功能）名稱包含敏感字眼，卻完全缺乏授權驗證常規調用
      - pattern: |
          function executeAdminAction(...) {
            ...
            // 缺乏 checkPermission() 或 checkRole() 等呼叫
            ...
          }

    message: "Missing Authorization (CWE-862): The application endpoint or sensitive business logic executes critical operations without checking the user's roles or permissions. Ensure proper Guards, Middleware, or authorization checks are explicitly added."
    languages: [typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-862']

  - id: ts-out-of-bounds-write-cwe787
    pattern-either:
      # Pattern 1: Buffer 寫入時，寫入的偏移量（Offset）直接受外部輸入影響，無邊界檢查
      - pattern: "$BUF.writeUInt8($VAL, $INPUT)"
      - pattern: "$BUF.write($STR, $INPUT, ...)"

      # Pattern 2: Buffer 複製時，目標起始偏移量、來源起始偏移量或複製長度直接受外部不受信任的輸入控制
      - pattern: "$SRC.copy($TARGET, $INPUT, ...)"
      - pattern: "$SRC.copy($TARGET, $OFFSET, $INPUT, ...)"

      # Pattern 3: 操作原生快取陣列（如 Int32Array, Float64Array）時，索引值直接使用外部變數且缺乏校驗
      - pattern: "$TYPED_ARRAY[$INPUT] = $VAL"

      # Pattern 4: 手動向 WebAssembly 導出的記憶體緩衝區（DataView）進行不安全寫入
      - pattern: "$VIEW.setUint32($INPUT, $VAL, ...)"
      - pattern: "$VIEW.setFloat64($INPUT, $VAL, ...)"

    message: "Out-of-bounds Write (CWE-787): The application writes data past the end, or before the beginning, of the intended buffer. In TypeScript, this manifests when manually managing byte offsets in Node.js Buffers, TypedArrays, or WebAssembly Shared Memory. Ensure all offset arguments and indices are strictly validated against buffer.length before writing."
    languages: [typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-787']

  - id: ts-path-traversal-cwe22
    pattern-either:
      # Pattern 1: fs 模組原生同步/非同步檔案讀取，直接使用字串拼接或樣板字串
      - pattern: $FS.readFile($X + $INPUT, ...)
      - pattern: $FS.readFile(`...${$INPUT}...`, ...)
      - pattern: $FS.readFileSync($X + $INPUT, ...)
      - pattern: $FS.readFileSync(`...${$INPUT}...`, ...)

      # Pattern 2: fs 模組檔案寫入/串流創建，其路徑直接受外部拼接控制
      - pattern: $FS.writeFile($X + $INPUT, ...)
      - pattern: $FS.writeFileSync($X + $INPUT, ...)
      - pattern: $FS.createReadStream($X + $INPUT, ...)
      - pattern: $FS.createWriteStream($X + $INPUT, ...)

      # Pattern 3: fs/promises 模組的非同步檔案讀寫操作拼接
      - pattern: $FSP.readFile($X + $INPUT, ...)
      - pattern: $FSP.writeFile($X + $INPUT, ...)

      # Pattern 4: path.join 或 path.resolve 僅做單純拼接，若無後續邊界檢查，依然屬於高風險 Path Traversal 特徵
      - pattern: path.join($DIR, $INPUT)
      - pattern: path.resolve($DIR, $INPUT)

    message: "Path Traversal (CWE-22): Untrusted input is dynamically concatenated into a file system path. This allows attackers to bypass intended access controls and read/write arbitrary files via relative path sequences (e.g., '../../'). Use path.basename(), sanizitation libraries, or strictly validate that the resolved path resides within the intended base directory."
    languages: [typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-22']

  - id: ts-use-after-free-cwe416
    pattern-either:
      # Pattern 1: 檔案描述符或系統 Stream 關閉/銷毀後，在後續程式碼中仍嘗試進行讀寫操作
      - pattern: |
          $STREAM.close(...);
          ...
          $STREAM.write(...);
      - pattern: |
          $STREAM.destroy(...);
          ...
          $STREAM.read(...);

      # Pattern 2: WebSocket 或 Socket 連線關閉/結束後，未清理引用便繼續發送資料
      - pattern: |
          $SOCKET.end(...);
          ...
          $SOCKET.write(...);

      # Pattern 3: 調用自訂或第三方 N-API/WASM 的記憶體釋放函數後，仍嘗試調用其操作方法
      - pattern: |
          $WASM_RESOURCE.free();
          ...
          $WASM_RESOURCE.$METHOD(...);
      - pattern: |
          $NATIVE_OBJ.destroy();
          ...
          $NATIVE_OBJ.update(...);

    message: "Use After Free (CWE-416): The application attempts to use a resource (such as a closed file descriptor, a destroyed stream, a closed socket, or a deallocated WebAssembly memory pointer) after it has been explicitly released. Ensure that all data access is guarded by state checks or that references are set to null immediately after release."
    languages: [typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-416']

  - id: ts-out-of-bounds-read-cwe125
    pattern-either:
      # Pattern 1: Buffer 讀取整數/浮點數時，偏移量直接受外部輸入影響，缺乏長度驗證
      - pattern: "$BUF.readUInt8($INPUT)"
      - pattern: "$BUF.readInt32LE($INPUT)"
      - pattern: "$BUF.readFloatBE($INPUT)"

      # Pattern 2: 使用 DataView 讀取底層 ArrayBuffer，且讀取的 byteOffset 受控
      - pattern: "$VIEW.getUint8($INPUT)"
      - pattern: "$VIEW.getInt32($INPUT, ...)"
      - pattern: "$VIEW.getFloat64($INPUT, ...)"

      # Pattern 3: 操作強型別快取陣列（如 Uint8Array）時，索引值直接使用外部變數且缺乏校驗
      - pattern: |
          $VAL = $TYPED_ARRAY[$INPUT];
      - pattern: |
          return $TYPED_ARRAY[$INPUT];

    message: "Out-of-bounds Read (CWE-125): The application allows user-controlled inputs to dictate memory offsets or indices when reading from a Node.js Buffer, DataView, or TypedArray. This can cause the application to crash via a RangeError (DoS) or unintentionally leak adjacent binary memory fragments. Always strictly validate that 'input < buffer.length' before reading."
    languages: [typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-125']

  - id: ts-command-injection-cwe78
    pattern-either:
      # Pattern 1 & 2: 使用命名空間或直接解構呼叫 exec / execSync (包含字串拼接與樣板字串)
      - pattern: "child_process.exec($X + $INPUT, ...)"
      - pattern: "child_process.exec(`...${$INPUT}...`, ...)"
      - pattern: "exec($X + $INPUT, ...)"
      - pattern: "exec(`...${$INPUT}...`, ...)"
      
      - pattern: "child_process.execSync($X + $INPUT, ...)"
      - pattern: "child_process.execSync(`...${$INPUT}...`, ...)"
      - pattern: "execSync($X + $INPUT, ...)"
      - pattern: "execSync(`...${$INPUT}...`, ...)"

      # Pattern 3: util.promisify(exec) 轉換後的任意非同步變數執行
      - pattern: "$EXEC_PROM($X + $INPUT, ...)"
      - pattern: "$EXEC_PROM(`...${$INPUT}...`, ...)"

      # Pattern 4: spawn / spawnSync 開啟危險的 shell: true 選項（用完整字串包裹，徹底修復 AST 崩潰問題）
      - pattern: "child_process.spawn($X + $INPUT, ..., { ..., shell: true, ... })"
      - pattern: "child_process.spawn(`...${$INPUT}...`, ..., { ..., shell: true, ... })"
      - pattern: "spawn($X + $INPUT, ..., { ..., shell: true, ... })"
      - pattern: "spawn(`...${$INPUT}...`, ..., { ..., shell: true, ... })"

    message: "OS Command Injection (CWE-78): Untrusted input is dynamically concatenated into an OS command execution function. This allows attackers to execute arbitrary shell commands with the privileges of the Node.js process. Avoid using exec/shell:true with concatenation; instead, use child_process.spawn or child_process.execFile with arguments passed as an array of strings."
    languages: [typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-78']

  - id: ts-code-injection-cwe94
    pattern-either:
      # Pattern 1: 全局 eval 函數內含不安全的字串拼接或樣板字串
      - pattern: eval($X + $INPUT)
      - pattern: eval(`...${$INPUT}...`)

      # Pattern 2: 使用 new Function 或是 Function 構造器動態生成程式碼，且內含外部輸入
      - pattern: new Function($X + $INPUT, ...)
      - pattern: new Function(..., $X + $INPUT)
      - pattern: new Function(`...${$INPUT}...`, ...)
      - pattern: new Function(..., `...${$INPUT}...`)
      - pattern: Function($X + $INPUT, ...)
      - pattern: Function(..., `...${$INPUT}...`)

      # Pattern 3: Node.js 核心安全沙箱 'vm' 模組的不安全動態腳本執行
      - pattern: $VM.runInContext($X + $INPUT, ...)
      - pattern: $VM.runInContext(`...${$INPUT}...`, ...)
      - pattern: $VM.runInNewContext($X + $INPUT, ...)
      - pattern: $VM.runInNewContext(`...${$INPUT}...`, ...)
      - pattern: $VM.runInThisContext($X + $INPUT, ...)
      - pattern: $VM.runInThisContext(`...${$INPUT}...`, ...)

      # Pattern 4: Node.js 'vm' 模組中，建立危險的 Script 對象時拼接了外部輸入
      - pattern: new $VM.Script($X + $INPUT, ...)
      - pattern: new $VM.Script(`...${$INPUT}...`, ...)

    message: "Improper Control of Generation of Code / Code Injection (CWE-94): Passing untrusted input into eval(), new Function(), or the 'vm' module allows attackers to execute arbitrary JavaScript/TypeScript code within the process context. Never pass user-controlled strings to these code-generation functions. Use safe alternatives such as JSON.parse() or a strict whitelist."
    languages: [typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-94']

  - id: ts-buffer-overflow-unchecked-copy-cwe120
    pattern-either:
      # Pattern 1: 不安全地使用 Buffer.copy() 進行區塊複製，且沒有在傳入前做長度檢查
      - pattern: "$SRC.copy($TARGET, ...)"

      # Pattern 2: 使用 TypedArray 的 .set() 批量寫入資料，直接丟入未經大小校驗的外部陣列或快取
      - pattern: "$TYPED_ARRAY.set($INPUT, ...)"

      # Pattern 3: 在固定大小的 Buffer 結構上呼叫 write()，且未指定或限制其寫入的長度上限（length 參數）
      - pattern: "$BUF.write($INPUT)"
      - pattern: "$BUF.write($INPUT, $OFFSET)"

      # Pattern 4: 自訂的快取寫入/複製函數中，在執行資料複製前，缺乏任何對來源與目標大小的比對邏輯
      - pattern: |
          function copyBuffer($SRC, $DEST, ...) {
            ...
            // 缺失對長度的安全檢驗
            ...
          }

    message: "Buffer Copy without Checking Size of Input (CWE-120): The application copies or writes an input buffer or array into a fixed-size target buffer (Node.js Buffer, TypedArray, or SharedArrayBuffer) without validating that the input size does not exceed the target allocation. This can trigger a runtime RangeError leading to Denial of Service (DoS) or cause native addon memory corruption. Always verify 'input.length <= target.length' before executing copies."
    languages: [typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-120']

  - id: ts-unrestricted-file-upload-cwe434
    pattern-either:
      # Pattern 1: Multer 配置中直接將不安全的原始檔名 (file.originalname) 作為儲存檔名，無任何副檔名檢查
      - pattern: "filename: (req, file, cb) => { ..., cb(null, file.originalname); }"
      - pattern: "filename: function(req, file, cb) { ..., cb(null, file.originalname); }"

      # Pattern 2: 在自訂的上傳路由或中間件中，直接拿 file.originalname 進行本地檔案寫入
      - pattern: "$FS.writeFile(..., $PATH + $REQ.file.originalname, ...)"
      - pattern: "$FS.writeFileSync(..., $PATH + $REQ.file.originalname, ...)"
      - pattern: "$FS.createWriteStream(..., $PATH + $REQ.file.originalname, ...)"

      # Pattern 3: NestJS 的 FileInterceptor 或 UploadedFile 的處理邏輯中，直接使用原始檔名進行儲存，缺乏副檔名白名單驗證
      - pattern: |
          @Post(...)
          @UseInterceptors(FileInterceptor(...))
          $METHOD(@UploadedFile() $FILE, ...) {
            ...
            $FS.writeFileSync(..., $FILE.originalname);
            ...
          }

    message: "Unrestricted Upload of File with Dangerous Type (CWE-434): The application allows users to upload files and retains their original extensions or names without strict server-side validation against a whitelist. This could enable an attacker to upload dangerous scripts (e.g., .js, .ts, .html) and execute them on the server or via clients' browsers. Always generate randomized file names, use standard mime-type checking, and validate file extensions strictly on the server side."
    languages: [typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-434']

  - id: ts-null-pointer-dereference-cwe476
    pattern-either:
      # Pattern 1: 使用 TypeScript 的非空斷言操作符（Non-null Assertion Operator !.）
      # 這等同於強行告訴編譯器「這絕對不是 null」，若運行時不幸為 null 就會引發崩潰
      - pattern: "$X!. $PROP"
      - pattern: "$X!. $METHOD(...)"

      # Pattern 2: 呼叫 Array.prototype.find() 後，在未檢查傳回值是否為 undefined 的情況下，直接連續存取屬性
      - pattern: "$ARR.find(...).$PROP"
      - pattern: "$ARR.find(...).$METHOD(...)"

      # Pattern 3: 對 Map.prototype.get() 的傳回值直接進行屬性解參照，而未校驗 key 是否真的存在
      - pattern: "$MAP.get(...).$PROP"
      - pattern: "$MAP.get(...).$METHOD(...)"

      # Pattern 4: 自訂函數的回傳型別明確包含 null/undefined，但在呼叫該函數後直接串接屬性
      - pattern: |
          function $FN(...): $TYPE | null { ... }
          ...
          $FN(...).$PROP
      - pattern: |
          function $FN(...): $TYPE | undefined { ... }
          ...
          $FN(...).$PROP

    message: "Null Pointer Dereference (CWE-476): The application attempts to dereference an object that can be null or undefined. Overusing the non-null assertion operator (!.) or bypassing checks on Array.find() / Map.get() outputs can lead to runtime TypeErrors and application crashes. Use optional chaining (?.) or explicit conditional checks instead."
    languages: [typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-476']

  - id: ts-stack-buffer-overflow-semantic-cwe121
    pattern-either:
      # Pattern 1: 在函式局部範疇中建立固定極小長度的 Buffer，並直接將未經長度校驗的外部輸入寫入
      - pattern: |
          function $FN(...) {
            ...
            const $BUF = Buffer.alloc($SIZE);
            ...
            $BUF.write($INPUT, ...);
            ...
          }

      # Pattern 2: 在局部範疇建立固定大小的 TypedArray，並直接使用 .set() 塞入未經檢查的外部資料
      - pattern: |
          function $FN(...) {
            ...
            const $TA = new Uint8Array($SIZE);
            ...
            $TA.set($INPUT, ...);
            ...
          }

      # Pattern 3: 函式內部存在自我遞迴呼叫（解構未知深度的外部輸入），且缺乏最大深度（Max Depth）的計數防禦器
      - pattern: |
          function $RECURSIVE($NODE, ...) {
            ...
            $RECURSIVE($NODE.$PROP, ...);
            ...
          }

    message: "Stack-based Buffer Overflow [Logical Mapping] (CWE-121): The application either allocates a fixed-size buffer in a local function scope and writes unvalidated inputs into it (causing a runtime RangeError), or performs unbounded deep recursion over untrusted nested data structures (causing a Maximum Call Stack Size Exceeded crash). Ensure local buffer writes are size-checked and recursive functions implement a maximum depth limit."
    languages: [typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-121']

  - id: ts-untrusted-deserialization-cwe502
    pattern-either:
      # Pattern 1: 使用不安全的 node-serialize 套件還原物件（支援函式還原與 IIFE 執行）
      - pattern: "nodeSerialize.unserialize($INPUT, ...)"
      - pattern: "unserialize($INPUT, ...)"

      # Pattern 2: 使用 js-yaml 進行高風險的 YAML 全功能還原
      - pattern: "yaml.load($INPUT, ...)"
      - pattern: "yaml.unsafeLoad($INPUT, ...)"
      - pattern: "load($INPUT, ...)"

      # Pattern 3: 使用 eval() 拼接括號來動態還原物件圖形（修正了前一版的引號閉合與語法衝突問題）
      - pattern: "eval('(' + $INPUT + ')')"
      - pattern: "eval(`(${$INPUT})`)"

    message: "Deserialization of Untrusted Data (CWE-502): Passing untrusted input to an unsafe deserialization function (like node-serialize.unserialize or unsafe YAML loaders) allows attackers to inject malicious objects and achieve Remote Code Execution (RCE). Use secure alternatives like JSON.parse() or configure strict, data-only schemas."
    languages: [typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-502']

  - id: ts-heap-buffer-overflow-semantic-cwe122
    pattern-either:
      # Pattern 1: 使用不安全的 allocUnsafe 於堆積分配空間，且後續的寫入操作限制長度（Length）或偏移量受外部非信任數據控制，導致未初始化記憶體外洩或邏輯溢位
      - pattern: "Buffer.allocUnsafe($SIZE)"
      - pattern: "Buffer.allocUnsafeSlow($SIZE)"

      # Pattern 2: 在手動維護的堆積物件池（Heap Object Pool）或陣列快取中，使用受控的索引進行賦值，缺乏長度與邊界檢查
      - pattern: "$POOL.set($INDEX, $OBJ)"
      - pattern: "$POOL_ARRAY[$INDEX] = $OBJ"

    message: "Heap-based Buffer Overflow [Semantic Mapping] (CWE-122): The application either allocates uninitialized memory blocks on the heap using Buffer.allocUnsafe() without fully clearing/overwriting the residual bytes (risking data leakage or out-of-bounds corruption), or manipulates a custom heap object pool using unvalidated indices. Always prefer Buffer.alloc() for safe heap allocation, and ensure all pool array assignments are bound-checked."
    languages: [typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-122']

  - id: ts-incorrect-authorization-cwe863
    pattern-either:
      # Pattern 1: 資料庫查詢/更新時，直接將前端傳入的 ID 當作唯一條件，完全沒有與當前 Session 或 JWT 的 user.id 進行比對
      - pattern: "$MODEL.findOne({ id: $REQ.params.id })"
      - pattern: "$MODEL.updateOne({ id: $REQ.params.id }, ...)"
      - pattern: "$MODEL.findByIdAndUpdate($REQ.body.id, ...)"

      # Pattern 2: 在自訂邏輯中，將物件擁有的所有者 ID 直接與前端傳入的參數做操作，而缺乏與當前登入者身分的校驗
      - pattern: |
          const $DATA = await $MODEL.findOne(...);
          ...
          // 漏洞特徵：直接執行敏感操作，中途完全沒有檢查 $DATA.ownerId === $REQ.user.id
          await $MODEL.deleteOne(...);

      # Pattern 3: 在 NestJS 等架構中，控制器方法包含管理員或敏感操作（如 delete/update），卻沒有掛載任何 @UseGuards() 或 @Roles() 權限防禦裝飾器
      - pattern: |
          @Delete(...)
          $METHOD(...) {
            ...
          }

    message: "Incorrect Authorization (CWE-863): The application performs an authorization check, but it does not correctly ensure that the logged-in user possesses the required privileges or ownership to access the requested resource. This often leads to Insecure Direct Object Reference (IDOR) vulnerabilities. Always validate that 'resource.ownerId === req.user.id' or enforce strict role-based access controls."
    languages: [typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-863']

  - id: ts-improper-input-validation-cwe20
    pattern-either:
      # Pattern 1: 外部輸入未經驗證，直接賦值給變數並用於動態物件屬性查找（原型污染/黑箱操作隱患）
      - pattern: |
          $VAR = $REQ.body;
          ...
          $OBJ[$VAR]
      - pattern: |
          $VAR = $REQ.query;
          ...
          $OBJ[$VAR]

      # Pattern 2: 使用外部輸入動態拼接建立不安全的正規表達式（用引號包裹，修正 Regex 引擎解析問題）
      - pattern: "new RegExp($X + $INPUT)"
      - pattern: "new RegExp(`...${$INPUT}...`)"
      - pattern: "new RegExp($INPUT)"

      # Pattern 3: 在 Express/Nest 中，直接將非信任的 query 或是 body 參數未加校驗直接丟入重定向
      - pattern: "res.redirect($REQ.query.$PARAM)"
      - pattern: "res.redirect($REQ.body.$PARAM)"

    message: "Improper Input Validation (CWE-20): The application receives untrusted input and uses it without prior validation, or uses a flawed regex validation pattern that can be bypassed. This can lead to open redirection, Prototype Pollution, or parameter injection. Always validate inputs using schema libraries like Zod or ensure rigorous boundary/format constraints."
    languages: [typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-20']

  - id: ts-improper-access-control-cwe284
    pattern-either:
      # Pattern 1: CORS 中間件配置過於寬鬆，將 Origin 設為 * 或允許任意網域
      - pattern: "cors({ origin: '*' })"
      - pattern: "cors({ origin: true })"
      - pattern: "res.setHeader('Access-Control-Allow-Origin', '*')"

      # Pattern 2: Express 路由配置中，敏感 API 端點（如包含 admin/config/delete）完全沒有掛載認證/授權檢查函式
      - pattern: "app.get('/admin/...', $METHOD)"
      - pattern: "router.post('/config/...', $METHOD)"

      # Pattern 3: NestJS 控制器中，敏感的端點或整個 Class 上暴露，卻缺乏身分驗證 Guard 的攔截
      - pattern: |
          @Controller('admin')
          class $CLASS {
            ...
          }

    message: "Improper Access Control (CWE-284): The application fails to restrict access to sensitive resources or endpoints properly. Setting CORS origins to '*' or allowing wildcard API routes without authentication/authorization layers exposes internal services to unauthorized cross-origin or external access. Always enforce explicit Guard/Middleware chains and limit CORS scopes."
    languages: [typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-284']

  - id: ts-sensitive-information-exposure-cwe200
    pattern-either:
      # Pattern 1: 在 catch 區塊中，直接將捕獲的錯誤堆疊 (error.stack) 或原始錯誤物件當作響應內文回傳給用戶
      - pattern: "res.send($ERR.stack)"
      - pattern: "res.json({ ..., error: $ERR, ... })"
      - pattern: "res.status(...).send($ERR)"

      # Pattern 2: 直接回傳包含敏感欄位名稱（如明示的 password, secret, token）的物件或全域變數
      - pattern: "res.json({ ..., password: $PASS, ... })"
      - pattern: "res.send({ ..., secret: $SEC, ... })"

      # Pattern 3: 在自訂日誌（如 console.log/error）或外部傳輸中，直接將環境變數 (process.env) 完整傾印
      - pattern: "console.log(process.env)"
      - pattern: "res.send(process.env)"

    message: "Exposure of Sensitive Information to an Unauthorized Actor (CWE-200): The application leaks sensitive data (such as raw error stacks, environment variables, or password fields) in HTTP responses or verbose logs. This information can assist attackers in mapping the internal infrastructure or bypassing access controls. Sanitize all output data and use explicit view models or validation schemas."
    languages: [typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-200']

  - id: ts-missing-authentication-cwe306
    pattern-either:
      # Pattern 1: Express 路由中，關鍵敏感路徑（如 /checkout, /payment, /password）直接綁定回呼函式，完全沒有掛載任何認證中間件
      - pattern: "app.post('/api/checkout', $METHOD)"
      - pattern: "router.post('/user/change-password', $METHOD)"
      - pattern: "app.put('/api/payment/...', $METHOD)"

      # Pattern 2: NestJS 控制器中，涉及敏感功能的方法（如含有 password, payment, checkout 字樣），其上方完全沒有任何 @UseGuards() 裝飾器
      - pattern: |
          @Post($PATH)
          $METHOD(...) {
            ...
            $X.changePassword(...);
            ...
          }
      - pattern: |
          @Post($PATH)
          $METHOD(...) {
            ...
            $X.processPayment(...);
            ...
          }

    message: "Missing Authentication for Critical Function (CWE-306): The application executes a critical function (such as changing passwords, processing payments, or checking out) without verifying the identity of the actor. Ensure that appropriate authentication middleware (e.g., passport.authenticate()) or NestJS AuthGuards are strictly enforced on these endpoints."
    languages: [typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-306']

  - id: ts-ssrf-untrusted-request-cwe918
    pattern-either:
      # Pattern 1: 使用 axios 進行不安全的 URL 拼接，直接接受非信任輸入作為請求目標
      - pattern: "axios.get($X + $INPUT, ...)"
      - pattern: "axios.get(`...${$INPUT}...`, ...)"
      - pattern: "axios.post($X + $INPUT, ...)"
      - pattern: "axios.post(`...${$INPUT}...`, ...)"
      - pattern: "axios($X + $INPUT, ...)"
      - pattern: "axios(`...${$INPUT}...`, ...)"

      # Pattern 2: 使用 axios.request 設定物件時，將 url 屬性直接指派為受控的拼接字串
      - pattern: "axios.request({ ..., url: $X + $INPUT, ... })"
      - pattern: "axios.request({ ..., url: `...${$INPUT}...`, ... })"

      # Pattern 3: 使用 node-fetch 或原生 fetch 進行不安全的動態 URL 請求
      - pattern: "fetch($X + $INPUT, ...)"
      - pattern: "fetch(`...${$INPUT}...`, ...)"

    message: "Server-Side Request Forgery (SSRF) (CWE-918): The application constructs a server-side HTTP request URL by concatenating untrusted user input directly. This allows external attackers to force the server to make unauthorized requests to internal resources, private networks, or cloud metadata endpoints (e.g., 169.254.169.254). Always validate inputs against a strict whitelist of allowed domains or use explicit URL parsing to restrict destinations."
    languages: [typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-918']

  - id: ts-command-injection-child-process-cwe77
    pattern-either:
      # Pattern 1: 使用 child_process.exec 進行不安全的字串拼接命令執行
      - pattern: "child_process.exec($X + $INPUT, ...)"
      - pattern: "child_process.exec(`...${$INPUT}...`, ...)"
      - pattern: "exec($X + $INPUT, ...)"
      - pattern: "exec(`...${$INPUT}...`, ...)"

      # Pattern 2: 使用 child_process.execSync 同步執行的不安全拼接特徵
      - pattern: "child_process.execSync($X + $INPUT, ...)"
      - pattern: "child_process.execSync(`...${$INPUT}...`, ...)"
      - pattern: "execSync($X + $INPUT, ...)"
      - pattern: "execSync(`...${$INPUT}...`, ...)"

      # Pattern 3: 在 spawn 或 execFile 中，錯誤地將 shell 選項設為 true，並透過字串拼接引數，將引數提權為指令執行
      - pattern: "child_process.spawn($CMD + $INPUT, ..., {..., shell: true, ...})"
      - pattern: "child_process.spawn(`...${$INPUT}...`, ..., {..., shell: true, ...})"
      - pattern: "spawn($CMD + $INPUT, ..., {..., shell: true, ...})"
      - pattern: "spawn(`...${$INPUT}...`, ..., {..., shell: true, ...})"

    message: "Improper Neutralization of Special Elements used in a Command ('Command Injection') (CWE-77): The application constructs an OS command by directly concatenating untrusted user input into child_process.exec or shell-enabled spawn functions. This allows malicious actors to execute arbitrary system commands with the privileges of the Node.js process. Always pass arguments as an array using safe APIs like child_process.execFile or child_process.spawn with shell: false."
    languages: [typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-77']

  - id: ts-idor-user-controlled-key-cwe639
    pattern-either:
      # Pattern 1: 資料庫或資料層查詢時，直接將前端可控的 params/body 鍵值作為對象直接查詢，且過濾條件中完全缺乏當前 req.user 的身分綁定
      - pattern: "$REPO.findOne({ where: { id: $REQ.params.$KEY } })"
      - pattern: "$REPO.find({ accountNumber: $REQ.body.$KEY })"
      - pattern: "$MODEL.findById($REQ.query.$KEY)"

      # Pattern 2: 在敏感操作（如刪除、更新）時，直接拿用戶傳入的 Key 進行就地異動，未檢查該資源的權限歸屬
      - pattern: "$MODEL.destroy({ where: { id: $REQ.params.$KEY } })"
      - pattern: "$MODEL.findOneAndUpdate({ _id: $REQ.body.$KEY }, ...)"

    message: "Authorization Bypass Through User-Controlled Key (CWE-639): The application uses an actor-controlled key to access a resource without verifying that the actor has permission to access that specific resource. This leads to Insecure Direct Object Reference (IDOR). Always chain the user identity identifier (e.g., req.user.id) to the query filter or perform explicit authorization mapping."
    languages: [typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-639']

  - id: ts-uncontrolled-resource-allocation-cwe770
    pattern-either:
      # Pattern 1: 直接將前端非信任的參數直接傳入 Buffer 分配函數，極易導致 OOM 崩潰
      - pattern: "Buffer.alloc($REQ.body.$PARAM)"
      - pattern: "Buffer.alloc($REQ.query.$PARAM)"
      - pattern: "new Array($REQ.body.$PARAM)"

      # Pattern 2: 在高開銷的路由（如涉及 /login, /forgot-password, /upload）配置中，連續定義了處理器卻在整條鏈路或全域遺漏了速率限制中間件（Rate Limiter）
      # 此特徵主要捕捉缺乏防護的高危險端點
      - pattern: "app.post('/api/login', $METHOD)"
      - pattern: "router.post('/api/sms/send', $METHOD)"

      # Pattern 3: 動態創立大量的定時器（setTimeout / setInterval）且計時長度受外部參數完全控制
      - pattern: "setTimeout($FN, $REQ.body.$PARAM)"
      - pattern: "setInterval($FN, $REQ.query.$PARAM)"

    message: "Allocation of Resources Without Limits or Throttling (CWE-770): The application allocates memory, limits timers, or exposes high-cost API endpoints without proper restriction or throttling. Attackers can leverage this to exhaust system memory (OOM) or flood services, leading to Denial of Service (DoS). Always enforce explicit maximum boundary checks on allocations and integrate rate-limiting middleware."
    languages: [typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-770']

  - id: ts-improper-authentication-cwe287
    pattern-either:
      # Pattern 1: 在身份認證或金鑰核對邏輯中，錯誤使用非嚴格相等 (== 或 !=) 進行密碼/Token 比對，易遭弱型別繞過
      - pattern: "if ($SECRET == $INPUT) { ... }"
      - pattern: "if ($SECRET != $INPUT) { ... }"

      # Pattern 2: 自訂認證中間件中，當捕獲到認證失敗或空值時，漏掉了 return 語句，導致後續的 next() 依然被執行，等同繞過認證
      - pattern: |
          if (!$REQ.headers.$AUTH) {
            $RES.status(401);
            next();
          }
      - pattern: |
          if (!$REQ.headers.$AUTH) {
            $RES.sendStatus(401);
            next();
          }

      # Pattern 3: 在 JWT 驗證邏輯中，配置了不安全的選項（例如允許 'none' 演算法或完全不驗證簽章）
      - pattern: "jwt.verify($TOKEN, $KEY, { algorithms: [..., 'none', ...] })"
      - pattern: "jwt.decode($TOKEN)"

    message: "Improper Authentication (CWE-287): The application fails to perform proper authentication before performing a restricted action. This can stem from weak type comparison during credentials check, missing early return statements in auth middleware leading to execution bypass, or using unsafe JWT configurations like decoding without verification or allowing the 'none' algorithm."
    languages: [typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-287']

  - id: ts-improper-privilege-management-cwe269
    pattern-either:
      # Pattern 1: 系統底層權限切換時，直接傳入外部非信任輸入作為 UID 或 GID，導致任意提權漏洞
      - pattern: "process.setuid($REQ.body.$PARAM)"
      - pattern: "process.setuid($REQ.query.$PARAM)"
      - pattern: "process.setgid($REQ.body.$PARAM)"

      # Pattern 2: 批量賦值 (Mass Assignment) 漏洞：直接將前端 body 物件未經清洗直接指派給使用者的權限屬性，或直接寫入資料庫
      - pattern: "Object.assign($USER, $REQ.body)"
      - pattern: "$MODEL.update($REQ.body, ...)"
      - pattern: "$MODEL.findByIdAndUpdate(..., $REQ.body, ...)"

      # Pattern 3: 在自訂提權、裝飾器或邏輯中，將不安全的任意布林參數值直接用於設定 isAdmin 或 role 等核心特權欄位
      - pattern: "$USER.isAdmin = $REQ.body.$PARAM"
      - pattern: "$USER.role = $REQ.body.$PARAM"

    message: "Improper Privilege Management (CWE-269): The application improperly manages privileges, allowing untrusted inputs to control system-level identities (setuid), causing Mass Assignment vulnerabilities where users can elevate their own roles (e.g., overriding 'role' or 'isAdmin'), or directly assigning unvalidated roles. Always strictly sanitize input data against a strict whitelist before object assignment or database entry."
    languages: [typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-269']

  - id: ts-buffer-bounds-restriction-cwe119
    pattern-either:
      # Pattern 1: 在未初始化的不安全 Buffer 上執行寫入操作，且其偏移量或長度直接受外部非信任數據控制，缺乏邊界檢查
      - pattern: "$BUF.write($INPUT, $OFFSET, $LENGTH, ...)"
      - pattern: "$BUF.write($INPUT, $OFFSET, ...)"

      # Pattern 2: 在 Buffer 複製操作 (copy) 中，目標起點、來源起點或複製長度直接套用外部參數
      - pattern: "$SRC_BUF.copy($TARGET_BUF, $TARGET_START, $SRC_START, $SRC_END)"
      - pattern: "$SRC_BUF.copy($TARGET_BUF, $TARGET_START, ...)"

      # Pattern 3: 對記憶體緩衝區進行子檢視切片 (subarray) 時，偏移量參數直接受前端控制，可能導致邏輯邊界破壞或越界讀取
      - pattern: "$BUF.subarray($START, $END)"
      - pattern: "$BUF.slice($START, $END)"

    message: "Improper Restriction of Operations within the Bounds of a Memory Buffer (CWE-119): The application performs operations on a Buffer instance where the offset, length, or slicing indices are driven by untrusted input. In Node.js/TypeScript, while this cannot cause a classic machine-level core dump, it can lead to Out-of-Bounds logical reads (leaking raw heap memory segments containing passwords/keys) or process crashes due to RangeError. Always enforce strict validation on offset and length parameters."
    languages: [typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-119']

  - id: ts-hardcoded-credentials-cwe798
    pattern-either:
      # Pattern 1: 常見的密碼、金鑰、私鑰變數被直接賦值為非空的明文字串常值
      - pattern: "const $PASS = \\"...\\";"
      - pattern: "let $SECRET = \\"...\\";"
      - pattern: "var $KEY = \\"...\\";"

      # Pattern 2: 在初始化資料庫連接、金鑰配置或 JWT 驗證時，直接將參數欄位寫死為字串
      - pattern: "jwt.verify($T, \\"...\\", ...)"
      - pattern: "new DataSource({ ..., password: \\"...\\", ... })"
      - pattern: "createConnection({ ..., password: \\"...\\", ... })"

      # Pattern 3: 物件或字典型態的配置檔案中，將敏感認證欄位直接硬編碼
      - pattern: "const $CONF = { ..., secret: \\"...\\", ... };"
      - pattern: "const $CONF = { ..., password: \\"...\\", ... };"

    message: "Use of Hard-coded Credentials (CWE-798): The application uses a hard-coded credential, such as a password, an encryption key, or an API secret. This makes it easy for attackers to compromise the system if they gain access to the source code. Always transfer credentials into external environment variables (process.env) or a secure secrets manager."
    languages: [typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-798']

  - id: ts-integer-overflow-typedarray-cwe190
    pattern-either:
      # Pattern 1: 在處理固定位元組的 TypedArray（如 Uint8Array, Int32Array）時，將受前端控制的相加或相乘運算直接寫入，易造成二進位截斷溢位
      - pattern: "new Uint8Array($REQ.body.$PARAM + $X)"
      - pattern: "new Int32Array($REQ.query.$PARAM * $X)"
      - pattern: "$TYPED_ARRAY[$INDEX] = $REQ.body.$PARAM + $X"

      # Pattern 2: 在 Buffer 分配、寫入或複製的長度/偏移量計算中，直接對前端傳入的參數進行算術運算而未經安全整數邊界校驗
      - pattern: "Buffer.alloc($REQ.body.$PARAM + $X)"
      - pattern: "$BUF.write($STR, $REQ.query.$OFFSET + $X)"

      # Pattern 3: 在大數計算、計費或迴圈邊界中，直接進行累加/累乘，且完全沒有校驗 Number.MAX_SAFE_INTEGER
      - pattern: |
          let $AMOUNT = $REQ.body.$PARAM;
          ...
          $AMOUNT += $X; // 缺乏邊界檢查的累加
    message: "Integer Overflow or Wraparound (CWE-190): The application performs arithmetic operations on untrusted inputs before allocating memory buffers, slicing arrays, or assigning values to strict container types like TypedArrays (e.g., Uint8Array). While native TypeScript numbers are float64 and lose precision rather than wrap around, underlying TypedArrays and Buffer boundaries will suffer wrap-around truncation or cause logical bypasses. Always validate inputs against 'Number.MAX_SAFE_INTEGER' and enforce maximum boundary checks."
    languages: [typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-190']

  - id: ts-uncontrolled-resource-consumption-cwe400
    pattern-either:
      # Pattern 1: ReDoS 漏洞 - 將前端不可信的輸入直接編譯為 RegExp 或直接用於正則匹配方法
      - pattern: "new RegExp($REQ.query.$PARAM, ...)"
      - pattern: "new RegExp($REQ.body.$PARAM, ...)"
      - pattern: "$STR.match($REQ.body.$PARAM)"
      - pattern: "$STR.search($REQ.query.$PARAM)"

      # Pattern 2: 迴圈迭代次數完全受控於外部輸入，且缺乏上限檢查，易導致 CPU 資源耗盡 (DoS)
      - pattern: |
          for (let $I = 0; $I < $REQ.body.$PARAM; $I++) {
            ...
          }
      - pattern: |
          while ($X < $REQ.query.$PARAM) {
            ...
            $X++;
          }

    message: "Uncontrolled Resource Consumption (CWE-400): The application does not properly control the consumption of CPU or execution time. Compiling dynamic text into RegExp without sanitization leads to Regular Expression Denial of Service (ReDoS). Running loops directly bounded by client inputs without a maximum limit blocks the single-threaded event loop. Always validate and enforce strict maximum thresholds."
    languages: [typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-400']

  - id: ts-hidden-functionality-backdoor-cwe912
    pattern-either:
      # Pattern 1: 利用後門請求標頭或參數，隱蔽且直接地觸發動態指令代碼執行 (eval / exec)
      - pattern: "if ($REQ.headers.$HEADER) { eval($REQ.headers.$HEADER); }"
      - pattern: "if ($REQ.query.$PARAM) { exec($REQ.query.$PARAM, ...); }"

      # Pattern 2: 硬編碼秘密萬能鑰匙，透過特定的特殊常值字串直接跳過密碼與身分驗證
      - pattern: "if ($INPUT === \\"...\\") { return true; }"
      - pattern: "if ($USER === \\"...\\") { $SESSION.isAdmin = true; }"

      # Pattern 3: 邏輯炸彈 (Logic Bomb) 特徵 - 秘密檢查特定的日期（如時間戳或特定年份）或秘密條件來觸發敏感操作
      - pattern: "if (new Date().getFullYear() === $YEAR) { ... }"
      - pattern: "if (Date.now() > $TIMESTAMP) { ... }"

    message: "Hidden Functionality / Backdoor (CWE-912): The application contains hidden functionality, hard-coded super-user bypass mechanisms, or logic bombs that execute restricted code based on undocumented trigger inputs (e.g., custom headers, magic strings, or specific timestamps). This poses an extreme risk of full system compromise. Audit all short-circuit logic and restrict dynamic execution APIs."
    languages: [typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-912']

  - id: ts-untrusted-module-inclusion-cwe829
    pattern-either:
      # Pattern 1: 使用不安全的明文 HTTP 協定網路路徑動態載入外部腳本或內容
      - pattern: "axios.get(\\"http://...\\")"
      - pattern: "fetch(\\"http://...\\")"

      # Pattern 2: 使用受外部前端參數控制的字串動態執行 require() 或 import()，導致載入惡意本機或網路模組
      - pattern: "require($REQ.body.$PARAM)"
      - pattern: "require($REQ.query.$PARAM)"
      - pattern: "import($REQ.body.$PARAM)"

      # Pattern 3: 從系統公共可讀寫的暫存目錄（如 /tmp）載入可能被惡意篡改或預先植入的模組檔
      - pattern: "require(\\"/tmp/...\\")"
      - pattern: "import(\\"/tmp/...\\")"

    message: "Inclusion of Functionality from Untrusted Control Sphere (CWE-829): The application imports or executes code from an untrusted sphere, such as plain HTTP remote sources, fully user-controlled dynamic module paths, or shared temporary directories (/tmp). This can lead to Remote Code Execution (RCE) or malicious dependency hijacking. Ensure all imported code comes from trusted, verified, and immutable repositories, and validate dynamic paths against a strict whitelist."
    languages: [typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-829']

  - id: ts-prototype-pollution-cwe1321
    pattern-either:
      # Pattern 1: 不安全的動態屬性指派，直接透過未經過濾的鍵值（如 req.body 傳入的鍵）寫入物件，最常見於自定義的 merge 或 path setter
      - pattern: "$OBJ[$KEY] = $VALUE"
      - pattern: "$OBJ[$KEY][$SUBKEY] = $VALUE"

      # Pattern 2: 遞迴合併（Recursive Merge）或克隆函式中，直接將來源物件的屬性無條件複製到目標物件中，且完全沒有檢查 __proto__ 或 constructor
      - pattern: |
          for (let $K in $SRC) {
            ...
            $TARGET[$K] = $SRC[$K];
          }
      - pattern: |
          for (let $K of Object.keys($SRC)) {
            ...
            $TARGET[$K] = $SRC[$K];
          }

    message: "Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution') (CWE-1321): The application recursively merges or assigns properties to an object using untrusted keys without filtering dangerous attributes such as '__proto__' or 'constructor.prototype'. This allows attackers to inject arbitrary properties into the global Object.prototype, leading to denial of service, authorization bypass, or remote code execution. Always implement a strict blocklist for dangerous keys or use Object.create(null) for data-holding dictionaries."
    languages: [typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-1321']

  - id: ts-improper-certificate-verification-cwe295
    pattern-either:
      # Pattern 1: 透過全域環境變數 NODE_TLS_REJECT_UNAUTHORIZED 停用整個 Node.js 行程的 TLS 憑證驗證
      - pattern: "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'"
      - pattern: "process.env.NODE_TLS_REJECT_UNAUTHORIZED = \\"0\\""

      # Pattern 2: 在建立 https.Agent 或 tls.connect 時，將 rejectUnauthorized 屬性設為 false
      - pattern: "new https.Agent({ ..., rejectUnauthorized: false, ... })"
      - pattern: "tls.connect({ ..., rejectUnauthorized: false, ... }, ...)"

      # Pattern 3: 在 Axios 或其他 HTTP 套件的請求配置中，就地停用憑證驗證
      - pattern: "axios.get($URL, { ..., rejectUnauthorized: false, ... })"
      - pattern: "axios.post($URL, $DATA, { ..., rejectUnauthorized: false, ... })"

    message: "Improper Certificate Verification (CWE-295): The application explicitly disables TLS/SSL certificate verification by setting 'rejectUnauthorized: false' or 'NODE_TLS_REJECT_UNAUTHORIZED = 0'. This makes the application highly vulnerable to Man-in-the-Middle (MITM) attacks, allowing attackers to intercept or modify encrypted traffic. Never disable certificate validation in production."
    languages: [typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-295']

  - id: ts-weak-hash-algorithm-cwe328
    pattern-either:
      # Pattern 1: 使用 Node.js 內建 crypto 模組直接建立不安全的 MD5 或 SHA1 雜湊實例
      - pattern: "crypto.createHash('md5')"
      - pattern: "crypto.createHash(\\"md5\\")"
      - pattern: "crypto.createHash('sha1')"
      - pattern: "crypto.createHash(\\"sha1\\")"

      # Pattern 2: 在建立 HMAC (Hash-based Message Authentication Code) 時使用了弱雜湊演算法
      - pattern: "crypto.createHmac('md5', ...)"
      - pattern: "crypto.createHmac(\\"md5\\", ...)"
      - pattern: "crypto.createHmac('sha1', ...)"
      - pattern: "crypto.createHmac(\\"sha1\\", ...)"

    message: "Use of Weak Hash (CWE-328): The application uses a weak or broken cryptographic hash algorithm (such as MD5 or SHA-1) which is vulnerable to collision attacks. Do not use MD5 or SHA-1 for security-sensitive contexts like password hashing, digital signatures, or integrity checks. Upgrade to secure alternatives like SHA-256 (crypto.createHash('sha256')) or memory-hard functions like Argon2 / bcrypt for passwords."
    languages: [typescript]
    severity: ERROR
    metadata:
      cwe: ['CWE-328']
"""

# ══════════════════════════════════════════════════════════════
# 9. 寫入 YAML 檔案與輸出報告
# ══════════════════════════════════════════════════════════════
with open("rules/python.yml", "w", encoding="utf-8", newline="\n") as f:
    f.write(py_rules)

with open("rules/javascript.yml", "w", encoding="utf-8", newline="\n") as f:
    f.write(js_rules)

with open("rules/java.yml", "w", encoding="utf-8", newline="\n") as f:
    f.write(java_rules)

with open("rules/cpp.yml", "w", encoding="utf-8", newline="\n") as f:
    f.write(cpp_rules)

with open("rules/c.yml", "w", encoding="utf-8", newline="\n") as f:
    f.write(c_rules)

with open("rules/csharp.yml", "w", encoding="utf-8", newline="\n") as f:
    f.write(cs_xss_rules)

with open("rules/php.yml", "w", encoding="utf-8", newline="\n") as f:
    f.write(php_rules)

with open("rules/typescript.yml", "w", encoding="utf-8", newline="\n") as f:
    f.write(ts_rules)

# 💡 全自動計算核心：利用動態計算字串中規則 id 的數量，免去開頭手動維護 stats 的負擔！
# 同時建立對應結構，完美符合原本尾段的變數讀取
stats = {
    "python": {
        "existing": [i for i in range(py_rules.count("  - id:"))],
        "added_or_modified": []
    },
    "javascript": {
        "existing": [i for i in range(js_rules.count("  - id:"))],
        "added_or_modified": []
    },
    "java": {
        "existing": [i for i in range(java_rules.count("  - id:"))],
        "added_or_modified": []
    },
    "cpp": {
        "existing": [i for i in range(cpp_rules.count("  - id:"))],
        "added_or_modified": []
    },
    "c": {
        "existing": [i for i in range(c_rules.count("  - id:"))],
        "added_or_modified": []
    },
    "csharp": {
        "existing": [i for i in range(cs_xss_rules.count("  - id:"))],
        "added_or_modified": []
    },
    "php": {
        "existing": [i for i in range(php_rules.count("  - id:"))],
        "added_or_modified": []
    },
    "typescript": {
        "existing": [i for i in range(ts_rules.count("  - id:"))],
        "added_or_modified": []
    }
}

# 計算各語言目前的規則總數
total_py_rules = len(stats['python']['existing']) + len(stats['python']['added_or_modified'])
total_js_rules = len(stats['javascript']['existing']) + len(stats['javascript']['added_or_modified'])
total_java_rules = len(stats['java']['existing']) + len(stats['java']['added_or_modified'])
total_cpp_rules = len(stats['cpp']['existing']) + len(stats['cpp']['added_or_modified'])
total_c_rules = len(stats['c']['existing']) + len(stats['c']['added_or_modified'])
total_cs_rules = len(stats['csharp']['existing']) + len(stats['csharp']['added_or_modified'])
total_php_rules = len(stats['php']['existing']) + len(stats['php']['added_or_modified'])
total_ts_rules = len(stats['typescript']['existing']) + len(stats['typescript']['added_or_modified'])

print("=" * 60)
print("🚀 Semgrep 規則資料庫與檔案建立成功！")
print("=" * 60)
print(f"📊 [Python 規則集 (python.yml)]       目前總共：{total_py_rules} 條規則")
print(f"📊 [JavaScript 規則集 (javascript.yml)] 目前總共：{total_js_rules} 條規則")
print(f"📊 [Java 規則集 (java.yml)]           目前總共：{total_java_rules} 條規則")
print(f"📊 [C/C++ 規則集 (cpp.yml)]           目前總共：{total_cpp_rules} 條規則 284,502有問題")
print(f"📊 [C 規則集 (c.yml)]                 目前總共：{total_c_rules} 條規則")
print(f"📊 [C# 規則集 (cs.yml)]               目前總共：{total_cs_rules} 條規則")
print(f"📊 [PHP 規則集 (php.yml)]             目前總共：{total_php_rules} 條規則")
print(f"📊 [TypeScript 規則集 (typescript.yml)] 目前總共：{total_ts_rules} 條規則")
print("=" * 60)
