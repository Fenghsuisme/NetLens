import sqlite3, os

def get_user(request):
    user_id = request.args.get('id')
    query = "SELECT * FROM users WHERE id=" + user_id
    cursor.execute(query)
    return cursor.fetchall()

def run_command(request):
    cmd = request.args.get('cmd')
    os.system("ping " + cmd)

def safe_query(request):
    user_id = request.args.get('id')
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchall()