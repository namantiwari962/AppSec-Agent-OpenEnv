import sqlite3

def init_db():
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    cursor.execute("INSERT INTO users (username, password) VALUES ('admin', 'secretpass')")
    cursor.execute("INSERT INTO users (username, password) VALUES ('user', 'userpass')")
    conn.commit()
    return conn

def login(conn, username, password):
    cursor = conn.cursor()
    # Vulnerable SQL query (SQLi)
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    try:
        cursor.execute(query)
        user = cursor.fetchone()
        if user:
            return True
        return False
    except sqlite3.Error:
        return False

def render_profile(username):
    # Vulnerable Cross-Site Scripting (XSS)
    return f"<h1>Welcome to your profile, {username}!</h1>"

def read_file(filename):
    # Vulnerable Path Traversal / Local File Inclusion (LFI)
    base_dir = "public/"
    file_path = base_dir + filename
    try:
        with open(file_path, "r") as f:
            return f.read()
    except FileNotFoundError:
        return "File not found."
