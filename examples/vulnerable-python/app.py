"""Intentionally vulnerable Flask application for security testing."""

import os
import pickle
import sqlite3
from flask import Flask, request, render_template_string

app = Flask(__name__)


# SQL Injection vulnerability
@app.route('/user/<user_id>')
def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # VULNERABLE: SQL injection via string formatting
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    return str(user)


# Command Injection vulnerability
@app.route('/ping')
def ping_host():
    host = request.args.get('host', 'localhost')
    # VULNERABLE: Command injection via os.system
    os.system(f"ping {host}")
    return f"Pinged {host}"


# Another command injection variant
@app.route('/lookup')
def dns_lookup():
    domain = request.args.get('domain')
    # VULNERABLE: Command injection via subprocess with shell=True
    import subprocess
    result = subprocess.check_output(f"nslookup {domain}", shell=True)
    return result


# Insecure deserialization
@app.route('/load-session', methods=['POST'])
def load_session():
    user_data = request.get_data()
    # VULNERABLE: Arbitrary code execution via pickle
    session = pickle.loads(user_data)
    return f"Session loaded: {session}"


# XSS vulnerability
@app.route('/greet')
def greet():
    name = request.args.get('name', 'Guest')
    # VULNERABLE: Reflected XSS via template string
    return render_template_string(f"<h1>Hello, {name}!</h1>")


# Path traversal vulnerability
@app.route('/read-file')
def read_file():
    filename = request.args.get('file')
    # VULNERABLE: Path traversal
    with open(f"./uploads/{filename}", 'r') as f:
        return f.read()


# Hardcoded credentials in code
def connect_to_admin_db():
    # VULNERABLE: Hardcoded password
    return sqlite3.connect('admin.db', password='admin123')


if __name__ == '__main__':
    # VULNERABLE: Debug mode in production code
    app.run(debug=True, host='0.0.0.0')
