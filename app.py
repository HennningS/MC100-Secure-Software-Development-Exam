from flask import Flask, request, jsonify, g, render_template, session, redirect, url_for
from flask_session import Session
import sqlite3
import bcrypt
from flask_httpauth import HTTPBasicAuth
import secrets 
from datetime import datetime, timedelta

app = Flask(__name__)

DATABASE = 'user_database.db'
auth = HTTPBasicAuth()

class PasswordManager:

    def __init__(self, DATABASE):
        self.conn = sqlite3.connect(DATABASE)
        self.cursor = self.conn.cursor()
        self.create_table()
        
    def create_table(self):
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                hashed_password TEXT NOT NULL,
                api_key TEXT UNIQUE NOT NULL 
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS reset_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                token TEXT UNIQUE NOT NULL,
                expires_at TEXT NOT NULL,
                used INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(username) REFERENCES users(username)
            )
        ''')
        conn.commit()
        conn.close()

    def register_user(self, username, password):
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

        #Generate secure API key:
        api_key = secrets.token_hex(32) # Generate a 32-character long hexadesimal string
        hashed_api_key = bcrypt.hashpw(api_key.encode(), bcrypt.gensalt())

        cursor.execute("INSERT INTO users (username, hashed_password, api_key) VALUES (?, ?, ?)", (username, hashed_password, hashed_api_key))

        conn.commit()
        conn.close()

        print(f"User '{username}' registered with API Key: {api_key}")
        return api_key


    @auth.verify_password
    def verify_user(self, username, password):
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("SELECT hashed_password FROM users WHERE username=?", (username,))
        user = cursor.fetchone()
        conn.close()
        if user and bcrypt.checkpw(password.encode(), user[0]): #user has been found and the the password is correct
            print("Password matches!")
            return True
        else:
            print("Password doesn't match.")
            return False

    def create_reset_token(self, username):
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM users WHERE username= ?", (username,))
        exists = cursor.fetchone()
        if not exists:
            conn.close()
            return None
        token = secrets.token_urlsafe(32) #Creates a 32-character long token for the URL
        expires_at = (datetime.utcnow() + timedelta(hours=1)).isoformat() #Set the token time to 1 hour
        cursor.execute(
            "INSERT INTO reset_tokens (username, token, expires_at, used) VALUES (?, ?, ?, 0)",
            (username, token, expires_at)
        )
        conn.commit()
        conn.close()
        print(f"Created reset token for '{username}' (expires in 1 hour)")
        return token

    def validate_reset_token(self, token):
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("SELECT username, expires_at, used FROM reset_tokens WHERE token= ?", (token,))
        row = cursor.fetchone()
        conn.close()
        if not row:
            return None
        username, expires_at_str, used = row
        try:
            expires_at = datetime.fromisoformat(expires_at_str)
        except ValueError:
            return None
        if used == 1 or datetime.utcnow() > expires_at:
            return None
        return username

    def reset_password_with_token(self, token, new_password):
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("SELECT username, expires_at, used FROM reset_tokens WHERE token= ?", (token,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return False
        username, expires_at_str, used = row
        try:
            expires_at = datetime.fromisoformat(expires_at_str)
        except ValueError:
            conn.close()
            return False
        if used == 1 or datetime.utcnow() > expires_at:
            conn.close()
            return False
        hashed_password = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())
        cursor.execute("UPDATE users SET hashed_password= ? WHERE username= ?", (hashed_password, username))
        cursor.execute("UPDATE reset_tokens SET used=1 WHERE token= ?", (token,))
        conn.commit()
        conn.close()
        print(f"Password reset for '{username}'")
        return True


def api_key_required(func):
    def wrapper(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return jsonify({'error': 'API key is missing'}), 401
            
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("SELECT api_key FROM users")
        users = cursor.fetchall()
        conn.close()

        for user_api_key in users:
            stored_key = user_api_key[0]
            if bcrypt.checkpw(api_key.encode(), stored_key):
                return func(*args, **kwargs)

        return jsonify({'error': 'Invalid API key'}), 401

    return wrapper
    

@app.route('/')
def hello_world():
    return 'Hello, Flask!'


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':    
        username = request.form['username']
        password = request.form['password']

        if pm.verify_user(username, password):
            return redirect(url_for('profile'))
        else:
            return 'Invalid username or password. <a href="/login">Try again</a>'

    return render_template('login.html')

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        pm.register_user(username, password)
        return redirect(url_for('profile'))
        
    return render_template('register.html')

@app.route('/password-reset-request', methods=['GET', 'POST'])
def password_reset_request():
    if request.method == 'POST':    
        username = request.form.get('username')
        token = pm.create_reset_token(username)
        if not token:
            return 'This user does not exist, please try again. <a href="/password-reset-request">Try Again</a>', 401
        reset_link = url_for('password_reset', token=token, _external=True)
        return f'Password reset link, only valid for 1 hour: <a href="{reset_link}">{reset_link}</a>'

    return render_template('password-reset-request.html')

@app.route('/password-reset/<token>', methods=['GET', 'POST'])
def password_reset(token):
    if request.method == 'POST':    
        new_password = request.form.get('password')
        if not new_password:
            return 'Password is required.'
        ok = pm.reset_password_with_token(token, new_password)
        if ok:
            return 'Password has been reset. <a href="/login">Login</a>'
        return 'Invalid or expired token.'

    username = pm.validate_reset_token(token)
    if not username:
        return 'Invalid or expired token.'
    return render_template('set_new_password.html', token=token)

@app.route('/profile')
def profile():
    return f'Welcome, name! <a href="/logout">Logout</a>'


@app.route("/api/secure", methods=["GET"])
@api_key_required
def secure_endpoint():
    return jsonify({"message": "You have accessed a secure endpoint!"})


if __name__ == '__main__':
    pm = PasswordManager(DATABASE)
    app.run(debug=True)