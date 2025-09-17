from flask import Flask, request, jsonify, g, render_template, session, redirect, url_for
from flask_session import Session
import sqlite3
import bcrypt
from flask_httpauth import HTTPBasicAuth
import secrets 

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