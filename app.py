"""
Task A.3.1: User Registration and Login with Password Hashing
Develop a Python application to handle secure user registration and login. Implement password
hashing using a robust cryptographic algorithm to ensure passwords are stored securely. User details
should be maintained in a database, and passwords must be verified securely during the login process.
"""

from flask import Flask, request, jsonify, g, render_template, session, redirect, url_for
from flask_session import Session
import sqlite3
import bcrypt

app = Flask(__name__)

DATABASE = 'user_database.db'

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
                hashed_password TEXT NOT NULL
            )
        ''')
        conn.commit()
        conn.close()

    def register_user(self, username, password):
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        cursor.execute("INSERT INTO users (username, hashed_password) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
        print(f"User '{username}' registered")
        print(f"Hashed password (includes salt): {hashed_password.decode()}")
        conn.close()

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


if __name__ == '__main__':
    pm = PasswordManager(DATABASE)
    app.run(debug=True)