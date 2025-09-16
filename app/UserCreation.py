import sqlite3
from contextlib import closing
from typing import Optional

from flask import Blueprint, request, jsonify, render_template
import bcrypt

DATABASE_PATH = "users.db"

user_bp = Blueprint("users", __name__, template_folder="template")


def get_db_connection() -> sqlite3.Connection:
	conn = sqlite3.connect(DATABASE_PATH)
	conn.row_factory = sqlite3.Row
	return conn


def init_db() -> None:
	with closing(get_db_connection()) as conn, conn:
		conn.execute(
			"""
			CREATE TABLE IF NOT EXISTS users (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				username TEXT UNIQUE NOT NULL,
				password_hash BLOB NOT NULL
			)
			"""
		)

@user_bp.route("/register", methods=["GET"])
def register_form():
	return render_template("register.html")


@user_bp.route("/register", methods=["POST"])
def register_submit():
	username = (request.form.get("username") or "").strip()
	password = request.form.get("password") or ""

	if not username:
		return jsonify({"error": "username is required"}), 400
	if not password or len(password) < 8:
		return jsonify({"error": "password must be at least 8 characters"}), 400

	password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

	try:
		with closing(get_db_connection()) as conn, conn:
			conn.execute(
				"INSERT INTO users (username, password_hash) VALUES (?, ?)",
				(username, password_hash),
			)
	except sqlite3.IntegrityError:
		return jsonify({"error": "username already exists"}), 409

	return jsonify({"message": "registration successful"}), 201


@user_bp.route("/login", methods=["GET"])
def login_form():
	return render_template("login.html")


@user_bp.route("/login", methods=["POST"])
def login_submit():
	username = (request.form.get("username") or "").strip()
	password = request.form.get("password") or ""

	if not username or not password:
		return jsonify({"error": "username and password are required"}), 400

	user_row: Optional[sqlite3.Row] = None
	with closing(get_db_connection()) as conn:
		cur = conn.execute(
			"SELECT id, username, password_hash FROM users WHERE username = ?",
			(username,),
		)
		user_row = cur.fetchone()

	if not user_row:
		return jsonify({"error": "invalid credentials"}), 401

	stored_hash: bytes = user_row["password_hash"]
	if not isinstance(stored_hash, (bytes, bytearray)):
		stored_hash = bytes(stored_hash)

	if bcrypt.checkpw(password.encode("utf-8"), stored_hash):
		return jsonify({"message": "login successful"}), 200
	else:
		return jsonify({"error": "invalid credentials"}), 401
