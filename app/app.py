from flask import Flask, jsonify

from .UserCreation import user_bp, init_db


def create_app() -> Flask:
	app = Flask(__name__)

	init_db()

	app.register_blueprint(user_bp)

	@app.get("/")
	def home():
		return ("Welcome home")

	return app


if __name__ == "__main__":
	app = create_app()
	app.run()
