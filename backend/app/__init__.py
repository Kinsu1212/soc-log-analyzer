from flask import Flask
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from dotenv import load_dotenv
import os


def create_app():
    load_dotenv()

    app = Flask(__name__)

    # Basic config
    app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET", "dev-secret")

    # Enable CORS
    CORS(app, origins=os.getenv("CORS_ORIGIN", "http://localhost:3000"))

    # Initialize JWT
    JWTManager(app)

    # Simple health check route
    @app.route("/api/health")
    def health():
        return {"status": "ok"}, 200

    return app