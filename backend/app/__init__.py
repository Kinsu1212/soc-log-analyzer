from flask import Flask
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from dotenv import load_dotenv
import os
from .routes import register_routes
from .extensions import db
from sqlalchemy import text
from .routes.uploads import uploads_bp

def create_app():
    load_dotenv()

    app = Flask(__name__)

    # DB config MUST be set before init_app
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
    "DATABASE_URL",
    "sqlite:///" + os.path.join(app.instance_path, "soclog.db"))
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False


    db.init_app(app)

    from . import models

    with app.app_context():
        db.create_all()

    app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "dev-secret")
    CORS(app, origins=os.getenv("CORS_ORIGIN", "http://localhost:3000"))
    JWTManager(app)

    register_routes(app)

    @app.route("/api/health")
    def health():
        return {"status": "ok"}, 200

    return app