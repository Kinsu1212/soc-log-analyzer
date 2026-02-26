from datetime import datetime
from .extensions import db
from werkzeug.security import generate_password_hash, check_password_hash

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def set_password(self, password: str) -> None:
        # Force PBKDF2 to avoid hashlib.scrypt issues on some Python builds
        self.password_hash = generate_password_hash(
            password,
            method="pbkdf2:sha256",
            salt_length=16,
        )

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)