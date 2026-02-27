from .auth import auth_bp
from .protected import protected_bp
from .uploads import uploads_bp

def register_routes(app):
    app.register_blueprint(auth_bp)
    app.register_blueprint(protected_bp)
    app.register_blueprint(uploads_bp)