import os
import logging
import secrets
import random
try:
    from flask import Flask, request, session
except ImportError:
    raise ImportError("Flask is not installed. Please install it using: pip install flask")
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix
from datetime import timedelta
import hashlib
import time

# Configure secure logging
logging.basicConfig(
    level=logging.WARNING,  # Reduced logging for stealth
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('secure.log', mode='a'),
        logging.StreamHandler()
    ]
)

login_manager = LoginManager()

# Generate secure session key if not provided
SESSION_SECRET = os.environ.get("SESSION_SECRET") or secrets.token_hex(32)

# Create the app with enhanced security
app = Flask(__name__)
app.secret_key = SESSION_SECRET
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Enhanced database configuration
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///secure_redteam.db")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
    "pool_timeout": 20,
    "max_overflow": 0
}

# Military-grade security configuration
app.config['WTF_CSRF_ENABLED'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)
app.config['SESSION_COOKIE_NAME'] = 'ghost_session'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0  # Disable caching

# Ghost mode configuration
app.config['GHOST_MODE'] = os.environ.get('GHOST_MODE', 'true').lower() == 'true'
app.config['STEALTH_HEADERS'] = True
app.config['ANTI_FINGERPRINTING'] = True

# Import database instance from models
from models import db

# Initialize extensions
db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'auth.login'
login_manager.login_message = 'Access denied. Authentication required.'
login_manager.login_message_category = 'error'
login_manager.session_protection = 'strong'

@login_manager.user_loader
def load_user(user_id):
    from models import User
    return User.query.get(int(user_id))

# Ghost mode middleware for stealth operations
@app.before_request
def ghost_mode_middleware():
    """Implement ghost mode security measures"""
    if app.config.get('GHOST_MODE'):
        # Anti-fingerprinting measures
        if app.config.get('ANTI_FINGERPRINTING'):
            # Randomize session timing
            time.sleep(random.uniform(0.01, 0.05))
            
        # Validate session integrity
        if 'user_id' in session:
            session_hash = hashlib.sha256(
                f"{session.get('user_id')}{request.remote_addr}{request.headers.get('User-Agent', '')}".encode()
            ).hexdigest()
            
            if session.get('session_hash') != session_hash:
                session.clear()
                return 'Session integrity violation', 403

@app.after_request
def ghost_mode_headers(response):
    """Apply stealth headers for ghost mode"""
    if app.config.get('STEALTH_HEADERS'):
        # Remove identifying headers
        response.headers.pop('Server', None)
        response.headers.pop('X-Powered-By', None)
        
        # Add security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        
        # Anti-caching headers
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, private'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        
        # Obfuscation headers
        response.headers['X-Robots-Tag'] = 'noindex, nofollow, nosnippet, noarchive'
        
    return response

# Enhanced session security
@app.before_request
def enhance_session_security():
    """Enhance session security with additional checks"""
    session.permanent = True
    
    # Generate session hash for integrity checking
    if 'user_id' in session and 'session_hash' not in session:
        session_hash = hashlib.sha256(
            f"{session.get('user_id')}{request.remote_addr}{request.headers.get('User-Agent', '')}".encode()
        ).hexdigest()
        session['session_hash'] = session_hash
        session['session_created'] = time.time()
    
    # Check session age
    if 'session_created' in session:
        session_age = time.time() - session.get('session_created', 0)
        if session_age > 7200:  # 2 hours
            session.clear()
            return 'Session expired', 401

with app.app_context():
    # Models are imported earlier (from models import db)
    # Ensure routes and auth are imported if they register blueprints or have other app context needs
    import routes
    import auth
    
    db.create_all()
    
    # Create default admin user if none exists
    from models import User
    from werkzeug.security import generate_password_hash
    
    if not User.query.filter_by(username='admin').first():
        admin_user = User(
            username='admin',
            email='admin@redteam.local',
            password_hash=generate_password_hash('RedTeam2024!'),
            role='admin',
            is_active=True
        )
        db.session.add(admin_user)
        db.session.commit()
        logging.info("Default admin user created: admin/RedTeam2024!")

# Register blueprints
from auth import auth_bp
from routes import main_bp

app.register_blueprint(auth_bp)
app.register_blueprint(main_bp)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
