from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

# Create database instance
db = SQLAlchemy()
from datetime import datetime, timedelta
from crypto_utils import encrypt_data, decrypt_data
import json

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default='operator')  # admin, operator, viewer
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    # Enhanced security fields
    totp_secret = db.Column(db.String(32))  # For 2FA
    failed_login_attempts = db.Column(db.Integer, default=0)
    account_locked_until = db.Column(db.DateTime)
    last_password_change = db.Column(db.DateTime, default=datetime.utcnow)
    session_token = db.Column(db.String(128))  # For session validation
    device_fingerprints = db.Column(db.Text)  # JSON array of trusted devices
    
    # Relationships
    scan_sessions = db.relationship('ScanSession', backref='user', lazy=True)
    reports = db.relationship('Report', backref='user', lazy=True)
    
    def is_account_locked(self):
        """Check if account is currently locked"""
        if self.account_locked_until:
            return datetime.utcnow() < self.account_locked_until
        return False
    
    def lock_account(self, duration_minutes=30):
        """Lock account for specified duration"""
        self.account_locked_until = datetime.utcnow() + timedelta(minutes=duration_minutes)
        self.failed_login_attempts = 0
    
    def unlock_account(self):
        """Unlock account and reset failed attempts"""
        self.account_locked_until = None
        self.failed_login_attempts = 0
    
    def increment_failed_login(self):
        """Increment failed login attempts and lock if threshold reached"""
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:
            self.lock_account()
    
    def reset_failed_login(self):
        """Reset failed login attempts on successful login"""
        self.failed_login_attempts = 0
        self.account_locked_until = None

class ScanSession(db.Model):
    __tablename__ = 'scan_sessions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    session_name = db.Column(db.String(100), nullable=False)
    target_info = db.Column(db.Text)  # Encrypted target information
    scan_type = db.Column(db.String(50), nullable=False)  # network, vulnerability, web_app, exploit
    status = db.Column(db.String(20), default='pending')  # pending, running, completed, failed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    findings = db.relationship('Finding', backref='scan_session', lazy=True)

class Finding(db.Model):
    __tablename__ = 'findings'
    id = db.Column(db.Integer, primary_key=True)
    scan_session_id = db.Column(db.Integer, db.ForeignKey('scan_sessions.id'), nullable=False)
    finding_type = db.Column(db.String(50), nullable=False)  # vulnerability, open_port, exploit_success
    severity = db.Column(db.String(20), nullable=False)  # critical, high, medium, low, info
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)  # Encrypted description
    target_host = db.Column(db.String(100))  # Encrypted host information
    target_port = db.Column(db.Integer)
    cve_id = db.Column(db.String(20))
    cvss_score = db.Column(db.Float)
    remediation = db.Column(db.Text)  # Encrypted remediation advice
    evidence = db.Column(db.Text)  # Encrypted evidence data
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Report(db.Model):
    __tablename__ = 'reports'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    report_name = db.Column(db.String(100), nullable=False)
    report_type = db.Column(db.String(50), nullable=False)  # executive, technical, compliance
    scan_sessions = db.Column(db.Text)  # JSON list of scan session IDs
    report_data = db.Column(db.Text)  # Encrypted report content
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_encrypted = db.Column(db.Boolean, default=True)

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    action = db.Column(db.String(100), nullable=False)
    target = db.Column(db.String(200))  # What was acted upon
    details = db.Column(db.Text)  # Encrypted action details
    ip_address = db.Column(db.String(45))  # Supports IPv6
    user_agent = db.Column(db.String(500))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_encrypted_details(self, details_dict):
        """Encrypt and store action details"""
        self.details = encrypt_data(json.dumps(details_dict))
    
    def get_decrypted_details(self):
        """Decrypt and return action details"""
        if self.details:
            try:
                return json.loads(decrypt_data(self.details))
            except:
                return {}
        return {}

class NetworkTarget(db.Model):
    __tablename__ = 'network_targets'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    target_range = db.Column(db.String(500))  # Encrypted IP ranges/hostnames
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_authorized = db.Column(db.Boolean, default=False)
    
    def set_encrypted_target_range(self, target_data):
        """Encrypt and store target information"""
        self.target_range = encrypt_data(json.dumps(target_data))
    
    def get_decrypted_target_range(self):
        """Decrypt and return target information"""
        if self.target_range:
            try:
                return json.loads(decrypt_data(self.target_range))
            except:
                return {}
        return {}
