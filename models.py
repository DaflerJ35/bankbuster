from app import db
from flask_login import UserMixin
from datetime import datetime
from crypto_utils import encrypt_data, decrypt_data
import json

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default='operator')  # admin, operator, viewer
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    # Relationships
    scan_sessions = db.relationship('ScanSession', backref='user', lazy=True)
    reports = db.relationship('Report', backref='user', lazy=True)

class ScanSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    session_name = db.Column(db.String(100), nullable=False)
    target_info = db.Column(db.Text)  # Encrypted target information
    scan_type = db.Column(db.String(50), nullable=False)  # network, vulnerability, web_app, exploit
    status = db.Column(db.String(20), default='pending')  # pending, running, completed, failed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    findings = db.relationship('Finding', backref='scan_session', lazy=True)

class Finding(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_session_id = db.Column(db.Integer, db.ForeignKey('scan_session.id'), nullable=False)
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
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    report_name = db.Column(db.String(100), nullable=False)
    report_type = db.Column(db.String(50), nullable=False)  # executive, technical, compliance
    scan_sessions = db.Column(db.Text)  # JSON list of scan session IDs
    report_data = db.Column(db.Text)  # Encrypted report content
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_encrypted = db.Column(db.Boolean, default=True)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
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
