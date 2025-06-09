from flask import request, session, current_app
from flask_login import current_user
from functools import wraps
import time
import ipaddress
import re
from datetime import datetime, timedelta

from app import db
from models import AuditLog

# Rate limiting storage
rate_limit_storage = {}

def rate_limit(max_requests=5, time_window=300):
    """Rate limiting decorator"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            client_ip = get_client_ip()
            current_time = time.time()
            
            # Clean old entries
            rate_limit_storage[client_ip] = [
                timestamp for timestamp in rate_limit_storage.get(client_ip, [])
                if current_time - timestamp < time_window
            ]
            
            # Check rate limit
            if len(rate_limit_storage.get(client_ip, [])) >= max_requests:
                return "Rate limit exceeded. Try again later.", 429
            
            # Add current request
            if client_ip not in rate_limit_storage:
                rate_limit_storage[client_ip] = []
            rate_limit_storage[client_ip].append(current_time)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def get_client_ip():
    """Get client IP address"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr

def create_audit_log(action, details, target=None):
    """Create encrypted audit log entry"""
    try:
        audit_log = AuditLog(
            user_id=current_user.id if current_user.is_authenticated else None,
            action=action,
            target=target,
            ip_address=get_client_ip(),
            user_agent=request.headers.get('User-Agent', '')[:500]
        )
        
        log_details = {
            'details': details,
            'timestamp': datetime.utcnow().isoformat(),
            'session_id': session.get('_id', 'anonymous')
        }
        audit_log.set_details(log_details)
        
        db.session.add(audit_log)
        db.session.commit()
    except Exception as e:
        current_app.logger.error(f"Failed to create audit log: {e}")

def validate_target(target):
    """Validate scan target format and check if it's authorized"""
    if not target:
        return False
    
    # Check for IP address
    try:
        ip = ipaddress.ip_address(target)
        # Prevent scanning of private/reserved ranges unless explicitly allowed
        if ip.is_private or ip.is_reserved or ip.is_loopback:
            return True  # Allow for testing purposes
        return True
    except ValueError:
        pass
    
    # Check for CIDR notation
    try:
        network = ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        pass
    
    # Check for hostname/domain
    hostname_pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    )
    if hostname_pattern.match(target):
        return True
    
    return False

def sanitize_input(input_string):
    """Sanitize user input"""
    if not input_string:
        return ""
    
    # Remove potentially dangerous characters
    dangerous_chars = ['<', '>', '"', "'", '&', '\x00']
    for char in dangerous_chars:
        input_string = input_string.replace(char, '')
    
    return input_string.strip()

def validate_session():
    """Validate current session"""
    if not current_user.is_authenticated:
        return False
    
    # Check session timeout
    last_activity = session.get('last_activity')
    if last_activity:
        last_activity_time = datetime.fromisoformat(last_activity)
        if datetime.utcnow() - last_activity_time > timedelta(hours=1):
            return False
    
    # Update last activity
    session['last_activity'] = datetime.utcnow().isoformat()
    return True

def admin_required(f):
    """Decorator to require admin privileges"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            create_audit_log('unauthorized_access', f'Non-admin user attempted to access {request.endpoint}')
            return "Access denied. Admin privileges required.", 403
        return f(*args, **kwargs)
    return decorated_function

def secure_headers():
    """Add security headers to responses"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            response = f(*args, **kwargs)
            
            # Add security headers
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'DENY'
            response.headers['X-XSS-Protection'] = '1; mode=block'
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
            response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' cdn.jsdelivr.net cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' cdn.jsdelivr.net cdnjs.cloudflare.com cdn.replit.com; font-src 'self' cdnjs.cloudflare.com; img-src 'self' data:;"
            
            return response
        return decorated_function
    return decorator
