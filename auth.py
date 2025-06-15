try:
    from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
except ImportError:
    print("Flask is not installed. Please install it using: pip install flask")
    raise
try:
    from flask_login import login_user, logout_user, login_required, current_user
except ImportError:
    print("Flask-Login is not installed. Please install it using: pip install flask-login")
    raise
from werkzeug.security import check_password_hash, generate_password_hash
from models import User, AuditLog, db
from security.auth import rate_limit, create_audit_log, get_client_ip
from security.encryption import generate_secure_token
import datetime
import hashlib
import pyotp
try:
    import qrcode
except ImportError:
    print("qrcode is not installed. Please install it using: pip install qrcode")
    raise
import io
import base64
import secrets
import time

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

@auth_bp.route('/login', methods=['GET', 'POST'])
@rate_limit(max_requests=5, time_window=300)
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        totp_code = request.form.get('totp_code')
        device_fingerprint = request.form.get('device_fingerprint')
        
        # Enhanced input validation
        if not username or not password:
            flash('Username and password are required', 'error')
            return render_template('login.html', require_2fa=False)
        
        # Rate limiting check
        client_ip = get_client_ip()
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password) and user.is_active:
            # Check if 2FA is enabled
            if hasattr(user, 'totp_secret') and user.totp_secret:
                if not totp_code:
                    flash('Two-factor authentication code required', 'warning')
                    return render_template('login.html', require_2fa=True, username=username)
                
                # Verify TOTP code
                totp = pyotp.TOTP(user.totp_secret)
                if not totp.verify(totp_code, valid_window=1):
                    create_audit_log('LOGIN_2FA_FAILED', f'Invalid 2FA code for user: {username}')
                    flash('Invalid two-factor authentication code', 'error')
                    return render_template('login.html', require_2fa=True, username=username)
            
            # Generate session security hash
            session_hash = hashlib.sha256(
                f"{user.id}{client_ip}{request.headers.get('User-Agent', '')}".encode()
            ).hexdigest()
            
            # Login user with enhanced session
            login_user(user, remember=True)
            session['session_hash'] = session_hash
            session['session_created'] = time.time()
            session['device_fingerprint'] = device_fingerprint
            session['ghost_mode'] = True
            
            user.last_login = datetime.datetime.utcnow()
            db.session.commit()
            
            # Log successful login with enhanced details
            create_audit_log('LOGIN_SUCCESS', {
                'username': username,
                'timestamp': datetime.datetime.utcnow().isoformat(),
                'success': True,
                'device_fingerprint': device_fingerprint,
                'session_hash': session_hash[:16],  # Partial hash for logging
                'ghost_mode': True
            }, target=f'User: {username}')
            
            flash('Ghost mode activated. Secure access granted.', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('main.dashboard'))
        else:
            # Enhanced failed login logging
            create_audit_log('LOGIN_FAILED', {
                'username': username,
                'timestamp': datetime.datetime.utcnow().isoformat(),
                'success': False,
                'device_fingerprint': device_fingerprint,
                'reason': 'Invalid credentials'
            }, target=f'User: {username}')
            
            flash('Access denied. Invalid credentials.', 'error')
            time.sleep(random.uniform(1, 3))  # Anti-timing attack delay
    
    return render_template('login.html', require_2fa=False)

@auth_bp.route('/setup-2fa', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    """Setup two-factor authentication"""
    if request.method == 'POST':
        totp_code = request.form.get('totp_code')
        
        if not totp_code:
            flash('TOTP code is required', 'error')
            return redirect(url_for('auth.setup_2fa'))
        
        # Verify the TOTP code
        secret = session.get('temp_totp_secret')
        if not secret:
            flash('Setup session expired. Please try again.', 'error')
            return redirect(url_for('auth.setup_2fa'))
        
        totp = pyotp.TOTP(secret)
        if totp.verify(totp_code, valid_window=1):
            # Save the secret to user account
            current_user.totp_secret = secret
            db.session.commit()
            
            # Clear temporary secret
            session.pop('temp_totp_secret', None)
            
            create_audit_log('2FA_ENABLED', 'Two-factor authentication enabled')
            flash('Two-factor authentication has been enabled successfully', 'success')
            return redirect(url_for('main.dashboard'))
        else:
            flash('Invalid TOTP code. Please try again.', 'error')
    
    # Generate new secret for setup
    secret = pyotp.random_base32()
    session['temp_totp_secret'] = secret
    
    # Generate QR code
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=current_user.username,
        issuer_name="RedTeam Platform"
    )
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    img_buffer = io.BytesIO()
    img.save(img_buffer, format='PNG')
    img_buffer.seek(0)
    
    qr_code_data = base64.b64encode(img_buffer.getvalue()).decode()
    
    return render_template('setup_2fa.html', 
                         qr_code=qr_code_data, 
                         secret=secret)

@auth_bp.route('/disable-2fa', methods=['POST'])
@login_required
def disable_2fa():
    """Disable two-factor authentication"""
    password = request.form.get('password')
    
    if not password or not check_password_hash(current_user.password_hash, password):
        flash('Invalid password', 'error')
        return redirect(url_for('main.settings'))
    
    current_user.totp_secret = None
    db.session.commit()
    
    create_audit_log('2FA_DISABLED', 'Two-factor authentication disabled')
    flash('Two-factor authentication has been disabled', 'warning')
    return redirect(url_for('main.settings'))

@auth_bp.route('/ghost-logout')
@login_required
def ghost_logout():
    """Secure logout with session cleanup"""
    create_audit_log('LOGOUT', 'User logged out from ghost mode')
    
    # Clear all session data
    session.clear()
    logout_user()
    
    flash('Ghost mode deactivated. Session terminated.', 'info')
    return redirect(url_for('auth.login'))

@auth_bp.route('/logout')
@login_required
def logout():
    # Log logout
    audit_log = AuditLog(
        user_id=current_user.id,
        action='LOGOUT',
        target=f'User: {current_user.username}',
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent')
    )
    audit_log.set_encrypted_details({
        'username': current_user.username,
        'timestamp': datetime.datetime.utcnow().isoformat()
    })
    db.session.add(audit_log)
    db.session.commit()
    
    logout_user()
    flash('Successfully logged out from Red Team Platform', 'info')
    return redirect(url_for('auth.login'))

@auth_bp.route('/register', methods=['GET', 'POST'])
@login_required
def register():
    # Only admins can register new users
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('main.dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role', 'operator')
        
        # Check if user already exists
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash('Username or email already exists', 'danger')
            return render_template('register.html')
        
        # Create new user
        new_user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            role=role,
            is_active=True
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        # Log user creation
        audit_log = AuditLog(
            user_id=current_user.id,
            action='USER_CREATED',
            target=f'New User: {username}',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        audit_log.set_encrypted_details({
            'created_by': current_user.username,
            'new_username': username,
            'new_email': email,
            'role': role,
            'timestamp': datetime.datetime.utcnow().isoformat()
        })
        db.session.add(audit_log)
        db.session.commit()
        
        flash(f'User {username} created successfully', 'success')
        return redirect(url_for('main.dashboard'))
    
    return render_template('register.html')

@auth_bp.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if not check_password_hash(current_user.password_hash, current_password):
            flash('Current password is incorrect', 'danger')
            return render_template('change_password.html')
        
        if new_password != confirm_password:
            flash('New passwords do not match', 'danger')
            return render_template('change_password.html')
        
        if len(new_password) < 8:
            flash('Password must be at least 8 characters long', 'danger')
            return render_template('change_password.html')
        
        # Update password
        current_user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        
        # Log password change
        audit_log = AuditLog(
            user_id=current_user.id,
            action='PASSWORD_CHANGED',
            target=f'User: {current_user.username}',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        audit_log.set_encrypted_details({
            'username': current_user.username,
            'timestamp': datetime.datetime.utcnow().isoformat()
        })
        db.session.add(audit_log)
        db.session.commit()
        
        flash('Password changed successfully', 'success')
        return redirect(url_for('main.dashboard'))
    
    return render_template('change_password.html')
