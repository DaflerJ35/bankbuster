from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from models import User, AuditLog
from app import db
import datetime

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password) and user.is_active:
            login_user(user, remember=True)
            user.last_login = datetime.datetime.utcnow()
            db.session.commit()
            
            # Log successful login
            audit_log = AuditLog(
                user_id=user.id,
                action='LOGIN_SUCCESS',
                target=f'User: {username}',
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent')
            )
            audit_log.set_encrypted_details({
                'username': username,
                'timestamp': datetime.datetime.utcnow().isoformat(),
                'success': True
            })
            db.session.add(audit_log)
            db.session.commit()
            
            flash('Successfully logged in to Red Team Platform', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('main.dashboard'))
        else:
            # Log failed login attempt
            audit_log = AuditLog(
                user_id=user.id if user else None,
                action='LOGIN_FAILED',
                target=f'User: {username}',
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent')
            )
            audit_log.set_encrypted_details({
                'username': username,
                'timestamp': datetime.datetime.utcnow().isoformat(),
                'success': False,
                'reason': 'Invalid credentials or inactive account'
            })
            db.session.add(audit_log)
            db.session.commit()
            
            flash('Invalid credentials or account is inactive', 'danger')
    
    return render_template('login.html')

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
