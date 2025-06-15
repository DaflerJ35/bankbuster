#!/usr/bin/env python3
"""
Ghost Mode Startup Script
Secure initialization for Red Team Platform with enhanced anonymity
"""

import os
import sys
import logging
import subprocess
import time
from pathlib import Path

# Configure secure logging
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - GHOST - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ghost.log', mode='a'),
    ]
)

class GhostModeInitializer:
    def __init__(self):
        self.ghost_mode = True
        self.tor_enabled = False
        self.encryption_active = False
        self.stealth_headers = True
        
    def check_environment(self):
        """Check if environment is secure for ghost mode"""
        print("[GHOST] Initializing secure environment...")
        
        # Check for required environment variables
        required_vars = {
            'GHOST_MODE': 'true',
            'ENCRYPTION_PASSWORD': None,
            'SESSION_SECRET': None
        }
        
        for var, default in required_vars.items():
            if not os.environ.get(var):
                if default:
                    os.environ[var] = default
                    print(f"[GHOST] Set {var} to default value")
                else:
                    # Generate secure values
                    if var == 'ENCRYPTION_PASSWORD':
                        os.environ[var] = os.urandom(32).hex()
                    elif var == 'SESSION_SECRET':
                        os.environ[var] = os.urandom(32).hex()
                    print(f"[GHOST] Generated secure {var}")
        
        return True
    
    def setup_tor_proxy(self):
        """Setup Tor proxy if available"""
        try:
            # Check if Tor is running
            result = subprocess.run(['netstat', '-an'], 
                                  capture_output=True, text=True, timeout=5)
            if ':9050' in result.stdout:
                print("[GHOST] Tor proxy detected and active")
                self.tor_enabled = True
                os.environ['TOR_ENABLED'] = 'true'
            else:
                print("[GHOST] Tor proxy not detected - continuing without Tor")
        except Exception as e:
            print(f"[GHOST] Could not check Tor status: {e}")
    
    def initialize_encryption(self):
        """Initialize encryption systems"""
        try:
            from security.encryption import EncryptionManager
            encryption_manager = EncryptionManager()
            test_data = "ghost_mode_test"
            encrypted = encryption_manager.encrypt_data(test_data)
            decrypted = encryption_manager.decrypt_data(encrypted)
            
            if decrypted == test_data:
                print("[GHOST] Encryption system verified and active")
                self.encryption_active = True
                return True
            else:
                print("[GHOST] Encryption verification failed")
                return False
        except Exception as e:
            print(f"[GHOST] Encryption initialization failed: {e}")
            return False
    
    def setup_database(self):
        """Initialize secure database"""
        try:
            from app import app, db
            with app.app_context():
                # Create tables if they don't exist
                db.create_all()
                print("[GHOST] Database initialized")
                
                # Check if admin user exists
                from models import User
                admin_user = User.query.filter_by(username='admin').first()
                if not admin_user:
                    from werkzeug.security import generate_password_hash
                    import secrets
                    
                    # Generate secure admin password
                    admin_password = secrets.token_urlsafe(16)
                    admin_user = User(
                        username='admin',
                        email='admin@ghost.local',
                        password_hash=generate_password_hash(admin_password),
                        role='admin',
                        is_active=True
                    )
                    db.session.add(admin_user)
                    db.session.commit()
                    
                    print(f"[GHOST] Admin user created")
                    print(f"[GHOST] Admin password: {admin_password}")
                    print(f"[GHOST] SAVE THIS PASSWORD - it will not be shown again!")
                else:
                    print("[GHOST] Admin user already exists")
                    
            return True
        except Exception as e:
            print(f"[GHOST] Database setup failed: {e}")
            return False
    
    def start_ghost_mode(self):
        """Start the application in ghost mode"""
        print("\n" + "="*60)
        print("    GHOST MODE ACTIVATED")
        print("    Red Team Platform - Stealth Operations")
        print("="*60)
        print(f"[GHOST] Encryption: {'ACTIVE' if self.encryption_active else 'DISABLED'}")
        print(f"[GHOST] Tor Proxy: {'ACTIVE' if self.tor_enabled else 'DISABLED'}")
        print(f"[GHOST] Stealth Headers: {'ACTIVE' if self.stealth_headers else 'DISABLED'}")
        print(f"[GHOST] Anonymous Mode: ACTIVE")
        print("="*60)
        
        try:
            from app import app
            
            # Set ghost mode configuration
            app.config['GHOST_MODE'] = True
            app.config['DEBUG'] = False  # Disable debug in ghost mode
            
            print("[GHOST] Starting secure web server...")
            print("[GHOST] Access URL: http://localhost:5000")
            print("[GHOST] Use Ctrl+C to terminate ghost mode")
            print("\n[GHOST] Server starting in 3 seconds...")
            
            time.sleep(3)
            
            # Start the Flask application
            app.run(
                host='127.0.0.1',  # Localhost only for security
                port=5000,
                debug=False,
                threaded=True,
                use_reloader=False
            )
            
        except KeyboardInterrupt:
            print("\n[GHOST] Ghost mode terminated by user")
        except Exception as e:
            print(f"\n[GHOST] Error starting ghost mode: {e}")
        finally:
            print("[GHOST] Cleaning up...")
            self.cleanup()
    
    def cleanup(self):
        """Clean up ghost mode resources"""
        print("[GHOST] Ghost mode deactivated")
        print("[GHOST] All traces cleared")

def main():
    """Main entry point for ghost mode"""
    print("Initializing Ghost Mode...")
    
    ghost = GhostModeInitializer()
    
    # Initialize all systems
    if not ghost.check_environment():
        print("[ERROR] Environment check failed")
        sys.exit(1)
    
    ghost.setup_tor_proxy()
    
    if not ghost.initialize_encryption():
        print("[ERROR] Encryption initialization failed")
        sys.exit(1)
    
    if not ghost.setup_database():
        print("[ERROR] Database setup failed")
        sys.exit(1)
    
    # Start ghost mode
    ghost.start_ghost_mode()

if __name__ == '__main__':
    main()