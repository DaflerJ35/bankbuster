import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import secrets
import hashlib

class CryptoManager:
    def __init__(self):
        self.master_key = self._get_or_create_master_key()
        self.fernet = Fernet(self.master_key)
    
    def _get_or_create_master_key(self):
        """Get or create the master encryption key"""
        key_file = 'master.key'
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            # Generate new master key
            password = os.environ.get('MASTER_PASSWORD', 'RedTeamPlatform2024!').encode()
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password))
            
            # Store key securely
            with open(key_file, 'wb') as f:
                f.write(key)
            with open('salt.key', 'wb') as f:
                f.write(salt)
            
            return key
    
    def encrypt_data(self, data):
        """Encrypt data using AES-256"""
        if isinstance(data, str):
            data = data.encode()
        return base64.urlsafe_b64encode(self.fernet.encrypt(data)).decode()
    
    def decrypt_data(self, encrypted_data):
        """Decrypt data using AES-256"""
        if isinstance(encrypted_data, str):
            encrypted_data = base64.urlsafe_b64decode(encrypted_data.encode())
        return self.fernet.decrypt(encrypted_data).decode()
    
    def generate_secure_token(self, length=32):
        """Generate a cryptographically secure token"""
        return secrets.token_urlsafe(length)
    
    def hash_password(self, password):
        """Hash password using SHA-256 with salt"""
        salt = os.urandom(32)
        pwdhash = hashlib.pbkdf2_hmac('sha256', 
                                     password.encode('utf-8'), 
                                     salt, 
                                     100000)
        return salt + pwdhash
    
    def verify_password(self, stored_password, provided_password):
        """Verify password against stored hash"""
        salt = stored_password[:32]
        stored_hash = stored_password[32:]
        pwdhash = hashlib.pbkdf2_hmac('sha256',
                                     provided_password.encode('utf-8'),
                                     salt,
                                     100000)
        return pwdhash == stored_hash

# Global crypto manager instance
crypto_manager = CryptoManager()

# Convenience functions
def encrypt_data(data):
    return crypto_manager.encrypt_data(data)

def decrypt_data(encrypted_data):
    return crypto_manager.decrypt_data(encrypted_data)

def generate_secure_token(length=32):
    return crypto_manager.generate_secure_token(length)

class RSAKeyManager:
    """Manage RSA key pairs for secure communications"""
    
    @staticmethod
    def generate_key_pair():
        """Generate RSA key pair"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()
        
        # Serialize keys
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem, public_pem
    
    @staticmethod
    def encrypt_with_public_key(message, public_key_pem):
        """Encrypt message with RSA public key"""
        public_key = serialization.load_pem_public_key(public_key_pem)
        encrypted = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted).decode()
    
    @staticmethod
    def decrypt_with_private_key(encrypted_message, private_key_pem):
        """Decrypt message with RSA private key"""
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
        decrypted = private_key.decrypt(
            base64.b64decode(encrypted_message),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted.decode()
