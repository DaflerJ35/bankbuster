import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets

class EncryptionManager:
    def __init__(self):
        self.key = self._get_or_create_key()
        self.fernet = Fernet(self.key)
    
    def _get_or_create_key(self):
        """Get encryption key from environment or generate new one"""
        env_key = os.environ.get('ENCRYPTION_KEY')
        if env_key:
            return env_key.encode()
        
        # Generate key from password
        password = os.environ.get('ENCRYPTION_PASSWORD', 'default-password-change-in-production').encode()
        salt = os.environ.get('ENCRYPTION_SALT', 'default-salt').encode()
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key
    
    def encrypt_data(self, data):
        """Encrypt data using AES-256"""
        if isinstance(data, str):
            data = data.encode()
        encrypted = self.fernet.encrypt(data)
        return base64.urlsafe_b64encode(encrypted).decode()
    
    def decrypt_data(self, encrypted_data):
        """Decrypt data"""
        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode())
            decrypted = self.fernet.decrypt(encrypted_bytes)
            return decrypted.decode()
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")
    
    def generate_secure_token(self, length=32):
        """Generate cryptographically secure random token"""
        return secrets.token_urlsafe(length)
    
    def encrypt_file(self, file_path, output_path=None):
        """Encrypt a file"""
        if not output_path:
            output_path = file_path + '.enc'
        
        with open(file_path, 'rb') as infile:
            data = infile.read()
        
        encrypted_data = self.fernet.encrypt(data)
        
        with open(output_path, 'wb') as outfile:
            outfile.write(encrypted_data)
        
        return output_path
    
    def decrypt_file(self, encrypted_file_path, output_path=None):
        """Decrypt a file"""
        if not output_path:
            output_path = encrypted_file_path.replace('.enc', '')
        
        with open(encrypted_file_path, 'rb') as infile:
            encrypted_data = infile.read()
        
        decrypted_data = self.fernet.decrypt(encrypted_data)
        
        with open(output_path, 'wb') as outfile:
            outfile.write(decrypted_data)
        
        return output_path

# Global encryption manager instance
encryption_manager = EncryptionManager()

def encrypt_data(data):
    """Convenience function for encrypting data"""
    return encryption_manager.encrypt_data(data)

def decrypt_data(encrypted_data):
    """Convenience function for decrypting data"""
    return encryption_manager.decrypt_data(encrypted_data)

def generate_secure_token(length=32):
    """Generate cryptographically secure random token"""
    return encryption_manager.generate_secure_token(length)
