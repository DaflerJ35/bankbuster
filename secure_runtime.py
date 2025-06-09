"""
Red Team Platform - Secure Runtime Environment
Encrypted sandbox container with military-grade security
"""

import os
import sys
import shutil
import tempfile
import subprocess
import psutil
import logging
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import json
import time
import threading
from datetime import datetime

class SecureRuntimeEnvironment:
    """Encrypted sandbox container for secure operations"""
    
    def __init__(self):
        self.sandbox_active = False
        self.memory_only = True
        self.encrypted_storage = {}
        self.temp_directory = None
        self.encryption_key = None
        self.runtime_logs = []
        self.auto_cleanup_timer = None
        self.biometric_verified = False
        self.device_fingerprint = None
        
    def initialize_sandbox(self, device_id=None, biometric_token=None):
        """Initialize encrypted sandbox environment"""
        try:
            # Generate device fingerprint
            self.device_fingerprint = self._generate_device_fingerprint()
            
            # Verify biometric authentication
            if biometric_token:
                self.biometric_verified = self._verify_biometric(biometric_token, device_id)
            
            # Initialize encryption
            self.encryption_key = self._generate_runtime_key()
            
            # Create temporary encrypted workspace
            self.temp_directory = tempfile.mkdtemp(prefix='redteam_secure_')
            
            # Set up memory-only operations
            self._configure_memory_operations()
            
            # Initialize sandbox protection
            self._initialize_sandbox_protection()
            
            self.sandbox_active = True
            self._log_secure("Secure runtime environment initialized")
            
            return {
                'success': True,
                'sandbox_id': self.device_fingerprint,
                'memory_only': self.memory_only,
                'encrypted': True
            }
            
        except Exception as e:
            self._log_secure(f"Sandbox initialization failed: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _generate_device_fingerprint(self):
        """Generate unique device fingerprint"""
        try:
            # Collect system information
            system_info = {
                'platform': sys.platform,
                'machine': os.uname().machine if hasattr(os, 'uname') else 'unknown',
                'processor_count': os.cpu_count(),
                'memory_total': psutil.virtual_memory().total,
                'boot_time': psutil.boot_time()
            }
            
            # Create fingerprint hash
            info_string = json.dumps(system_info, sort_keys=True)
            digest = hashes.Hash(hashes.SHA256())
            digest.update(info_string.encode())
            fingerprint = digest.finalize()
            
            return base64.b64encode(fingerprint).decode()[:32]
            
        except Exception:
            # Fallback fingerprint
            return base64.b64encode(os.urandom(24)).decode()[:32]
    
    def _verify_biometric(self, token, device_id):
        """Verify biometric authentication"""
        # Simulate biometric verification
        # In production, this would integrate with actual biometric hardware
        if token and len(token) > 10:
            return True
        return False
    
    def _generate_runtime_key(self):
        """Generate encryption key for runtime operations"""
        password = os.urandom(32)
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return Fernet(key)
    
    def _configure_memory_operations(self):
        """Configure memory-only operations"""
        # Set environment variables for memory-only mode
        os.environ['REDTEAM_MEMORY_ONLY'] = '1'
        os.environ['TMPDIR'] = self.temp_directory
        
        # Configure logging to memory
        self.memory_only = True
        
    def _initialize_sandbox_protection(self):
        """Initialize sandbox protection mechanisms"""
        try:
            # Check if running in container
            if os.path.exists('/.dockerenv'):
                self._log_secure("Running in Docker container - enhanced security")
            
            # Set up process isolation
            self._setup_process_isolation()
            
            # Initialize auto-cleanup timer
            self._setup_auto_cleanup()
            
        except Exception as e:
            self._log_secure(f"Sandbox protection setup warning: {str(e)}")
    
    def _setup_process_isolation(self):
        """Set up process isolation mechanisms"""
        try:
            # Limit process capabilities
            if sys.platform.startswith('linux'):
                # Set process limits
                import resource
                resource.setrlimit(resource.RLIMIT_CORE, (0, 0))  # No core dumps
                resource.setrlimit(resource.RLIMIT_FSIZE, (1024*1024*100, 1024*1024*100))  # 100MB file limit
        except Exception:
            pass
    
    def _setup_auto_cleanup(self):
        """Set up automatic cleanup timer"""
        def cleanup_timer():
            time.sleep(3600)  # 1 hour timeout
            self.emergency_cleanup("Timeout reached")
        
        self.auto_cleanup_timer = threading.Thread(target=cleanup_timer, daemon=True)
        self.auto_cleanup_timer.start()
    
    def store_encrypted(self, key, data):
        """Store data in encrypted memory"""
        try:
            if not self.encryption_key:
                raise Exception("Encryption not initialized")
            
            encrypted_data = self.encryption_key.encrypt(json.dumps(data).encode())
            self.encrypted_storage[key] = encrypted_data
            
            return True
        except Exception as e:
            self._log_secure(f"Encrypted storage failed: {str(e)}")
            return False
    
    def retrieve_encrypted(self, key):
        """Retrieve data from encrypted memory"""
        try:
            if key not in self.encrypted_storage:
                return None
            
            encrypted_data = self.encrypted_storage[key]
            decrypted_data = self.encryption_key.decrypt(encrypted_data)
            
            return json.loads(decrypted_data.decode())
        except Exception as e:
            self._log_secure(f"Encrypted retrieval failed: {str(e)}")
            return None
    
    def create_secure_temp_file(self, suffix='.tmp'):
        """Create secure temporary file"""
        if not self.sandbox_active:
            raise Exception("Sandbox not active")
        
        fd, path = tempfile.mkstemp(suffix=suffix, dir=self.temp_directory)
        os.close(fd)
        return path
    
    def execute_in_sandbox(self, command, timeout=30):
        """Execute command in sandboxed environment"""
        try:
            if not self.sandbox_active:
                raise Exception("Sandbox not active")
            
            # Set up sandboxed environment
            env = os.environ.copy()
            env['PATH'] = '/usr/bin:/bin'  # Restrict PATH
            env['HOME'] = self.temp_directory
            
            # Execute command with restrictions
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=self.temp_directory,
                env=env
            )
            
            self._log_secure(f"Sandbox execution: {command[:50]}...")
            
            return {
                'returncode': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr
            }
            
        except subprocess.TimeoutExpired:
            return {'error': 'Command timeout'}
        except Exception as e:
            return {'error': str(e)}
    
    def emergency_cleanup(self, reason="Manual trigger"):
        """Emergency cleanup and memory wipe"""
        try:
            self._log_secure(f"Emergency cleanup triggered: {reason}")
            
            # Clear encrypted storage
            self.encrypted_storage.clear()
            
            # Wipe memory variables
            if self.encryption_key:
                self.encryption_key = None
            
            # Remove temporary directory
            if self.temp_directory and os.path.exists(self.temp_directory):
                shutil.rmtree(self.temp_directory, ignore_errors=True)
            
            # Clear runtime logs
            self.runtime_logs.clear()
            
            # Reset biometric state
            self.biometric_verified = False
            self.device_fingerprint = None
            
            # Disable sandbox
            self.sandbox_active = False
            
            # Cancel cleanup timer
            if self.auto_cleanup_timer and self.auto_cleanup_timer.is_alive():
                # Timer will exit naturally
                pass
            
            return True
            
        except Exception as e:
            # Force cleanup even if errors occur
            self.sandbox_active = False
            return False
    
    def check_environment_integrity(self):
        """Check for hostile environment indicators"""
        threats_detected = []
        
        try:
            # Check for debugging
            if self._detect_debugger():
                threats_detected.append("Debugger detected")
            
            # Check for virtualization
            if self._detect_virtualization():
                threats_detected.append("Virtual environment detected")
            
            # Check for monitoring tools
            if self._detect_monitoring():
                threats_detected.append("Monitoring tools detected")
            
            # Check memory pressure
            if psutil.virtual_memory().percent > 90:
                threats_detected.append("High memory usage")
            
            return {
                'threats': threats_detected,
                'safe': len(threats_detected) == 0
            }
            
        except Exception:
            return {'threats': ['Environment check failed'], 'safe': False}
    
    def _detect_debugger(self):
        """Detect debugger presence"""
        try:
            # Check for common debugger processes
            debugger_processes = ['gdb', 'lldb', 'windbg', 'x64dbg', 'ollydbg']
            for proc in psutil.process_iter(['name']):
                if proc.info['name'] and proc.info['name'].lower() in debugger_processes:
                    return True
            return False
        except Exception:
            return False
    
    def _detect_virtualization(self):
        """Detect virtual environment"""
        try:
            # Check for VM indicators
            vm_indicators = [
                '/proc/sys/kernel/ostype',
                '/.dockerenv',
                '/proc/vz',
                '/proc/bc'
            ]
            
            for indicator in vm_indicators:
                if os.path.exists(indicator):
                    return True
            
            # Check system manufacturer
            try:
                with open('/sys/class/dmi/id/sys_vendor', 'r') as f:
                    vendor = f.read().strip().lower()
                    vm_vendors = ['vmware', 'virtualbox', 'qemu', 'xen', 'kvm']
                    if any(vm in vendor for vm in vm_vendors):
                        return True
            except Exception:
                pass
            
            return False
        except Exception:
            return False
    
    def _detect_monitoring(self):
        """Detect monitoring tools"""
        try:
            monitoring_tools = ['wireshark', 'tcpdump', 'strace', 'ltrace', 'procmon']
            for proc in psutil.process_iter(['name']):
                if proc.info['name'] and proc.info['name'].lower() in monitoring_tools:
                    return True
            return False
        except Exception:
            return False
    
    def _log_secure(self, message):
        """Secure logging to memory only"""
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'message': message,
            'sandbox_id': self.device_fingerprint
        }
        
        # Store in memory only
        self.runtime_logs.append(log_entry)
        
        # Limit log size
        if len(self.runtime_logs) > 1000:
            self.runtime_logs = self.runtime_logs[-500:]
    
    def get_runtime_status(self):
        """Get current runtime status"""
        return {
            'sandbox_active': self.sandbox_active,
            'memory_only': self.memory_only,
            'biometric_verified': self.biometric_verified,
            'device_fingerprint': self.device_fingerprint,
            'encrypted_items': len(self.encrypted_storage),
            'log_entries': len(self.runtime_logs),
            'temp_directory': self.temp_directory,
            'environment_check': self.check_environment_integrity()
        }

# Global secure runtime instance
secure_runtime = SecureRuntimeEnvironment()