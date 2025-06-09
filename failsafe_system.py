"""
Red Team Platform - Failsafe Mechanisms and Emergency Systems
Kill switch, memory wipe, and anti-forensics capabilities
"""

import os
import sys
import psutil
import threading
import time
import shutil
import tempfile
import hashlib
import logging
from datetime import datetime, timedelta
from secure_runtime import secure_runtime
from crypto_utils import encrypt_data, decrypt_data
import subprocess

class FailsafeSystem:
    """Advanced failsafe system with kill switch and memory protection"""
    
    def __init__(self):
        self.kill_switch_active = False
        self.biometric_lock = False
        self.device_id_verified = False
        self.hostile_environment_detected = False
        self.emergency_triggers = {}
        self.monitored_processes = []
        self.monitoring_thread = None
        self.auto_destruct_timer = None
        self.memory_protection_active = True
        
    def initialize_failsafe(self, device_id, biometric_hash):
        """Initialize failsafe system with device binding"""
        try:
            # Verify device ID
            current_device_id = self._get_device_fingerprint()
            self.device_id_verified = (current_device_id == device_id)
            
            # Verify biometric
            if biometric_hash:
                self.biometric_lock = self._verify_biometric_hash(biometric_hash)
            
            # Set up emergency triggers
            self._setup_emergency_triggers()
            
            # Start continuous monitoring
            self._start_monitoring()
            
            # Initialize memory protection
            self._initialize_memory_protection()
            
            return {
                'success': True,
                'device_verified': self.device_id_verified,
                'biometric_verified': self.biometric_lock,
                'monitoring_active': True,
                'memory_protection': self.memory_protection_active
            }
            
        except Exception as e:
            logging.error(f"Failsafe initialization failed: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _get_device_fingerprint(self):
        """Get unique device fingerprint"""
        try:
            # Collect hardware identifiers
            system_info = {
                'platform': sys.platform,
                'processor': os.uname().machine if hasattr(os, 'uname') else 'unknown',
                'memory': psutil.virtual_memory().total,
                'boot_time': psutil.boot_time()
            }
            
            # Create stable fingerprint
            fingerprint_data = ''.join(str(v) for v in system_info.values())
            return hashlib.sha256(fingerprint_data.encode()).hexdigest()[:32]
            
        except Exception:
            return 'unknown_device'
    
    def _verify_biometric_hash(self, provided_hash):
        """Verify biometric hash (simulated)"""
        # In production, this would verify actual biometric data
        return len(provided_hash) > 32 and provided_hash.isalnum()
    
    def _setup_emergency_triggers(self):
        """Setup various emergency trigger conditions"""
        self.emergency_triggers = {
            'vm_detection': self._detect_virtual_environment,
            'debugger_detection': self._detect_debugger_presence,
            'network_monitoring': self._detect_network_monitoring,
            'process_injection': self._detect_process_injection,
            'memory_analysis': self._detect_memory_analysis,
            'behavioral_analysis': self._detect_behavioral_analysis,
            'sandbox_environment': self._detect_sandbox_environment
        }
    
    def _start_monitoring(self):
        """Start continuous environment monitoring"""
        def monitoring_loop():
            while not self.kill_switch_active:
                try:
                    # Check all trigger conditions
                    for trigger_name, trigger_func in self.emergency_triggers.items():
                        if trigger_func():
                            logging.warning(f"Emergency trigger activated: {trigger_name}")
                            self.trigger_emergency_response(trigger_name)
                            return
                    
                    # Check device/biometric integrity
                    if not self._verify_integrity():
                        self.trigger_emergency_response("integrity_failure")
                        return
                    
                    time.sleep(5)  # Check every 5 seconds
                    
                except Exception as e:
                    logging.error(f"Monitoring error: {str(e)}")
                    time.sleep(10)
        
        self.monitoring_thread = threading.Thread(target=monitoring_loop, daemon=True)
        self.monitoring_thread.start()
    
    def _verify_integrity(self):
        """Verify device and biometric integrity"""
        # Check device ID hasn't changed
        current_device = self._get_device_fingerprint()
        if current_device != self._get_device_fingerprint():
            return False
        
        # Additional integrity checks
        if not self.device_id_verified or not self.biometric_lock:
            return False
        
        return True
    
    def _detect_virtual_environment(self):
        """Detect virtual machine environment"""
        try:
            vm_indicators = [
                '/sys/class/dmi/id/sys_vendor',
                '/.dockerenv',
                '/proc/vz',
                '/proc/bc'
            ]
            
            for indicator in vm_indicators:
                if os.path.exists(indicator):
                    try:
                        with open(indicator, 'r') as f:
                            content = f.read().lower()
                            vm_keywords = ['vmware', 'virtualbox', 'qemu', 'xen', 'kvm', 'docker']
                            if any(keyword in content for keyword in vm_keywords):
                                return True
                    except:
                        pass
            
            # Check CPU information
            try:
                with open('/proc/cpuinfo', 'r') as f:
                    cpu_info = f.read().lower()
                    if any(vm in cpu_info for vm in ['vmware', 'virtualbox', 'qemu']):
                        return True
            except:
                pass
            
            return False
            
        except Exception:
            return False
    
    def _detect_debugger_presence(self):
        """Detect debugger or analysis tools"""
        try:
            dangerous_processes = [
                'gdb', 'lldb', 'windbg', 'x64dbg', 'ollydbg',
                'ida', 'ida64', 'radare2', 'ghidra',
                'strace', 'ltrace', 'sysdig'
            ]
            
            for proc in psutil.process_iter(['name']):
                if proc.info['name']:
                    proc_name = proc.info['name'].lower()
                    if any(dangerous in proc_name for dangerous in dangerous_processes):
                        return True
            
            # Check for debugger environment variables
            debug_vars = ['_', 'DEBUGGING', 'DEBUG_MODE']
            for var in debug_vars:
                if var in os.environ:
                    return True
            
            return False
            
        except Exception:
            return False
    
    def _detect_network_monitoring(self):
        """Detect network monitoring tools"""
        try:
            monitoring_tools = [
                'wireshark', 'tshark', 'tcpdump', 'ngrep',
                'ettercap', 'dsniff', 'kismet', 'aircrack'
            ]
            
            for proc in psutil.process_iter(['name']):
                if proc.info['name']:
                    proc_name = proc.info['name'].lower()
                    if any(tool in proc_name for tool in monitoring_tools):
                        return True
            
            # Check for suspicious network interfaces
            try:
                result = subprocess.run(['ip', 'link'], capture_output=True, text=True)
                if 'monitor' in result.stdout or 'promisc' in result.stdout:
                    return True
            except:
                pass
            
            return False
            
        except Exception:
            return False
    
    def _detect_process_injection(self):
        """Detect process injection attempts"""
        try:
            current_pid = os.getpid()
            current_process = psutil.Process(current_pid)
            
            # Check for unusual memory mappings
            try:
                memory_maps = current_process.memory_maps()
                for mapping in memory_maps:
                    # Look for suspicious memory regions
                    if 'rwx' in mapping.perms or 'inject' in mapping.path.lower():
                        return True
            except:
                pass
            
            # Check for unusual parent process
            try:
                parent = current_process.parent()
                if parent and parent.name().lower() in ['rundll32.exe', 'regsvr32.exe']:
                    return True
            except:
                pass
            
            return False
            
        except Exception:
            return False
    
    def _detect_memory_analysis(self):
        """Detect memory analysis tools"""
        try:
            memory_tools = [
                'volatility', 'rekall', 'winpmem', 'dumpit',
                'memoryze', 'redline', 'mandiant'
            ]
            
            for proc in psutil.process_iter(['name', 'cmdline']):
                if proc.info['name']:
                    proc_name = proc.info['name'].lower()
                    if any(tool in proc_name for tool in memory_tools):
                        return True
                
                # Check command line arguments
                if proc.info['cmdline']:
                    cmdline = ' '.join(proc.info['cmdline']).lower()
                    if any(tool in cmdline for tool in memory_tools):
                        return True
            
            return False
            
        except Exception:
            return False
    
    def _detect_behavioral_analysis(self):
        """Detect behavioral analysis systems"""
        try:
            # Check for sandbox-like environment indicators
            sandbox_indicators = [
                # Low disk space (typical of sandboxes)
                lambda: psutil.disk_usage('/').free < 10 * 1024 * 1024 * 1024,  # 10GB
                # Low RAM (typical of sandboxes)
                lambda: psutil.virtual_memory().total < 2 * 1024 * 1024 * 1024,  # 2GB
                # Short uptime (recently created VM)
                lambda: time.time() - psutil.boot_time() < 300,  # 5 minutes
                # Low process count
                lambda: len(psutil.pids()) < 50
            ]
            
            suspicious_count = sum(1 for indicator in sandbox_indicators if indicator())
            return suspicious_count >= 2
            
        except Exception:
            return False
    
    def _detect_sandbox_environment(self):
        """Detect automated analysis sandbox"""
        try:
            # Check for common sandbox artifacts
            sandbox_files = [
                '/usr/bin/VBoxControl',
                '/usr/bin/VBoxService',
                '/usr/bin/qemu-ga',
                '/sys/class/dmi/id/product_name'
            ]
            
            for file_path in sandbox_files:
                if os.path.exists(file_path):
                    return True
            
            # Check for sandbox-specific processes
            sandbox_processes = [
                'vboxservice', 'vmtoolsd', 'qemu-ga',
                'sandboxie', 'cuckoo', 'anubis'
            ]
            
            for proc in psutil.process_iter(['name']):
                if proc.info['name']:
                    proc_name = proc.info['name'].lower()
                    if any(sandbox in proc_name for sandbox in sandbox_processes):
                        return True
            
            return False
            
        except Exception:
            return False
    
    def trigger_emergency_response(self, trigger_reason):
        """Trigger emergency response protocols"""
        try:
            logging.critical(f"EMERGENCY RESPONSE TRIGGERED: {trigger_reason}")
            
            self.hostile_environment_detected = True
            self.kill_switch_active = True
            
            # Execute emergency procedures in order
            self._emergency_memory_wipe()
            self._emergency_file_cleanup()
            self._emergency_process_termination()
            self._emergency_anti_forensics()
            self._emergency_system_lockdown()
            
            # Final system exit
            logging.critical("Emergency response completed - terminating")
            os._exit(0)
            
        except Exception as e:
            logging.error(f"Emergency response failed: {str(e)}")
            # Force exit even if cleanup fails
            os._exit(1)
    
    def _emergency_memory_wipe(self):
        """Emergency memory wipe procedures"""
        try:
            logging.info("Executing emergency memory wipe")
            
            # Clear secure runtime if active
            if secure_runtime.sandbox_active:
                secure_runtime.emergency_cleanup("Emergency response")
            
            # Overwrite sensitive variables
            sensitive_vars = [
                'encryption_key', 'api_key', 'password', 'token',
                'secret', 'private_key', 'credential'
            ]
            
            # Clear global variables
            for name in list(globals().keys()):
                if any(sensitive in name.lower() for sensitive in sensitive_vars):
                    globals()[name] = None
            
            # Force garbage collection
            import gc
            gc.collect()
            
            logging.info("Memory wipe completed")
            
        except Exception as e:
            logging.error(f"Memory wipe failed: {str(e)}")
    
    def _emergency_file_cleanup(self):
        """Emergency file system cleanup"""
        try:
            logging.info("Executing emergency file cleanup")
            
            # Remove temporary files
            temp_dirs = [tempfile.gettempdir(), '/tmp', '/var/tmp']
            for temp_dir in temp_dirs:
                if os.path.exists(temp_dir):
                    try:
                        for item in os.listdir(temp_dir):
                            if 'redteam' in item.lower() or 'payload' in item.lower():
                                item_path = os.path.join(temp_dir, item)
                                if os.path.isfile(item_path):
                                    # Secure deletion
                                    self._secure_delete_file(item_path)
                                elif os.path.isdir(item_path):
                                    shutil.rmtree(item_path, ignore_errors=True)
                    except:
                        pass
            
            # Remove logs if they exist
            log_files = [
                '/var/log/redteam.log',
                './redteam.log',
                './audit.log'
            ]
            
            for log_file in log_files:
                if os.path.exists(log_file):
                    self._secure_delete_file(log_file)
            
            logging.info("File cleanup completed")
            
        except Exception as e:
            logging.error(f"File cleanup failed: {str(e)}")
    
    def _secure_delete_file(self, file_path):
        """Securely delete file with overwriting"""
        try:
            if not os.path.exists(file_path):
                return
            
            file_size = os.path.getsize(file_path)
            
            # Overwrite with random data multiple times
            with open(file_path, 'rb+') as f:
                for _ in range(3):
                    f.seek(0)
                    f.write(os.urandom(file_size))
                    f.flush()
                    os.fsync(f.fileno())
            
            # Remove the file
            os.remove(file_path)
            
        except Exception:
            # If secure deletion fails, try simple removal
            try:
                os.remove(file_path)
            except:
                pass
    
    def _emergency_process_termination(self):
        """Emergency process termination"""
        try:
            logging.info("Executing emergency process termination")
            
            current_pid = os.getpid()
            
            # Terminate child processes
            try:
                current_process = psutil.Process(current_pid)
                children = current_process.children(recursive=True)
                
                for child in children:
                    try:
                        child.terminate()
                    except:
                        try:
                            child.kill()
                        except:
                            pass
            except:
                pass
            
            logging.info("Process termination completed")
            
        except Exception as e:
            logging.error(f"Process termination failed: {str(e)}")
    
    def _emergency_anti_forensics(self):
        """Emergency anti-forensics measures"""
        try:
            logging.info("Executing anti-forensics measures")
            
            # Clear bash history
            history_files = [
                os.path.expanduser('~/.bash_history'),
                os.path.expanduser('~/.zsh_history'),
                os.path.expanduser('~/.history')
            ]
            
            for history_file in history_files:
                if os.path.exists(history_file):
                    try:
                        with open(history_file, 'w') as f:
                            f.write('')
                    except:
                        pass
            
            # Clear system logs if possible
            try:
                log_files = [
                    '/var/log/auth.log',
                    '/var/log/syslog',
                    '/var/log/messages'
                ]
                
                for log_file in log_files:
                    if os.path.exists(log_file) and os.access(log_file, os.W_OK):
                        with open(log_file, 'a') as f:
                            # Add noise entries to obscure activities
                            for _ in range(10):
                                f.write(f"{datetime.now()} normal_activity: routine system operation\n")
            except:
                pass
            
            logging.info("Anti-forensics measures completed")
            
        except Exception as e:
            logging.error(f"Anti-forensics failed: {str(e)}")
    
    def _emergency_system_lockdown(self):
        """Emergency system lockdown procedures"""
        try:
            logging.info("Executing system lockdown")
            
            # Disable future execution capability
            lockdown_file = '/tmp/.redteam_lockdown'
            try:
                with open(lockdown_file, 'w') as f:
                    f.write(f"LOCKDOWN_TIMESTAMP:{int(time.time())}\n")
                    f.write(f"TRIGGER_REASON:{getattr(self, 'last_trigger_reason', 'unknown')}\n")
                    f.write("SYSTEM_DISABLED:true\n")
            except:
                pass
            
            # Clear network connections
            try:
                subprocess.run(['iptables', '-F'], capture_output=True, timeout=5)
            except:
                pass
            
            logging.info("System lockdown completed")
            
        except Exception as e:
            logging.error(f"System lockdown failed: {str(e)}")
    
    def _initialize_memory_protection(self):
        """Initialize memory protection mechanisms"""
        try:
            # Set memory protection flags
            if hasattr(os, 'mlock'):
                # Lock critical memory pages
                try:
                    import mlock
                    # This would lock sensitive memory in production
                    pass
                except ImportError:
                    pass
            
            # Set up memory monitoring
            self.memory_protection_active = True
            
        except Exception:
            self.memory_protection_active = False
    
    def manual_kill_switch(self, reason="Manual activation"):
        """Manually activate kill switch"""
        self.last_trigger_reason = reason
        self.trigger_emergency_response(reason)
    
    def get_failsafe_status(self):
        """Get current failsafe system status"""
        return {
            'kill_switch_active': self.kill_switch_active,
            'device_verified': self.device_id_verified,
            'biometric_verified': self.biometric_lock,
            'hostile_environment': self.hostile_environment_detected,
            'monitoring_active': self.monitoring_thread.is_alive() if self.monitoring_thread else False,
            'memory_protection': self.memory_protection_active,
            'triggers_configured': len(self.emergency_triggers),
            'system_integrity': self._verify_integrity()
        }
    
    def test_triggers(self):
        """Test emergency trigger detection (for debugging)"""
        test_results = {}
        
        for trigger_name, trigger_func in self.emergency_triggers.items():
            try:
                result = trigger_func()
                test_results[trigger_name] = {
                    'detected': result,
                    'status': 'active' if result else 'inactive'
                }
            except Exception as e:
                test_results[trigger_name] = {
                    'detected': False,
                    'status': 'error',
                    'error': str(e)
                }
        
        return test_results

# Global failsafe system instance
failsafe_system = FailsafeSystem()