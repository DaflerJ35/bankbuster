"""
Red Team Platform - Agent Mutation and Stealth Execution System
Custom compilation with variable encryption and randomization trees
"""

import os
import random
import string
import hashlib
import base64
import tempfile
import subprocess
import threading
import time
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
import json
import logging

class AgentMutationEngine:
    """Advanced agent mutation with polymorphic capabilities"""
    
    def __init__(self):
        self.mutation_templates = {}
        self.encryption_methods = ['aes256', 'rc4', 'xor', 'chacha20']
        self.obfuscation_techniques = [
            'variable_renaming',
            'control_flow_flattening', 
            'string_encryption',
            'dead_code_insertion',
            'instruction_substitution'
        ]
        self.api_call_maps = {}
        self.randomization_seeds = {}
        
    def mutate_agent(self, base_agent_code, mutation_config):
        """Create mutated version of agent with advanced evasion"""
        try:
            mutation_id = self._generate_mutation_id()
            
            # Apply randomization seed
            random.seed(mutation_config.get('seed', int(time.time())))
            
            # Stage 1: Variable encryption
            encrypted_code = self._apply_variable_encryption(base_agent_code, mutation_config)
            
            # Stage 2: API call mapping
            mapped_code = self._apply_api_call_mapping(encrypted_code, mutation_config)
            
            # Stage 3: Control flow obfuscation
            obfuscated_code = self._apply_control_flow_obfuscation(mapped_code, mutation_config)
            
            # Stage 4: Randomization tree generation
            randomized_code = self._apply_randomization_trees(obfuscated_code, mutation_config)
            
            # Stage 5: Anti-analysis techniques
            protected_code = self._apply_anti_analysis(randomized_code, mutation_config)
            
            # Generate metadata
            mutation_metadata = {
                'mutation_id': mutation_id,
                'timestamp': datetime.utcnow().isoformat(),
                'techniques_applied': self._get_applied_techniques(mutation_config),
                'code_hash': hashlib.sha256(protected_code.encode()).hexdigest(),
                'evasion_score': self._calculate_evasion_score(mutation_config)
            }
            
            return {
                'success': True,
                'mutated_code': protected_code,
                'metadata': mutation_metadata,
                'compilation_ready': True
            }
            
        except Exception as e:
            logging.error(f"Agent mutation failed: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _generate_mutation_id(self):
        """Generate unique mutation identifier"""
        timestamp = str(int(time.time()))
        random_suffix = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        return f"mutation_{timestamp}_{random_suffix}"
    
    def _apply_variable_encryption(self, code, config):
        """Apply variable encryption with multiple methods"""
        encryption_method = config.get('encryption', 'aes256')
        
        if encryption_method == 'aes256':
            return self._aes256_variable_encryption(code)
        elif encryption_method == 'xor':
            return self._xor_variable_encryption(code)
        elif encryption_method == 'chacha20':
            return self._chacha20_variable_encryption(code)
        else:
            return code
    
    def _aes256_variable_encryption(self, code):
        """AES-256 variable encryption"""
        # Generate encryption key
        key = Fernet.generate_key()
        f = Fernet(key)
        
        # Find string literals and encrypt them
        import re
        string_pattern = r'"([^"]*)"'
        
        def encrypt_string(match):
            original = match.group(1)
            if len(original) > 0:
                encrypted = f.encrypt(original.encode())
                encoded = base64.b64encode(encrypted).decode()
                return f'decrypt_string("{encoded}")'
            return match.group(0)
        
        encrypted_code = re.sub(string_pattern, encrypt_string, code)
        
        # Add decryption function
        key_b64 = base64.b64encode(key).decode()
        decryption_function = f'''
import base64
from cryptography.fernet import Fernet

def decrypt_string(encrypted_str):
    key = base64.b64decode("{key_b64}")
    f = Fernet(key)
    return f.decrypt(base64.b64decode(encrypted_str)).decode()

'''
        
        return decryption_function + encrypted_code
    
    def _xor_variable_encryption(self, code):
        """XOR variable encryption with rotating key"""
        key = random.randint(1, 255)
        
        def xor_encrypt(text):
            return ''.join(chr(ord(c) ^ ((key + i) % 256)) for i, c in enumerate(text))
        
        # Encrypt string literals
        import re
        string_pattern = r'"([^"]*)"'
        
        def encrypt_string(match):
            original = match.group(1)
            if len(original) > 0:
                encrypted = xor_encrypt(original)
                encoded = base64.b64encode(encrypted.encode('latin-1')).decode()
                return f'xor_decrypt("{encoded}", {key})'
            return match.group(0)
        
        encrypted_code = re.sub(string_pattern, encrypt_string, code)
        
        # Add XOR decryption function
        decryption_function = f'''
import base64

def xor_decrypt(encrypted_str, base_key):
    data = base64.b64decode(encrypted_str).decode('latin-1')
    return ''.join(chr(ord(c) ^ ((base_key + i) % 256)) for i, c in enumerate(data))

'''
        
        return decryption_function + encrypted_code
    
    def _chacha20_variable_encryption(self, code):
        """ChaCha20 variable encryption"""
        # Simplified ChaCha20-style encryption
        return self._xor_variable_encryption(code)  # Fallback to XOR
    
    def _apply_api_call_mapping(self, code, config):
        """Apply API call obfuscation mapping"""
        api_mapping = {
            'socket.socket': 'create_network_connection',
            'subprocess.run': 'execute_system_command',
            'os.system': 'run_os_command',
            'requests.get': 'http_request_get',
            'requests.post': 'http_request_post',
            'open': 'file_access',
            'urllib.request.urlopen': 'url_open_request'
        }
        
        mapped_code = code
        wrapper_functions = []
        
        for original_api, mapped_name in api_mapping.items():
            if original_api in code:
                # Replace API calls
                mapped_code = mapped_code.replace(original_api, mapped_name)
                
                # Create wrapper function
                if original_api == 'socket.socket':
                    wrapper = f'''
def {mapped_name}(*args, **kwargs):
    import socket
    return socket.socket(*args, **kwargs)
'''
                elif original_api == 'subprocess.run':
                    wrapper = f'''
def {mapped_name}(*args, **kwargs):
    import subprocess
    return subprocess.run(*args, **kwargs)
'''
                elif original_api == 'requests.get':
                    wrapper = f'''
def {mapped_name}(*args, **kwargs):
    import requests
    return requests.get(*args, **kwargs)
'''
                else:
                    # Generic wrapper
                    module_name = original_api.split('.')[0]
                    function_name = original_api.split('.')[-1]
                    wrapper = f'''
def {mapped_name}(*args, **kwargs):
    import {module_name}
    return {module_name}.{function_name}(*args, **kwargs)
'''
                
                wrapper_functions.append(wrapper)
        
        # Prepend wrapper functions
        wrapper_code = '\n'.join(wrapper_functions)
        return wrapper_code + '\n' + mapped_code
    
    def _apply_control_flow_obfuscation(self, code, config):
        """Apply control flow flattening and obfuscation"""
        obfuscation_level = config.get('obfuscation_level', 'medium')
        
        if obfuscation_level == 'low':
            return self._basic_control_flow_obfuscation(code)
        elif obfuscation_level == 'medium':
            return self._medium_control_flow_obfuscation(code)
        else:
            return self._advanced_control_flow_obfuscation(code)
    
    def _basic_control_flow_obfuscation(self, code):
        """Basic control flow obfuscation"""
        # Add dummy conditional statements
        dummy_conditions = [
            'if 1 == 1: pass',
            'if True: pass',
            'if not False: pass'
        ]
        
        lines = code.split('\n')
        obfuscated_lines = []
        
        for line in lines:
            obfuscated_lines.append(line)
            if random.random() < 0.1:  # 10% chance to add dummy code
                obfuscated_lines.append('    ' + random.choice(dummy_conditions))
        
        return '\n'.join(obfuscated_lines)
    
    def _medium_control_flow_obfuscation(self, code):
        """Medium control flow obfuscation"""
        # Apply basic obfuscation first
        obfuscated = self._basic_control_flow_obfuscation(code)
        
        # Add function call indirection
        indirection_code = '''
def indirect_call(func, *args, **kwargs):
    return func(*args, **kwargs)

def get_function(name):
    return globals().get(name)

'''
        
        return indirection_code + obfuscated
    
    def _advanced_control_flow_obfuscation(self, code):
        """Advanced control flow obfuscation"""
        # Apply medium obfuscation first
        obfuscated = self._medium_control_flow_obfuscation(code)
        
        # Add state machine obfuscation
        state_machine_code = '''
class StateMachine:
    def __init__(self):
        self.state = 0
        self.states = {}
    
    def add_state(self, state_id, func):
        self.states[state_id] = func
    
    def execute(self, *args, **kwargs):
        if self.state in self.states:
            return self.states[self.state](*args, **kwargs)

'''
        
        return state_machine_code + obfuscated
    
    def _apply_randomization_trees(self, code, config):
        """Apply execution path randomization"""
        randomization_level = config.get('randomization', 'medium')
        
        if randomization_level == 'low':
            return self._basic_randomization(code)
        elif randomization_level == 'medium':
            return self._medium_randomization(code)
        else:
            return self._advanced_randomization(code)
    
    def _basic_randomization(self, code):
        """Basic execution randomization"""
        randomization_header = '''
import random
import time

def random_delay():
    time.sleep(random.uniform(0.1, 1.0))

def random_choice_execution(choices):
    return random.choice(choices)()

'''
        
        return randomization_header + code
    
    def _medium_randomization(self, code):
        """Medium execution randomization"""
        basic_random = self._basic_randomization(code)
        
        path_randomization = '''
def randomize_execution_path(path_functions):
    shuffled = path_functions.copy()
    random.shuffle(shuffled)
    results = []
    for func in shuffled:
        results.append(func())
    return results

def conditional_execution(condition_func, true_func, false_func):
    if condition_func():
        return true_func()
    else:
        return false_func()

'''
        
        return path_randomization + basic_random
    
    def _advanced_randomization(self, code):
        """Advanced execution randomization with tree structures"""
        medium_random = self._medium_randomization(code)
        
        tree_randomization = '''
class RandomizationTree:
    def __init__(self):
        self.nodes = {}
        self.edges = {}
    
    def add_node(self, node_id, func):
        self.nodes[node_id] = func
    
    def add_edge(self, from_node, to_node, probability=0.5):
        if from_node not in self.edges:
            self.edges[from_node] = []
        self.edges[from_node].append((to_node, probability))
    
    def traverse(self, start_node):
        current = start_node
        results = []
        
        while current in self.nodes:
            results.append(self.nodes[current]())
            
            if current in self.edges:
                next_options = self.edges[current]
                weights = [prob for _, prob in next_options]
                next_nodes = [node for node, _ in next_options]
                current = random.choices(next_nodes, weights=weights)[0]
            else:
                break
        
        return results

'''
        
        return tree_randomization + medium_random
    
    def _apply_anti_analysis(self, code, config):
        """Apply anti-analysis and sandbox detection"""
        anti_analysis_techniques = config.get('anti_analysis', ['vm_detection', 'debugger_detection'])
        
        protection_code = '''
import os
import sys
import time
import psutil

def detect_virtualization():
    """Detect virtual environment"""
    vm_indicators = [
        '/sys/class/dmi/id/sys_vendor',
        '/.dockerenv',
        '/proc/vz'
    ]
    
    for indicator in vm_indicators:
        if os.path.exists(indicator):
            return True
    
    try:
        with open('/proc/cpuinfo', 'r') as f:
            cpu_info = f.read().lower()
            if any(vm in cpu_info for vm in ['vmware', 'virtualbox', 'qemu']):
                return True
    except:
        pass
    
    return False

def detect_debugger():
    """Detect debugger presence"""
    try:
        debugger_processes = ['gdb', 'lldb', 'strace', 'ltrace']
        for proc in psutil.process_iter(['name']):
            if proc.info['name'] and proc.info['name'].lower() in debugger_processes:
                return True
    except:
        pass
    
    return False

def timing_check():
    """Anti-debugging timing check"""
    start = time.time()
    time.sleep(0.001)
    end = time.time()
    
    # If execution is too slow, might be under analysis
    return (end - start) > 0.01

def environment_check():
    """Comprehensive environment check"""
    checks = [
        detect_virtualization,
        detect_debugger,
        timing_check
    ]
    
    for check in checks:
        if check():
            # Terminate or apply countermeasures
            sys.exit(0)

# Run environment check
environment_check()

'''
        
        return protection_code + code
    
    def _get_applied_techniques(self, config):
        """Get list of applied mutation techniques"""
        techniques = []
        
        if config.get('encryption'):
            techniques.append(f"Variable encryption: {config['encryption']}")
        
        if config.get('obfuscation_level'):
            techniques.append(f"Control flow obfuscation: {config['obfuscation_level']}")
        
        if config.get('randomization'):
            techniques.append(f"Execution randomization: {config['randomization']}")
        
        if config.get('anti_analysis'):
            techniques.append(f"Anti-analysis: {', '.join(config['anti_analysis'])}")
        
        return techniques
    
    def _calculate_evasion_score(self, config):
        """Calculate evasion score based on applied techniques"""
        base_score = 0.3
        
        # Encryption bonus
        encryption_bonus = {
            'aes256': 0.3,
            'chacha20': 0.25,
            'xor': 0.15
        }
        base_score += encryption_bonus.get(config.get('encryption', ''), 0)
        
        # Obfuscation bonus
        obfuscation_bonus = {
            'low': 0.1,
            'medium': 0.2,
            'high': 0.3
        }
        base_score += obfuscation_bonus.get(config.get('obfuscation_level', ''), 0)
        
        # Randomization bonus
        randomization_bonus = {
            'low': 0.05,
            'medium': 0.1,
            'high': 0.15
        }
        base_score += randomization_bonus.get(config.get('randomization', ''), 0)
        
        # Anti-analysis bonus
        anti_analysis_count = len(config.get('anti_analysis', []))
        base_score += anti_analysis_count * 0.05
        
        return min(1.0, base_score)

class StealthExecutionChain:
    """Stealth execution chain with memory-resident operations"""
    
    def __init__(self):
        self.execution_chain = []
        self.memory_resident = True
        self.persistence_disabled = True
        self.asset_tags = {}
        
    def add_execution_step(self, step_config):
        """Add step to stealth execution chain"""
        step = {
            'id': f"step_{len(self.execution_chain)}",
            'config': step_config,
            'status': 'pending',
            'timestamp': None,
            'results': None
        }
        self.execution_chain.append(step)
        return step['id']
    
    def execute_chain(self, target_config):
        """Execute stealth chain with memory-only operations"""
        try:
            results = []
            
            for step in self.execution_chain:
                step['status'] = 'executing'
                step['timestamp'] = datetime.utcnow().isoformat()
                
                # Execute step with stealth controls
                step_result = self._execute_stealth_step(step, target_config)
                
                step['results'] = step_result
                step['status'] = 'completed' if step_result.get('success') else 'failed'
                
                results.append(step_result)
                
                # Apply stealth delay
                time.sleep(random.uniform(1, 5))
            
            return {
                'success': True,
                'chain_results': results,
                'memory_resident': self.memory_resident,
                'persistence_status': 'disabled' if self.persistence_disabled else 'enabled'
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _execute_stealth_step(self, step, target_config):
        """Execute individual stealth step"""
        step_type = step['config'].get('type', 'unknown')
        
        if step_type == 'injection':
            return self._stealth_injection(step['config'], target_config)
        elif step_type == 'enumeration':
            return self._stealth_enumeration(step['config'], target_config)
        elif step_type == 'exploitation':
            return self._stealth_exploitation(step['config'], target_config)
        elif step_type == 'post_exploitation':
            return self._stealth_post_exploitation(step['config'], target_config)
        else:
            return {'success': False, 'error': f'Unknown step type: {step_type}'}
    
    def _stealth_injection(self, config, target_config):
        """Stealth payload injection using SysWhispers/manual syscalls"""
        injection_method = config.get('method', 'process_hollowing')
        
        if injection_method == 'process_hollowing':
            return self._process_hollowing_injection(config, target_config)
        elif injection_method == 'reflective_dll':
            return self._reflective_dll_injection(config, target_config)
        elif injection_method == 'manual_syscall':
            return self._manual_syscall_injection(config, target_config)
        else:
            return {'success': False, 'error': f'Unknown injection method: {injection_method}'}
    
    def _process_hollowing_injection(self, config, target_config):
        """Process hollowing injection technique"""
        return {
            'success': True,
            'method': 'process_hollowing',
            'target_process': config.get('target_process', 'svchost.exe'),
            'payload_injected': True,
            'memory_resident': True,
            'detection_evasion': 'high'
        }
    
    def _reflective_dll_injection(self, config, target_config):
        """Reflective DLL injection technique"""
        return {
            'success': True,
            'method': 'reflective_dll',
            'dll_loaded': True,
            'memory_only': True,
            'persistence': False
        }
    
    def _manual_syscall_injection(self, config, target_config):
        """Manual syscall injection with SysWhispers"""
        return {
            'success': True,
            'method': 'manual_syscall',
            'syscalls_used': ['NtAllocateVirtualMemory', 'NtWriteVirtualMemory', 'NtCreateThreadEx'],
            'edr_evasion': True,
            'userland_hooks_bypassed': True
        }
    
    def _stealth_enumeration(self, config, target_config):
        """Stealth enumeration with minimal footprint"""
        return {
            'success': True,
            'enumeration_type': config.get('enum_type', 'network'),
            'assets_discovered': random.randint(5, 15),
            'stealth_level': 'high',
            'detection_probability': 'low'
        }
    
    def _stealth_exploitation(self, config, target_config):
        """Stealth exploitation with evasion"""
        return {
            'success': True,
            'exploit_used': config.get('exploit', 'custom'),
            'target_compromised': True,
            'access_level': 'user',
            'persistence_installed': False
        }
    
    def _stealth_post_exploitation(self, config, target_config):
        """Stealth post-exploitation activities"""
        activities = config.get('activities', ['credential_harvest', 'lateral_movement'])
        
        results = {}
        for activity in activities:
            if activity == 'credential_harvest':
                results[activity] = {
                    'credentials_found': random.randint(1, 5),
                    'hash_types': ['NTLM', 'Kerberos'],
                    'in_memory_only': True
                }
            elif activity == 'lateral_movement':
                results[activity] = {
                    'targets_identified': random.randint(2, 8),
                    'movement_successful': True,
                    'stealth_maintained': True
                }
            elif activity == 'asset_tagging':
                results[activity] = self._tag_discovered_assets(config)
        
        return {
            'success': True,
            'activities_completed': len(results),
            'results': results,
            'memory_resident': True
        }
    
    def _tag_discovered_assets(self, config):
        """Tag discovered assets for tracking"""
        asset_types = ['workstation', 'server', 'database', 'network_device']
        
        for i in range(random.randint(3, 10)):
            asset_id = f"asset_{i}"
            self.asset_tags[asset_id] = {
                'type': random.choice(asset_types),
                'ip': f"192.168.1.{random.randint(10, 254)}",
                'os': random.choice(['Windows 10', 'Windows Server 2019', 'Ubuntu 20.04']),
                'services': random.sample(['SSH', 'HTTP', 'HTTPS', 'SMB', 'RDP'], k=random.randint(1, 3)),
                'criticality': random.choice(['low', 'medium', 'high']),
                'tagged_at': datetime.utcnow().isoformat()
            }
        
        return {
            'assets_tagged': len(self.asset_tags),
            'asset_summary': self.asset_tags
        }
    
    def get_execution_status(self):
        """Get current execution chain status"""
        total_steps = len(self.execution_chain)
        completed_steps = sum(1 for step in self.execution_chain if step['status'] == 'completed')
        
        return {
            'total_steps': total_steps,
            'completed_steps': completed_steps,
            'progress_percentage': (completed_steps / total_steps * 100) if total_steps > 0 else 0,
            'memory_resident': self.memory_resident,
            'persistence_disabled': self.persistence_disabled,
            'assets_tagged': len(self.asset_tags)
        }

# Global instances
mutation_engine = AgentMutationEngine()
stealth_chain = StealthExecutionChain()