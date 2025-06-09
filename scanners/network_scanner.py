import nmap
import socket
import threading
import time
from datetime import datetime
from security.anonymity import anonymity_manager
from security.encryption import encrypt_data

class NetworkScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.anonymity = anonymity_manager
    
    def scan_network(self, target, port_range='1-1000', scan_type='tcp', stealth_mode=True):
        """Perform network scan with anonymization"""
        results = {
            'target': target,
            'scan_started': datetime.utcnow().isoformat(),
            'scan_type': scan_type,
            'stealth_mode': stealth_mode,
            'hosts': {},
            'summary': {}
        }
        
        try:
            # Rotate identity if using Tor
            if stealth_mode:
                self.anonymity.rotate_identity()
                time.sleep(2)  # Wait for new identity
            
            # Configure scan arguments
            scan_args = self._build_scan_args(scan_type, stealth_mode)
            
            # Perform the scan
            print(f"Starting network scan of {target} with ports {port_range}")
            self.nm.scan(hosts=target, ports=port_range, arguments=scan_args)
            
            # Process results
            for host in self.nm.all_hosts():
                host_info = {
                    'state': self.nm[host].state(),
                    'hostname': self.nm[host].hostname(),
                    'protocols': {},
                    'os_detection': {},
                    'services': []
                }
                
                # Process each protocol
                for protocol in self.nm[host].all_protocols():
                    ports = self.nm[host][protocol].keys()
                    host_info['protocols'][protocol] = {}
                    
                    for port in ports:
                        port_info = self.nm[host][protocol][port]
                        host_info['protocols'][protocol][port] = {
                            'state': port_info['state'],
                            'name': port_info.get('name', ''),
                            'product': port_info.get('product', ''),
                            'version': port_info.get('version', ''),
                            'extrainfo': port_info.get('extrainfo', ''),
                            'reason': port_info.get('reason', ''),
                            'conf': port_info.get('conf', '')
                        }
                        
                        # Add to services list
                        if port_info['state'] == 'open':
                            service = {
                                'port': port,
                                'protocol': protocol,
                                'service': port_info.get('name', 'unknown'),
                                'product': port_info.get('product', ''),
                                'version': port_info.get('version', '')
                            }
                            host_info['services'].append(service)
                
                # OS Detection
                if 'osmatch' in self.nm[host]:
                    for osmatch in self.nm[host]['osmatch']:
                        host_info['os_detection'][osmatch['name']] = {
                            'accuracy': osmatch['accuracy'],
                            'line': osmatch['line']
                        }
                
                results['hosts'][host] = host_info
            
            # Generate summary
            results['summary'] = self._generate_summary(results['hosts'])
            results['scan_completed'] = datetime.utcnow().isoformat()
            results['status'] = 'completed'
            
        except Exception as e:
            results['error'] = str(e)
            results['status'] = 'failed'
            results['scan_completed'] = datetime.utcnow().isoformat()
        
        return results
    
    def _build_scan_args(self, scan_type, stealth_mode):
        """Build nmap scan arguments"""
        args = []
        
        if scan_type == 'tcp':
            args.append('-sS' if stealth_mode else '-sT')
        elif scan_type == 'udp':
            args.append('-sU')
        elif scan_type == 'comprehensive':
            args.extend(['-sS', '-sU', '-O', '--traceroute'])
        
        if stealth_mode:
            args.extend(['-T2', '--max-retries=1'])
        else:
            args.append('-T4')
        
        # Service detection
        args.extend(['-sV', '--version-intensity=5'])
        
        # OS detection
        args.append('-O')
        
        return ' '.join(args)
    
    def _generate_summary(self, hosts):
        """Generate scan summary"""
        summary = {
            'total_hosts': len(hosts),
            'hosts_up': 0,
            'total_ports': 0,
            'open_ports': 0,
            'services_found': [],
            'os_types': []
        }
        
        for host, host_info in hosts.items():
            if host_info['state'] == 'up':
                summary['hosts_up'] += 1
            
            for protocol, ports in host_info['protocols'].items():
                summary['total_ports'] += len(ports)
                for port, port_info in ports.items():
                    if port_info['state'] == 'open':
                        summary['open_ports'] += 1
                        service = port_info.get('name', 'unknown')
                        if service not in summary['services_found']:
                            summary['services_found'].append(service)
            
            # Collect OS information
            for os_name in host_info['os_detection'].keys():
                if os_name not in summary['os_types']:
                    summary['os_types'].append(os_name)
        
        return summary
    
    def ping_sweep(self, network):
        """Perform ping sweep to discover live hosts"""
        try:
            self.nm.scan(hosts=network, arguments='-sn')
            live_hosts = []
            
            for host in self.nm.all_hosts():
                if self.nm[host].state() == 'up':
                    live_hosts.append({
                        'ip': host,
                        'hostname': self.nm[host].hostname(),
                        'state': self.nm[host].state()
                    })
            
            return {
                'network': network,
                'live_hosts': live_hosts,
                'total_hosts': len(live_hosts)
            }
        except Exception as e:
            return {'error': str(e)}
    
    def port_scan_single_host(self, host, ports, timeout=10):
        """Fast port scan for single host"""
        open_ports = []
        
        if isinstance(ports, str):
            if '-' in ports:
                start, end = map(int, ports.split('-'))
                ports = range(start, end + 1)
            else:
                ports = [int(ports)]
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout / 1000.0)  # Convert to seconds
                result = sock.connect_ex((host, port))
                sock.close()
                
                if result == 0:
                    open_ports.append(port)
            except:
                pass
        
        # Use threading for faster scanning
        threads = []
        for port in ports:
            thread = threading.Thread(target=scan_port, args=(port,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        return sorted(open_ports)
