import nmap
import socket
import threading
import time
import json
from datetime import datetime
from models import ScanSession, Finding
from app import db
from crypto_utils import encrypt_data
from anonymity_manager import AnonymityManager
import logging

class NetworkScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.anonymity = AnonymityManager()
        self.is_scanning = False
        self.scan_results = {}
    
    def scan_network(self, session_id, targets, scan_type='basic', use_anonymity=True):
        """
        Perform network scan with anonymity protection
        scan_type: basic, stealth, aggressive, custom
        """
        try:
            session = ScanSession.query.get(session_id)
            if not session:
                logging.error(f"Scan session {session_id} not found")
                return False
            
            session.status = 'running'
            db.session.commit()
            
            self.is_scanning = True
            results = []
            
            # Configure proxy if anonymity is enabled
            if use_anonymity:
                self.anonymity.setup_tor_proxy()
            
            for target in targets:
                if not self.is_scanning:
                    break
                
                target_results = self._scan_single_target(target, scan_type)
                results.extend(target_results)
                
                # Store findings in database
                for result in target_results:
                    finding = Finding(
                        scan_session_id=session_id,
                        finding_type='open_port',
                        severity=self._calculate_port_severity(result['port'], result['service']),
                        title=f"Open Port: {result['port']}/{result['protocol']}",
                        description=encrypt_data(json.dumps({
                            'service': result['service'],
                            'version': result.get('version', 'Unknown'),
                            'state': result['state'],
                            'reason': result.get('reason', '')
                        })),
                        target_host=encrypt_data(result['host']),
                        target_port=result['port']
                    )
                    db.session.add(finding)
            
            session.status = 'completed'
            db.session.commit()
            
            self.scan_results[session_id] = results
            self.is_scanning = False
            
            return True
            
        except Exception as e:
            logging.error(f"Network scan failed: {str(e)}")
            session.status = 'failed'
            db.session.commit()
            self.is_scanning = False
            return False
    
    def _scan_single_target(self, target, scan_type):
        """Scan a single target with specified scan type"""
        results = []
        
        try:
            # Determine nmap arguments based on scan type
            nmap_args = self._get_nmap_args(scan_type)
            
            # Perform the scan
            scan_result = self.nm.scan(target, arguments=nmap_args)
            
            for host in scan_result['scan']:
                if 'tcp' in scan_result['scan'][host]:
                    for port in scan_result['scan'][host]['tcp']:
                        port_info = scan_result['scan'][host]['tcp'][port]
                        
                        result = {
                            'host': host,
                            'port': port,
                            'protocol': 'tcp',
                            'state': port_info['state'],
                            'service': port_info.get('name', 'unknown'),
                            'version': port_info.get('version', ''),
                            'product': port_info.get('product', ''),
                            'reason': port_info.get('reason', ''),
                            'timestamp': datetime.utcnow().isoformat()
                        }
                        results.append(result)
                
                if 'udp' in scan_result['scan'][host]:
                    for port in scan_result['scan'][host]['udp']:
                        port_info = scan_result['scan'][host]['udp'][port]
                        
                        result = {
                            'host': host,
                            'port': port,
                            'protocol': 'udp',
                            'state': port_info['state'],
                            'service': port_info.get('name', 'unknown'),
                            'version': port_info.get('version', ''),
                            'product': port_info.get('product', ''),
                            'reason': port_info.get('reason', ''),
                            'timestamp': datetime.utcnow().isoformat()
                        }
                        results.append(result)
        
        except Exception as e:
            logging.error(f"Error scanning target {target}: {str(e)}")
        
        return results
    
    def _get_nmap_args(self, scan_type):
        """Get nmap arguments based on scan type"""
        args_map = {
            'basic': '-sS -O -sV',
            'stealth': '-sS -T2 -f --scan-delay 1s',
            'aggressive': '-sS -sV -O -A -T4',
            'comprehensive': '-sS -sU -sV -O -A -p-',
            'custom': '-sS -sV -O'
        }
        return args_map.get(scan_type, args_map['basic'])
    
    def _calculate_port_severity(self, port, service):
        """Calculate severity based on port and service"""
        critical_ports = [22, 23, 3389, 5900, 1433, 3306, 5432, 1521]
        high_risk_ports = [21, 25, 53, 80, 110, 143, 443, 993, 995]
        
        if port in critical_ports:
            return 'critical'
        elif port in high_risk_ports:
            return 'high'
        elif service in ['ssh', 'telnet', 'ftp', 'mysql', 'postgresql']:
            return 'high'
        elif port < 1024:
            return 'medium'
        else:
            return 'low'
    
    def stop_scan(self):
        """Stop the current scan"""
        self.is_scanning = False
    
    def get_scan_status(self, session_id):
        """Get current scan status"""
        session = ScanSession.query.get(session_id)
        return {
            'status': session.status if session else 'unknown',
            'is_running': self.is_scanning,
            'results_count': len(self.scan_results.get(session_id, []))
        }
    
    def discovery_scan(self, network_range):
        """Perform host discovery scan"""
        try:
            # Use ping scan to discover live hosts
            discovery_result = self.nm.scan(hosts=network_range, arguments='-sn')
            
            live_hosts = []
            for host in discovery_result['scan']:
                if discovery_result['scan'][host]['status']['state'] == 'up':
                    host_info = {
                        'ip': host,
                        'hostname': discovery_result['scan'][host]['hostnames'][0]['name'] if discovery_result['scan'][host]['hostnames'] else '',
                        'status': 'up',
                        'timestamp': datetime.utcnow().isoformat()
                    }
                    live_hosts.append(host_info)
            
            return live_hosts
            
        except Exception as e:
            logging.error(f"Discovery scan failed: {str(e)}")
            return []
    
    def service_detection(self, target, ports):
        """Perform detailed service detection on specific ports"""
        try:
            port_range = ','.join(map(str, ports))
            scan_result = self.nm.scan(target, port_range, arguments='-sV -sC')
            
            services = []
            if target in scan_result['scan']:
                host_data = scan_result['scan'][target]
                
                if 'tcp' in host_data:
                    for port in host_data['tcp']:
                        port_info = host_data['tcp'][port]
                        service_info = {
                            'port': port,
                            'protocol': 'tcp',
                            'service': port_info.get('name', 'unknown'),
                            'product': port_info.get('product', ''),
                            'version': port_info.get('version', ''),
                            'extrainfo': port_info.get('extrainfo', ''),
                            'script_results': port_info.get('script', {}),
                            'state': port_info['state']
                        }
                        services.append(service_info)
            
            return services
            
        except Exception as e:
            logging.error(f"Service detection failed: {str(e)}")
            return []
