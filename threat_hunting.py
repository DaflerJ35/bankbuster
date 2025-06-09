"""
Red Team Platform - Advanced Threat Hunting and Behavioral Analysis
Real-time threat detection, behavioral analytics, and predictive hunting
"""

import json
import time
import threading
from datetime import datetime, timedelta
from collections import defaultdict, deque
import hashlib
import re
from typing import Dict, List, Any
from models import db, Finding, ScanSession, AuditLog
from crypto_utils import CryptoManager

class ThreatHuntingEngine:
    """Advanced threat hunting with machine learning and behavioral analysis"""
    
    def __init__(self):
        self.crypto = CryptoManager()
        self.active_hunts = {}
        self.behavioral_baselines = {}
        self.threat_indicators = {}
        self.hunting_rules = self._load_hunting_rules()
        self.ioc_feeds = IOCManager()
        self.behavioral_analyzer = BehavioralAnalyzer()
        self.attribution_engine = AttributionEngine()
        
    def start_threat_hunt(self, hunt_config):
        """Start a new threat hunting session"""
        hunt_id = self._generate_hunt_id()
        
        hunt_session = {
            'id': hunt_id,
            'config': hunt_config,
            'start_time': datetime.utcnow(),
            'status': 'active',
            'findings': [],
            'behavioral_anomalies': [],
            'attribution_data': {},
            'stop_flag': threading.Event()
        }
        
        self.active_hunts[hunt_id] = hunt_session
        
        # Start hunting thread
        hunt_thread = threading.Thread(
            target=self._execute_hunt,
            args=(hunt_session,),
            daemon=True
        )
        hunt_thread.start()
        
        return hunt_id
    
    def _execute_hunt(self, hunt_session):
        """Execute threat hunting logic"""
        hunt_config = hunt_session['config']
        hunt_type = hunt_config.get('type', 'comprehensive')
        
        while not hunt_session['stop_flag'].is_set():
            try:
                if hunt_type == 'apt_detection':
                    self._hunt_apt_activity(hunt_session)
                elif hunt_type == 'insider_threat':
                    self._hunt_insider_threats(hunt_session)
                elif hunt_type == 'living_off_land':
                    self._hunt_lolbins(hunt_session)
                elif hunt_type == 'lateral_movement':
                    self._hunt_lateral_movement(hunt_session)
                elif hunt_type == 'data_exfiltration':
                    self._hunt_data_exfiltration(hunt_session)
                elif hunt_type == 'zero_day':
                    self._hunt_zero_day_activity(hunt_session)
                else:
                    self._comprehensive_hunt(hunt_session)
                
                # Update behavioral baselines
                self._update_behavioral_baselines(hunt_session)
                
                # Check for attribution indicators
                self._perform_attribution_analysis(hunt_session)
                
                time.sleep(30)  # Hunt cycle interval
                
            except Exception as e:
                print(f"Error in threat hunt {hunt_session['id']}: {e}")
                time.sleep(60)
    
    def _hunt_apt_activity(self, hunt_session):
        """Hunt for Advanced Persistent Threat indicators"""
        apt_indicators = [
            {
                'name': 'Long-term persistence',
                'pattern': r'(systemd|cron|registry.*run|wmi.*subscription)',
                'severity': 'high'
            },
            {
                'name': 'Credential dumping',
                'pattern': r'(mimikatz|secretsdump|lsass|sam\.hive)',
                'severity': 'critical'
            },
            {
                'name': 'Living-off-the-land binaries',
                'pattern': r'(powershell.*-enc|wmic.*process|rundll32.*javascript)',
                'severity': 'medium'
            },
            {
                'name': 'Unusual network beaconing',
                'pattern': r'(regular.*intervals|c2.*communication|heartbeat)',
                'severity': 'high'
            }
        ]
        
        findings = self._scan_for_patterns(apt_indicators, hunt_session)
        hunt_session['findings'].extend(findings)
        
        # APT-specific behavioral analysis
        self._analyze_apt_behavior(hunt_session)
    
    def _hunt_insider_threats(self, hunt_session):
        """Hunt for insider threat indicators"""
        insider_indicators = [
            {
                'name': 'Unusual data access patterns',
                'pattern': r'(bulk.*download|after.*hours.*access|privilege.*escalation)',
                'severity': 'medium'
            },
            {
                'name': 'Data staging and collection',
                'pattern': r'(tar.*gz|zip.*archive|usb.*device|external.*storage)',
                'severity': 'high'
            },
            {
                'name': 'Policy violations',
                'pattern': r'(unauthorized.*software|restricted.*access|security.*bypass)',
                'severity': 'high'
            }
        ]
        
        findings = self._scan_for_patterns(insider_indicators, hunt_session)
        hunt_session['findings'].extend(findings)
        
        # Behavioral deviation analysis
        self._analyze_user_behavior_deviation(hunt_session)
    
    def _hunt_lolbins(self, hunt_session):
        """Hunt for Living-off-the-Land binary abuse"""
        lolbin_patterns = [
            {
                'name': 'PowerShell abuse',
                'pattern': r'powershell.*(-enc|-w.*hidden|-exec.*bypass)',
                'severity': 'high'
            },
            {
                'name': 'WMI abuse',
                'pattern': r'wmic.*(process.*call|/node:|/user:)',
                'severity': 'medium'
            },
            {
                'name': 'Certutil abuse',
                'pattern': r'certutil.*(-decode|-urlcache|-f)',
                'severity': 'medium'
            },
            {
                'name': 'Rundll32 abuse',
                'pattern': r'rundll32.*(javascript:|vbscript:|shell32)',
                'severity': 'high'
            },
            {
                'name': 'Regsvr32 abuse',
                'pattern': r'regsvr32.*(/s|/u|/i:|scrobj\.dll)',
                'severity': 'high'
            }
        ]
        
        findings = self._scan_for_patterns(lolbin_patterns, hunt_session)
        hunt_session['findings'].extend(findings)
    
    def _hunt_lateral_movement(self, hunt_session):
        """Hunt for lateral movement techniques"""
        lateral_indicators = [
            {
                'name': 'Pass-the-hash attacks',
                'pattern': r'(ntlm.*relay|smb.*authentication|hash.*passing)',
                'severity': 'critical'
            },
            {
                'name': 'Remote execution',
                'pattern': r'(psexec|winrm|ssh.*keys|remote.*desktop)',
                'severity': 'high'
            },
            {
                'name': 'Service creation',
                'pattern': r'(sc.*create|new.*service|service.*install)',
                'severity': 'medium'
            },
            {
                'name': 'Scheduled tasks',
                'pattern': r'(schtasks|at\.exe|cron.*job)',
                'severity': 'medium'
            }
        ]
        
        findings = self._scan_for_patterns(lateral_indicators, hunt_session)
        hunt_session['findings'].extend(findings)
        
        # Network flow analysis for lateral movement
        self._analyze_network_flows(hunt_session)
    
    def _hunt_data_exfiltration(self, hunt_session):
        """Hunt for data exfiltration activities"""
        exfil_indicators = [
            {
                'name': 'Large data transfers',
                'pattern': r'(curl.*-T|wget.*--post|ftp.*put|scp.*-r)',
                'severity': 'high'
            },
            {
                'name': 'DNS tunneling',
                'pattern': r'(nslookup.*base64|dig.*txt|dns.*exfil)',
                'severity': 'high'
            },
            {
                'name': 'ICMP tunneling',
                'pattern': r'(ping.*-p|icmp.*data|tunnel.*icmp)',
                'severity': 'medium'
            },
            {
                'name': 'Cloud storage uploads',
                'pattern': r'(dropbox|googledrive|onedrive|s3.*upload)',
                'severity': 'medium'
            }
        ]
        
        findings = self._scan_for_patterns(exfil_indicators, hunt_session)
        hunt_session['findings'].extend(findings)
        
        # Data flow analysis
        self._analyze_data_flows(hunt_session)
    
    def _hunt_zero_day_activity(self, hunt_session):
        """Hunt for potential zero-day exploitation"""
        zero_day_indicators = [
            {
                'name': 'Unknown exploitation patterns',
                'pattern': r'(unknown.*exploit|custom.*payload|new.*technique)',
                'severity': 'critical'
            },
            {
                'name': 'Unusual system behavior',
                'pattern': r'(unexpected.*crash|memory.*corruption|stack.*overflow)',
                'severity': 'high'
            },
            {
                'name': 'Novel persistence methods',
                'pattern': r'(new.*autostart|custom.*persistence|undocumented.*feature)',
                'severity': 'high'
            }
        ]
        
        findings = self._scan_for_patterns(zero_day_indicators, hunt_session)
        hunt_session['findings'].extend(findings)
        
        # Anomaly detection for zero-day behavior
        self._detect_zero_day_anomalies(hunt_session)
    
    def _comprehensive_hunt(self, hunt_session):
        """Comprehensive threat hunting across all categories"""
        self._hunt_apt_activity(hunt_session)
        self._hunt_insider_threats(hunt_session)
        self._hunt_lolbins(hunt_session)
        self._hunt_lateral_movement(hunt_session)
        self._hunt_data_exfiltration(hunt_session)
        self._hunt_zero_day_activity(hunt_session)
    
    def _scan_for_patterns(self, patterns, hunt_session):
        """Scan system data for threat patterns"""
        findings = []
        
        # Scan recent findings from database
        recent_findings = Finding.query.filter(
            Finding.created_at >= datetime.utcnow() - timedelta(hours=24)
        ).all()
        
        for finding in recent_findings:
            try:
                # Decrypt finding data
                description = self.crypto.decrypt_data(finding.description)
                evidence = self.crypto.decrypt_data(finding.evidence) if finding.evidence else ""
                
                combined_text = f"{description} {evidence}".lower()
                
                for pattern in patterns:
                    if re.search(pattern['pattern'], combined_text, re.IGNORECASE):
                        findings.append({
                            'hunt_id': hunt_session['id'],
                            'pattern_name': pattern['name'],
                            'severity': pattern['severity'],
                            'finding_id': finding.id,
                            'match_text': combined_text[:200],
                            'timestamp': datetime.utcnow()
                        })
                        
            except Exception as e:
                continue
        
        return findings
    
    def _analyze_apt_behavior(self, hunt_session):
        """Analyze behavioral patterns specific to APT groups"""
        apt_behaviors = {
            'persistence_techniques': [
                'registry_modification',
                'service_creation',
                'scheduled_tasks',
                'wmi_subscriptions'
            ],
            'evasion_techniques': [
                'process_hollowing',
                'dll_sideloading',
                'lolbins_abuse',
                'fileless_execution'
            ],
            'collection_techniques': [
                'keylogging',
                'screen_capture',
                'clipboard_access',
                'browser_data'
            ]
        }
        
        # Score APT likelihood based on technique combinations
        apt_score = self._calculate_apt_score(hunt_session, apt_behaviors)
        
        if apt_score > 0.7:
            hunt_session['behavioral_anomalies'].append({
                'type': 'apt_behavior',
                'score': apt_score,
                'description': 'High likelihood of APT activity detected',
                'timestamp': datetime.utcnow()
            })
    
    def _analyze_user_behavior_deviation(self, hunt_session):
        """Analyze user behavior for insider threat indicators"""
        user_behaviors = self.behavioral_analyzer.get_user_behavior_profiles()
        
        for user_id, behavior in user_behaviors.items():
            baseline = self.behavioral_baselines.get(user_id, {})
            
            # Check for significant deviations
            deviations = []
            
            if behavior.get('access_hours', 0) > baseline.get('normal_hours', 8) * 2:
                deviations.append('unusual_hours')
            
            if behavior.get('data_access', 0) > baseline.get('normal_access', 100) * 5:
                deviations.append('excessive_data_access')
            
            if behavior.get('failed_logins', 0) > baseline.get('normal_failures', 2) * 3:
                deviations.append('authentication_anomalies')
            
            if deviations:
                hunt_session['behavioral_anomalies'].append({
                    'type': 'insider_threat',
                    'user_id': user_id,
                    'deviations': deviations,
                    'risk_score': len(deviations) * 0.3,
                    'timestamp': datetime.utcnow()
                })
    
    def _analyze_network_flows(self, hunt_session):
        """Analyze network flows for lateral movement patterns"""
        # This would integrate with network monitoring tools
        # For now, simulate network flow analysis
        suspicious_flows = [
            {
                'source_ip': '192.168.1.100',
                'dest_ip': '192.168.1.200',
                'port': 445,
                'protocol': 'SMB',
                'pattern': 'admin_share_access'
            },
            {
                'source_ip': '192.168.1.100',
                'dest_ip': '192.168.1.201',
                'port': 3389,
                'protocol': 'RDP',
                'pattern': 'remote_desktop'
            }
        ]
        
        for flow in suspicious_flows:
            hunt_session['findings'].append({
                'hunt_id': hunt_session['id'],
                'type': 'network_flow',
                'severity': 'medium',
                'description': f"Suspicious {flow['protocol']} traffic detected",
                'source_ip': flow['source_ip'],
                'dest_ip': flow['dest_ip'],
                'timestamp': datetime.utcnow()
            })
    
    def _analyze_data_flows(self, hunt_session):
        """Analyze data flows for exfiltration patterns"""
        # Monitor for large data movements
        data_flows = self.behavioral_analyzer.get_data_transfer_patterns()
        
        for flow in data_flows:
            if flow.get('size_mb', 0) > 1000:  # Large transfers
                hunt_session['findings'].append({
                    'hunt_id': hunt_session['id'],
                    'type': 'data_exfiltration',
                    'severity': 'high',
                    'description': f"Large data transfer detected: {flow['size_mb']}MB",
                    'destination': flow.get('destination', 'unknown'),
                    'timestamp': datetime.utcnow()
                })
    
    def _detect_zero_day_anomalies(self, hunt_session):
        """Detect anomalies that might indicate zero-day exploitation"""
        anomaly_indicators = [
            'unexpected_crashes',
            'memory_corruption_signs',
            'novel_execution_paths',
            'unusual_system_calls',
            'unknown_file_formats'
        ]
        
        for indicator in anomaly_indicators:
            # This would integrate with system monitoring
            # For now, simulate anomaly detection
            if self._check_anomaly_indicator(indicator):
                hunt_session['behavioral_anomalies'].append({
                    'type': 'zero_day_anomaly',
                    'indicator': indicator,
                    'confidence': 0.6,
                    'description': f"Potential zero-day indicator: {indicator}",
                    'timestamp': datetime.utcnow()
                })
    
    def _check_anomaly_indicator(self, indicator):
        """Check for specific anomaly indicators"""
        # Simulate anomaly detection logic
        import random
        return random.random() > 0.8  # 20% chance of anomaly
    
    def _calculate_apt_score(self, hunt_session, apt_behaviors):
        """Calculate APT likelihood score"""
        score = 0.0
        total_techniques = sum(len(techniques) for techniques in apt_behaviors.values())
        
        for category, techniques in apt_behaviors.items():
            for technique in techniques:
                # Check if technique was observed in findings
                if any(technique in str(finding).lower() for finding in hunt_session['findings']):
                    score += 1.0 / total_techniques
        
        return min(score, 1.0)
    
    def _update_behavioral_baselines(self, hunt_session):
        """Update behavioral baselines based on observations"""
        # This would learn normal behavior patterns over time
        pass
    
    def _perform_attribution_analysis(self, hunt_session):
        """Perform threat actor attribution analysis"""
        attribution_data = self.attribution_engine.analyze_findings(hunt_session['findings'])
        hunt_session['attribution_data'] = attribution_data
    
    def _generate_hunt_id(self):
        """Generate unique hunt session ID"""
        timestamp = str(int(time.time()))
        random_data = str(time.time_ns())
        return hashlib.md5(f"{timestamp}{random_data}".encode()).hexdigest()[:16]
    
    def _load_hunting_rules(self):
        """Load threat hunting rules and patterns"""
        return {
            'mitre_attack_patterns': {
                'T1055': 'Process Injection',
                'T1059': 'Command and Scripting Interpreter',
                'T1070': 'Indicator Removal on Host',
                'T1078': 'Valid Accounts',
                'T1082': 'System Information Discovery',
                'T1083': 'File and Directory Discovery',
                'T1105': 'Ingress Tool Transfer',
                'T1112': 'Modify Registry',
                'T1136': 'Create Account',
                'T1190': 'Exploit Public-Facing Application'
            },
            'custom_patterns': [
                {
                    'name': 'Suspicious PowerShell',
                    'pattern': r'powershell.*(-enc|-w.*hidden|-nop)',
                    'mitre_id': 'T1059.001'
                },
                {
                    'name': 'Credential Dumping',
                    'pattern': r'(mimikatz|lsass|secretsdump|sam\.save)',
                    'mitre_id': 'T1003'
                }
            ]
        }
    
    def get_hunt_status(self, hunt_id):
        """Get current status of threat hunt"""
        hunt_session = self.active_hunts.get(hunt_id)
        if not hunt_session:
            return {'error': 'Hunt session not found'}
        
        return {
            'id': hunt_id,
            'status': hunt_session['status'],
            'start_time': hunt_session['start_time'],
            'findings_count': len(hunt_session['findings']),
            'anomalies_count': len(hunt_session['behavioral_anomalies']),
            'attribution': hunt_session.get('attribution_data', {}),
            'recent_findings': hunt_session['findings'][-10:]  # Last 10 findings
        }
    
    def stop_hunt(self, hunt_id):
        """Stop active threat hunt"""
        hunt_session = self.active_hunts.get(hunt_id)
        if hunt_session:
            hunt_session['stop_flag'].set()
            hunt_session['status'] = 'stopped'
            return True
        return False

class BehavioralAnalyzer:
    """Advanced behavioral analysis for threat detection"""
    
    def __init__(self):
        self.user_profiles = {}
        self.system_baselines = {}
        self.anomaly_threshold = 2.0  # Standard deviations
    
    def get_user_behavior_profiles(self):
        """Get current user behavior profiles"""
        # This would integrate with user activity monitoring
        # For now, return simulated data
        return {
            'user1': {
                'access_hours': 12,
                'data_access': 500,
                'failed_logins': 5,
                'locations': ['office', 'home']
            },
            'user2': {
                'access_hours': 8,
                'data_access': 200,
                'failed_logins': 1,
                'locations': ['office']
            }
        }
    
    def get_data_transfer_patterns(self):
        """Get data transfer patterns for analysis"""
        # Simulate data transfer monitoring
        return [
            {
                'size_mb': 1500,
                'destination': 'external_ftp',
                'user': 'user1',
                'timestamp': datetime.utcnow()
            },
            {
                'size_mb': 50,
                'destination': 'internal_share',
                'user': 'user2',
                'timestamp': datetime.utcnow()
            }
        ]
    
    def detect_behavioral_anomalies(self, user_id, current_behavior):
        """Detect behavioral anomalies for specific user"""
        baseline = self.user_profiles.get(user_id, {})
        anomalies = []
        
        # Statistical anomaly detection
        for metric, value in current_behavior.items():
            if metric in baseline:
                mean = baseline[metric].get('mean', 0)
                std = baseline[metric].get('std', 1)
                
                if abs(value - mean) > self.anomaly_threshold * std:
                    anomalies.append({
                        'metric': metric,
                        'current_value': value,
                        'expected_range': (mean - std, mean + std),
                        'severity': 'high' if abs(value - mean) > 3 * std else 'medium'
                    })
        
        return anomalies

class AttributionEngine:
    """Threat actor attribution and campaign tracking"""
    
    def __init__(self):
        self.threat_actors = self._load_threat_actor_profiles()
        self.campaign_signatures = self._load_campaign_signatures()
    
    def analyze_findings(self, findings):
        """Analyze findings for threat actor attribution"""
        attribution_scores = defaultdict(float)
        
        for finding in findings:
            # Extract techniques and patterns
            techniques = self._extract_techniques(finding)
            
            # Score against known threat actors
            for actor_name, actor_profile in self.threat_actors.items():
                score = self._calculate_attribution_score(techniques, actor_profile)
                attribution_scores[actor_name] += score
        
        # Normalize scores
        total_score = sum(attribution_scores.values())
        if total_score > 0:
            for actor in attribution_scores:
                attribution_scores[actor] /= total_score
        
        return dict(attribution_scores)
    
    def _extract_techniques(self, finding):
        """Extract MITRE ATT&CK techniques from finding"""
        # This would use NLP and pattern matching
        # For now, return simulated technique extraction
        techniques = []
        
        finding_text = str(finding).lower()
        
        if 'powershell' in finding_text:
            techniques.append('T1059.001')
        if 'credential' in finding_text:
            techniques.append('T1003')
        if 'persistence' in finding_text:
            techniques.append('T1547')
        if 'lateral' in finding_text:
            techniques.append('T1021')
        
        return techniques
    
    def _calculate_attribution_score(self, observed_techniques, actor_profile):
        """Calculate attribution score for threat actor"""
        actor_techniques = set(actor_profile.get('techniques', []))
        observed_set = set(observed_techniques)
        
        if not actor_techniques or not observed_set:
            return 0.0
        
        # Jaccard similarity
        intersection = len(actor_techniques.intersection(observed_set))
        union = len(actor_techniques.union(observed_set))
        
        return intersection / union if union > 0 else 0.0
    
    def _load_threat_actor_profiles(self):
        """Load known threat actor profiles"""
        return {
            'APT29': {
                'name': 'Cozy Bear',
                'country': 'Russia',
                'techniques': ['T1059.001', 'T1003', 'T1547', 'T1070'],
                'tools': ['PowerShell', 'Mimikatz', 'Cobalt Strike'],
                'targets': ['Government', 'Healthcare', 'Energy']
            },
            'APT28': {
                'name': 'Fancy Bear',
                'country': 'Russia',
                'techniques': ['T1566.001', 'T1055', 'T1021', 'T1083'],
                'tools': ['X-Agent', 'Sofacy', 'Zebrocy'],
                'targets': ['Military', 'Government', 'Aerospace']
            },
            'Lazarus': {
                'name': 'Lazarus Group',
                'country': 'North Korea',
                'techniques': ['T1190', 'T1105', 'T1055', 'T1027'],
                'tools': ['RATANKBA', 'PowerRatankba', 'Manuscrypt'],
                'targets': ['Financial', 'Cryptocurrency', 'Defense']
            }
        }
    
    def _load_campaign_signatures(self):
        """Load campaign-specific signatures"""
        return {
            'SolarWinds': {
                'indicators': ['sunburst', 'sunspot', 'teardrop'],
                'techniques': ['T1195.002', 'T1027', 'T1070'],
                'attribution': 'APT29'
            },
            'WannaCry': {
                'indicators': ['wcry', 'wanna', 'decrypt'],
                'techniques': ['T1190', 'T1486', 'T1021.002'],
                'attribution': 'Lazarus'
            }
        }

class IOCManager:
    """Indicator of Compromise management and correlation"""
    
    def __init__(self):
        self.ioc_database = {}
        self.feed_sources = [
            'alienvault_otx',
            'virustotal',
            'misp',
            'threatcrowd'
        ]
        self.last_update = None
    
    def update_ioc_feeds(self):
        """Update IOC feeds from external sources"""
        # This would integrate with real threat intel feeds
        # For now, simulate IOC data
        self.ioc_database = {
            'domains': [
                'malicious-domain.com',
                'evil-site.net',
                'bad-actor.org'
            ],
            'ips': [
                '192.168.100.100',
                '10.0.0.50',
                '172.16.1.200'
            ],
            'hashes': [
                'a1b2c3d4e5f6...',
                'f6e5d4c3b2a1...',
                '123456789abc...'
            ],
            'urls': [
                'http://malicious-domain.com/payload.exe',
                'https://evil-site.net/backdoor.php'
            ]
        }
        self.last_update = datetime.utcnow()
    
    def check_ioc_matches(self, data):
        """Check data against IOC database"""
        matches = []
        
        for ioc_type, ioc_list in self.ioc_database.items():
            for ioc in ioc_list:
                if ioc.lower() in str(data).lower():
                    matches.append({
                        'type': ioc_type,
                        'value': ioc,
                        'confidence': 'high',
                        'source': 'threat_intel'
                    })
        
        return matches

# Global threat hunting instance
threat_hunter = ThreatHuntingEngine()