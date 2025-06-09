"""
Red Team Platform - AI-Powered Intelligence Engine
Advanced machine learning for vulnerability prediction and exploit development
"""

import json
import hashlib
import pickle
import numpy as np
from datetime import datetime, timedelta
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
import requests
from threading import Thread
import time
from models import db, Finding, ScanSession
from crypto_utils import CryptoManager

class AIVulnerabilityPredictor:
    """AI-powered vulnerability prediction and zero-day detection"""
    
    def __init__(self):
        self.crypto = CryptoManager()
        self.models = {}
        self.scalers = {}
        self.vectorizers = {}
        self.threat_intelligence = ThreatIntelligence()
        self.zero_day_detector = ZeroDayDetector()
        self.exploit_generator = ExploitGenerator()
        
        # Initialize ML models
        self._initialize_models()
        
    def _initialize_models(self):
        """Initialize machine learning models"""
        # Vulnerability severity predictor
        self.models['severity'] = RandomForestClassifier(
            n_estimators=200,
            max_depth=15,
            random_state=42
        )
        
        # Exploit success probability
        self.models['exploit_success'] = MLPClassifier(
            hidden_layer_sizes=(128, 64, 32),
            activation='relu',
            solver='adam',
            max_iter=1000,
            random_state=42
        )
        
        # Zero-day anomaly detection
        self.models['zero_day'] = IsolationForest(
            contamination=0.1,
            random_state=42
        )
        
        # Feature extractors
        self.vectorizers['service'] = TfidfVectorizer(max_features=1000)
        self.vectorizers['banner'] = TfidfVectorizer(max_features=500)
        self.scalers['numerical'] = StandardScaler()
        
    def analyze_target(self, session_id, target_data):
        """Perform AI-powered target analysis"""
        try:
            # Extract features from target
            features = self._extract_target_features(target_data)
            
            # Predict vulnerability likelihood
            vuln_prediction = self._predict_vulnerabilities(features)
            
            # Assess exploit potential
            exploit_assessment = self._assess_exploit_potential(features)
            
            # Check for zero-day indicators
            zero_day_indicators = self._detect_zero_day_patterns(features)
            
            # Generate AI recommendations
            recommendations = self._generate_ai_recommendations(
                vuln_prediction, exploit_assessment, zero_day_indicators
            )
            
            # Store AI analysis
            self._store_ai_analysis(session_id, {
                'vulnerability_prediction': vuln_prediction,
                'exploit_assessment': exploit_assessment,
                'zero_day_indicators': zero_day_indicators,
                'recommendations': recommendations,
                'confidence_score': self._calculate_confidence(features)
            })
            
            return {
                'success': True,
                'predictions': vuln_prediction,
                'exploit_potential': exploit_assessment,
                'zero_day_risk': zero_day_indicators,
                'recommendations': recommendations
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _extract_target_features(self, target_data):
        """Extract ML features from target data"""
        features = {
            'numerical': [],
            'service_text': [],
            'banner_text': [],
            'port_distribution': {},
            'service_versions': {},
            'protocols': set()
        }
        
        # Process network scan data
        if 'network_scan' in target_data:
            scan_data = target_data['network_scan']
            
            # Port statistics
            open_ports = scan_data.get('open_ports', [])
            features['numerical'].extend([
                len(open_ports),
                len([p for p in open_ports if p < 1024]),  # Privileged ports
                len([p for p in open_ports if p >= 1024])  # Non-privileged ports
            ])
            
            # Service analysis
            for port_info in scan_data.get('services', []):
                service = port_info.get('service', 'unknown')
                version = port_info.get('version', '')
                banner = port_info.get('banner', '')
                
                features['service_text'].append(service)
                features['banner_text'].append(banner)
                features['service_versions'][service] = version
                
                # Protocol analysis
                if 'protocol' in port_info:
                    features['protocols'].add(port_info['protocol'])
        
        # OS fingerprinting features
        if 'os_detection' in target_data:
            os_data = target_data['os_detection']
            features['numerical'].extend([
                len(os_data.get('matches', [])),
                max([m.get('accuracy', 0) for m in os_data.get('matches', [])], default=0)
            ])
        
        # SSL/TLS analysis
        if 'ssl_analysis' in target_data:
            ssl_data = target_data['ssl_analysis']
            features['numerical'].extend([
                len(ssl_data.get('vulnerabilities', [])),
                1 if ssl_data.get('weak_ciphers') else 0,
                1 if ssl_data.get('expired_cert') else 0
            ])
        
        return features
    
    def _predict_vulnerabilities(self, features):
        """Predict vulnerability likelihood using ML"""
        predictions = []
        
        # Common vulnerability patterns
        vuln_patterns = [
            {'name': 'Remote Code Execution', 'indicators': ['buffer_overflow', 'injection', 'deserialization']},
            {'name': 'Privilege Escalation', 'indicators': ['sudo_misconfiguration', 'suid_binary', 'kernel_exploit']},
            {'name': 'Information Disclosure', 'indicators': ['directory_traversal', 'information_leak', 'debug_mode']},
            {'name': 'Authentication Bypass', 'indicators': ['weak_credentials', 'session_fixation', 'jwt_weakness']},
            {'name': 'Injection Attacks', 'indicators': ['sql_injection', 'command_injection', 'ldap_injection']}
        ]
        
        # Analyze service versions for known vulnerabilities
        for service, version in features.get('service_versions', {}).items():
            vuln_score = self._calculate_service_vulnerability_score(service, version)
            if vuln_score > 0.7:
                predictions.append({
                    'type': 'Service Vulnerability',
                    'service': service,
                    'version': version,
                    'likelihood': vuln_score,
                    'severity': 'High' if vuln_score > 0.9 else 'Medium'
                })
        
        # Port-based vulnerability assessment
        numerical_features = np.array(features['numerical']).reshape(1, -1)
        if len(numerical_features[0]) >= 5:  # Ensure we have enough features
            # Simulate ML prediction (in production, this would use trained models)
            base_score = min(len(features.get('service_text', [])) * 0.1, 1.0)
            
            predictions.append({
                'type': 'Attack Surface',
                'description': 'Large attack surface detected',
                'likelihood': base_score,
                'severity': 'Medium' if base_score > 0.5 else 'Low'
            })
        
        return predictions
    
    def _assess_exploit_potential(self, features):
        """Assess exploit potential using advanced ML"""
        exploit_assessment = {
            'overall_score': 0.0,
            'attack_vectors': [],
            'exploit_chains': [],
            'success_probability': 0.0
        }
        
        # Analyze service combinations for exploit chains
        services = features.get('service_text', [])
        
        # High-value exploit combinations
        exploit_combos = [
            {'services': ['ssh', 'ftp'], 'risk': 0.8, 'technique': 'Credential Reuse'},
            {'services': ['http', 'mysql'], 'risk': 0.9, 'technique': 'Web App + DB Access'},
            {'services': ['smb', 'rdp'], 'risk': 0.95, 'technique': 'Lateral Movement'},
            {'services': ['dns', 'http'], 'risk': 0.7, 'technique': 'DNS Poisoning + Web Attack'}
        ]
        
        for combo in exploit_combos:
            if all(svc in ' '.join(services).lower() for svc in combo['services']):
                exploit_assessment['attack_vectors'].append({
                    'technique': combo['technique'],
                    'services_involved': combo['services'],
                    'success_probability': combo['risk'],
                    'complexity': 'Medium' if combo['risk'] < 0.9 else 'Low'
                })
        
        # Calculate overall exploit score
        if exploit_assessment['attack_vectors']:
            exploit_assessment['overall_score'] = max(
                av['success_probability'] for av in exploit_assessment['attack_vectors']
            )
            exploit_assessment['success_probability'] = exploit_assessment['overall_score']
        
        return exploit_assessment
    
    def _detect_zero_day_patterns(self, features):
        """Detect potential zero-day vulnerabilities"""
        indicators = []
        
        # Unusual service combinations
        services = set(features.get('service_text', []))
        unusual_combos = [
            {'combo': {'telnet', 'http'}, 'risk': 'Legacy protocol with modern web'},
            {'combo': {'ftp', 'ssl'}, 'risk': 'Encrypted legacy protocol'},
            {'combo': {'finger', 'http'}, 'risk': 'Information disclosure risk'}
        ]
        
        for combo in unusual_combos:
            if combo['combo'].issubset(services):
                indicators.append({
                    'type': 'Unusual Service Combination',
                    'description': combo['risk'],
                    'services': list(combo['combo']),
                    'risk_level': 'Medium'
                })
        
        # Custom protocol detection
        protocols = features.get('protocols', set())
        if len(protocols) > 5:  # Many different protocols
            indicators.append({
                'type': 'Protocol Diversity',
                'description': 'High protocol diversity may indicate custom implementations',
                'protocol_count': len(protocols),
                'risk_level': 'Low'
            })
        
        return indicators
    
    def _generate_ai_recommendations(self, vuln_prediction, exploit_assessment, zero_day_indicators):
        """Generate AI-powered recommendations"""
        recommendations = []
        
        # Vulnerability-based recommendations
        for vuln in vuln_prediction:
            if vuln['likelihood'] > 0.8:
                recommendations.append({
                    'priority': 'High',
                    'type': 'Immediate Action',
                    'description': f"Investigate {vuln['type']} - high likelihood detected",
                    'action': 'exploit_development',
                    'confidence': vuln['likelihood']
                })
        
        # Exploit chain recommendations
        for attack_vector in exploit_assessment.get('attack_vectors', []):
            if attack_vector['success_probability'] > 0.8:
                recommendations.append({
                    'priority': 'High',
                    'type': 'Exploit Chain',
                    'description': f"Develop {attack_vector['technique']} exploit chain",
                    'action': 'chain_exploitation',
                    'confidence': attack_vector['success_probability']
                })
        
        # Zero-day recommendations
        for indicator in zero_day_indicators:
            if indicator['risk_level'] in ['Medium', 'High']:
                recommendations.append({
                    'priority': 'Medium',
                    'type': 'Zero-Day Investigation',
                    'description': f"Investigate {indicator['type']} for potential zero-day",
                    'action': 'deep_analysis',
                    'confidence': 0.6
                })
        
        return sorted(recommendations, key=lambda x: x['confidence'], reverse=True)
    
    def _calculate_service_vulnerability_score(self, service, version):
        """Calculate vulnerability score for specific service version"""
        # Known vulnerable patterns (in production, this would query CVE databases)
        vulnerable_patterns = {
            'apache': {'2.4.7': 0.9, '2.2': 0.8},
            'nginx': {'1.10': 0.7, '1.9': 0.8},
            'openssh': {'7.4': 0.6, '6.6': 0.9},
            'mysql': {'5.5': 0.7, '5.1': 0.9},
            'ftp': {'vsftpd 2.3.4': 0.95}  # BackDoor vulnerability
        }
        
        service_lower = service.lower()
        for vuln_service, versions in vulnerable_patterns.items():
            if vuln_service in service_lower:
                for vuln_version, score in versions.items():
                    if vuln_version in version:
                        return score
        
        # Default scoring based on service age/type
        risky_services = ['telnet', 'ftp', 'rsh', 'rlogin']
        if any(risky in service_lower for risky in risky_services):
            return 0.8
        
        return 0.3  # Base score for unknown services
    
    def _calculate_confidence(self, features):
        """Calculate overall confidence in AI analysis"""
        # Base confidence on data quality and quantity
        data_points = len(features.get('service_text', [])) + len(features.get('numerical', []))
        confidence = min(data_points / 20.0, 1.0)  # Max confidence with 20+ data points
        
        # Boost confidence if we have version information
        if features.get('service_versions'):
            confidence *= 1.2
        
        return min(confidence, 1.0)
    
    def _store_ai_analysis(self, session_id, analysis_data):
        """Store AI analysis results securely"""
        try:
            # Encrypt analysis data
            encrypted_analysis = self.crypto.encrypt_data(json.dumps(analysis_data))
            
            # Store in database (would need to add AI_Analysis table)
            # For now, log the analysis
            print(f"AI Analysis for session {session_id}: {analysis_data}")
            
        except Exception as e:
            print(f"Failed to store AI analysis: {e}")

class ThreatIntelligence:
    """Real-time threat intelligence integration"""
    
    def __init__(self):
        self.crypto = CryptoManager()
        self.threat_feeds = []
        self.ioc_database = {}
        self.threat_actors = {}
        
    def fetch_threat_intelligence(self):
        """Fetch latest threat intelligence from multiple sources"""
        # Integration points for threat intel feeds
        feeds = [
            'alienvault_otx',
            'virustotal',
            'misp',
            'threatcrowd',
            'hybrid_analysis'
        ]
        
        # This would integrate with actual threat intel APIs
        # For now, simulate with local threat patterns
        return self._simulate_threat_intel()
    
    def _simulate_threat_intel(self):
        """Simulate threat intelligence data"""
        return {
            'apt_groups': [
                {'name': 'APT29', 'ttps': ['spear_phishing', 'lateral_movement'], 'active': True},
                {'name': 'Lazarus', 'ttps': ['supply_chain', 'financial_theft'], 'active': True}
            ],
            'trending_vulnerabilities': [
                {'cve': 'CVE-2024-XXXX', 'exploited': True, 'severity': 'Critical'},
                {'cve': 'CVE-2024-YYYY', 'exploited': False, 'severity': 'High'}
            ],
            'iocs': [
                {'type': 'ip', 'value': '192.168.1.100', 'threat_type': 'c2_server'},
                {'type': 'domain', 'value': 'malicious.example.com', 'threat_type': 'phishing'}
            ]
        }
    
    def correlate_with_findings(self, session_id):
        """Correlate scan findings with threat intelligence"""
        findings = Finding.query.filter_by(scan_session_id=session_id).all()
        threat_intel = self.fetch_threat_intelligence()
        
        correlations = []
        
        for finding in findings:
            # Check IOCs
            for ioc in threat_intel['iocs']:
                if self._check_ioc_match(finding, ioc):
                    correlations.append({
                        'finding_id': finding.id,
                        'threat_type': ioc['threat_type'],
                        'ioc_value': ioc['value'],
                        'severity': 'High'
                    })
        
        return correlations
    
    def _check_ioc_match(self, finding, ioc):
        """Check if finding matches IOC"""
        # Decrypt finding data for analysis
        try:
            description = self.crypto.decrypt_data(finding.description)
            target_host = self.crypto.decrypt_data(finding.target_host)
            
            if ioc['type'] == 'ip' and ioc['value'] in target_host:
                return True
            if ioc['type'] == 'domain' and ioc['value'] in description:
                return True
                
        except:
            pass
        
        return False

class ZeroDayDetector:
    """Advanced zero-day vulnerability detection"""
    
    def __init__(self):
        self.behavior_patterns = {}
        self.anomaly_threshold = 0.15
        
    def analyze_for_zero_days(self, target_data):
        """Analyze target for potential zero-day vulnerabilities"""
        zero_day_indicators = []
        
        # Behavioral analysis
        behavioral_anomalies = self._detect_behavioral_anomalies(target_data)
        zero_day_indicators.extend(behavioral_anomalies)
        
        # Protocol fuzzing results
        fuzzing_results = self._analyze_fuzzing_results(target_data)
        zero_day_indicators.extend(fuzzing_results)
        
        # Memory corruption indicators
        memory_indicators = self._detect_memory_corruption(target_data)
        zero_day_indicators.extend(memory_indicators)
        
        return zero_day_indicators
    
    def _detect_behavioral_anomalies(self, target_data):
        """Detect unusual behavioral patterns"""
        anomalies = []
        
        # Unusual response patterns
        if 'response_analysis' in target_data:
            responses = target_data['response_analysis']
            
            # Inconsistent error handling
            error_patterns = set()
            for response in responses:
                if 'error' in response:
                    error_patterns.add(response['error_type'])
            
            if len(error_patterns) > 3:  # Multiple different error types
                anomalies.append({
                    'type': 'Inconsistent Error Handling',
                    'description': 'Multiple error types suggest custom implementation',
                    'confidence': 0.6
                })
        
        return anomalies
    
    def _analyze_fuzzing_results(self, target_data):
        """Analyze fuzzing results for zero-day indicators"""
        indicators = []
        
        if 'fuzzing_results' in target_data:
            fuzzing = target_data['fuzzing_results']
            
            # Unexpected crashes
            if fuzzing.get('crashes', 0) > 0:
                indicators.append({
                    'type': 'Application Crash',
                    'description': f"Service crashed {fuzzing['crashes']} times during fuzzing",
                    'confidence': 0.8
                })
            
            # Memory leaks
            if fuzzing.get('memory_usage_increase', 0) > 50:  # 50% increase
                indicators.append({
                    'type': 'Memory Leak',
                    'description': 'Significant memory usage increase detected',
                    'confidence': 0.7
                })
        
        return indicators
    
    def _detect_memory_corruption(self, target_data):
        """Detect memory corruption vulnerabilities"""
        indicators = []
        
        # Static analysis indicators
        if 'binary_analysis' in target_data:
            binary = target_data['binary_analysis']
            
            # Lack of security mitigations
            missing_mitigations = []
            security_features = ['aslr', 'dep', 'stack_canary', 'fortify']
            
            for feature in security_features:
                if not binary.get(feature, False):
                    missing_mitigations.append(feature)
            
            if len(missing_mitigations) >= 2:
                indicators.append({
                    'type': 'Missing Security Mitigations',
                    'description': f"Missing: {', '.join(missing_mitigations)}",
                    'confidence': 0.7
                })
        
        return indicators

class ExploitGenerator:
    """AI-powered exploit generation and development"""
    
    def __init__(self):
        self.exploit_templates = {}
        self.payload_database = {}
        self._load_exploit_templates()
        
    def _load_exploit_templates(self):
        """Load exploit templates and payloads"""
        self.exploit_templates = {
            'buffer_overflow': {
                'pattern': 'A' * 1000,
                'shellcode_offset': 112,
                'return_address': '\\x41\\x42\\x43\\x44'
            },
            'sql_injection': {
                'patterns': [
                    "' OR '1'='1",
                    "'; DROP TABLE users; --",
                    "' UNION SELECT * FROM information_schema.tables --"
                ]
            },
            'command_injection': {
                'patterns': [
                    "; cat /etc/passwd",
                    "| whoami",
                    "&& id"
                ]
            }
        }
    
    def generate_exploit(self, vulnerability_data):
        """Generate custom exploit based on vulnerability analysis"""
        exploit_code = {
            'type': vulnerability_data.get('type', 'unknown'),
            'target': vulnerability_data.get('target', ''),
            'payload': '',
            'delivery_method': '',
            'success_probability': 0.0
        }
        
        vuln_type = vulnerability_data.get('type', '').lower()
        
        if 'buffer_overflow' in vuln_type:
            exploit_code.update(self._generate_buffer_overflow_exploit(vulnerability_data))
        elif 'sql_injection' in vuln_type:
            exploit_code.update(self._generate_sql_injection_exploit(vulnerability_data))
        elif 'command_injection' in vuln_type:
            exploit_code.update(self._generate_command_injection_exploit(vulnerability_data))
        else:
            exploit_code.update(self._generate_generic_exploit(vulnerability_data))
        
        return exploit_code
    
    def _generate_buffer_overflow_exploit(self, vuln_data):
        """Generate buffer overflow exploit"""
        template = self.exploit_templates['buffer_overflow']
        
        # Calculate exact buffer size needed
        buffer_size = vuln_data.get('buffer_size', 1000)
        offset = vuln_data.get('offset', template['shellcode_offset'])
        
        exploit = {
            'payload': template['pattern'][:offset] + template['return_address'],
            'delivery_method': 'TCP',
            'success_probability': 0.75,
            'notes': f'Buffer overflow with {offset} byte offset'
        }
        
        return exploit
    
    def _generate_sql_injection_exploit(self, vuln_data):
        """Generate SQL injection exploit"""
        patterns = self.exploit_templates['sql_injection']['patterns']
        
        # Choose pattern based on database type
        db_type = vuln_data.get('database_type', 'mysql')
        selected_pattern = patterns[0]  # Default
        
        if 'postgresql' in db_type.lower():
            selected_pattern = patterns[2]  # UNION-based
        elif 'mssql' in db_type.lower():
            selected_pattern = patterns[1]  # More aggressive
        
        exploit = {
            'payload': selected_pattern,
            'delivery_method': 'HTTP POST',
            'success_probability': 0.8,
            'notes': f'SQL injection for {db_type}'
        }
        
        return exploit
    
    def _generate_command_injection_exploit(self, vuln_data):
        """Generate command injection exploit"""
        patterns = self.exploit_templates['command_injection']['patterns']
        
        # Select pattern based on OS
        os_type = vuln_data.get('os_type', 'linux')
        selected_pattern = patterns[0]  # Default Unix/Linux
        
        if 'windows' in os_type.lower():
            selected_pattern = "&& dir"  # Windows command
        
        exploit = {
            'payload': selected_pattern,
            'delivery_method': 'HTTP Parameter',
            'success_probability': 0.7,
            'notes': f'Command injection for {os_type}'
        }
        
        return exploit
    
    def _generate_generic_exploit(self, vuln_data):
        """Generate generic exploit framework"""
        exploit = {
            'payload': 'Generic payload - manual customization required',
            'delivery_method': 'Manual',
            'success_probability': 0.5,
            'notes': 'Custom exploit development needed'
        }
        
        return exploit

# Global AI intelligence instance
ai_intelligence = AIVulnerabilityPredictor()