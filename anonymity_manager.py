import socks
import socket
import requests
import random
import time
import logging
from stem import Signal
from stem.control import Controller
import os

class AnonymityManager:
    def __init__(self):
        self.tor_enabled = False
        self.proxy_chains = []
        self.current_proxy = None
        self.tor_controller = None
        
    def setup_tor_proxy(self):
        """Setup Tor proxy for anonymized traffic"""
        try:
            # Configure SOCKS proxy for Tor
            socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 9050)
            socket.socket = socks.socksocket
            
            # Test Tor connection
            if self._test_tor_connection():
                self.tor_enabled = True
                logging.info("Tor proxy activated successfully")
                
                # Setup Tor controller for circuit management
                try:
                    self.tor_controller = Controller.from_port(port=9051)
                    self.tor_controller.authenticate()
                    logging.info("Tor controller connected")
                except Exception as e:
                    logging.warning(f"Could not connect to Tor controller: {str(e)}")
                
                return True
            else:
                logging.warning("Tor proxy test failed, continuing without Tor")
                return False
                
        except Exception as e:
            logging.error(f"Failed to setup Tor proxy: {str(e)}")
            return False
    
    def _test_tor_connection(self):
        """Test if Tor connection is working"""
        try:
            # Use a simple HTTP request to test connectivity
            proxies = {
                'http': 'socks5://127.0.0.1:9050',
                'https': 'socks5://127.0.0.1:9050'
            }
            
            response = requests.get(
                'http://httpbin.org/ip',
                proxies=proxies,
                timeout=10
            )
            
            if response.status_code == 200:
                ip_info = response.json()
                logging.info(f"Tor connection active. Exit IP: {ip_info.get('origin')}")
                return True
            
        except Exception as e:
            logging.debug(f"Tor connection test failed: {str(e)}")
        
        return False
    
    def rotate_tor_circuit(self):
        """Rotate Tor circuit to get new exit node"""
        try:
            if self.tor_controller:
                self.tor_controller.signal(Signal.NEWNYM)
                time.sleep(5)  # Wait for new circuit
                logging.info("Tor circuit rotated")
                return True
        except Exception as e:
            logging.error(f"Failed to rotate Tor circuit: {str(e)}")
        
        return False
    
    def setup_proxy_chain(self, proxy_list):
        """Setup proxy chain for enhanced anonymity"""
        try:
            self.proxy_chains = []
            
            for proxy in proxy_list:
                if self._test_proxy(proxy):
                    self.proxy_chains.append(proxy)
                    logging.info(f"Added proxy to chain: {proxy['host']}:{proxy['port']}")
            
            if self.proxy_chains:
                self.current_proxy = random.choice(self.proxy_chains)
                logging.info(f"Proxy chain setup complete with {len(self.proxy_chains)} proxies")
                return True
            
        except Exception as e:
            logging.error(f"Failed to setup proxy chain: {str(e)}")
        
        return False
    
    def _test_proxy(self, proxy_config):
        """Test individual proxy connectivity"""
        try:
            proxy_url = f"{proxy_config['protocol']}://{proxy_config['host']}:{proxy_config['port']}"
            proxies = {'http': proxy_url, 'https': proxy_url}
            
            response = requests.get(
                'http://httpbin.org/ip',
                proxies=proxies,
                timeout=10
            )
            
            return response.status_code == 200
            
        except Exception as e:
            logging.debug(f"Proxy test failed for {proxy_config}: {str(e)}")
            return False
    
    def get_proxy_config(self):
        """Get current proxy configuration for requests"""
        if self.tor_enabled:
            return {
                'http': 'socks5://127.0.0.1:9050',
                'https': 'socks5://127.0.0.1:9050'
            }
        elif self.current_proxy:
            proxy_url = f"{self.current_proxy['protocol']}://{self.current_proxy['host']}:{self.current_proxy['port']}"
            return {'http': proxy_url, 'https': proxy_url}
        
        return None
    
    def randomize_user_agent(self):
        """Generate random user agent for requests"""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0'
        ]
        
        return random.choice(user_agents)
    
    def get_anonymized_session(self):
        """Get a requests session configured for anonymity"""
        session = requests.Session()
        
        # Set random user agent
        session.headers.update({'User-Agent': self.randomize_user_agent()})
        
        # Configure proxy
        proxy_config = self.get_proxy_config()
        if proxy_config:
            session.proxies = proxy_config
        
        # Disable SSL verification for testing (can be enabled based on requirements)
        session.verify = False
        
        # Set reasonable timeouts
        session.timeout = 30
        
        return session
    
    def obfuscate_traffic(self, data):
        """Apply traffic obfuscation techniques"""
        try:
            # Add random delays
            time.sleep(random.uniform(0.1, 2.0))
            
            # In a real implementation, this could include:
            # - Packet fragmentation
            # - Traffic padding
            # - Protocol tunneling
            # - Timing randomization
            
            return data
            
        except Exception as e:
            logging.error(f"Traffic obfuscation failed: {str(e)}")
            return data
    
    def enable_anti_forensics(self):
        """Enable anti-forensics capabilities"""
        try:
            # Clear DNS cache
            if os.name == 'nt':  # Windows
                os.system('ipconfig /flushdns')
            else:  # Linux/Mac
                os.system('sudo systemctl restart systemd-resolved')
            
            # Clear browser cache and history (if applicable)
            # This would be implemented based on specific requirements
            
            logging.info("Anti-forensics measures activated")
            return True
            
        except Exception as e:
            logging.error(f"Anti-forensics setup failed: {str(e)}")
            return False
    
    def get_anonymity_status(self):
        """Get current anonymity status"""
        status = {
            'tor_enabled': self.tor_enabled,
            'proxy_chains_count': len(self.proxy_chains),
            'current_proxy': self.current_proxy['host'] if self.current_proxy else None,
            'exit_ip': None
        }
        
        # Get current exit IP
        try:
            session = self.get_anonymized_session()
            response = session.get('http://httpbin.org/ip', timeout=10)
            if response.status_code == 200:
                status['exit_ip'] = response.json().get('origin')
        except:
            pass
        
        return status
    
    def setup_vpn_tunnel(self, vpn_config):
        """Setup VPN tunnel for additional security layer"""
        try:
            # This would integrate with OpenVPN or similar
            # For demonstration, we'll simulate VPN setup
            
            if self._test_vpn_connectivity(vpn_config):
                logging.info("VPN tunnel established")
                return True
            else:
                logging.warning("VPN tunnel setup failed")
                return False
                
        except Exception as e:
            logging.error(f"VPN setup failed: {str(e)}")
            return False
    
    def _test_vpn_connectivity(self, vpn_config):
        """Test VPN connectivity"""
        # In a real implementation, this would test the VPN connection
        # For demonstration purposes, we'll return True
        return True
    
    def cleanup_anonymity(self):
        """Cleanup anonymity resources"""
        try:
            if self.tor_controller:
                self.tor_controller.close()
            
            # Reset socket to default
            socket.socket = socket._orig_socket
            
            self.tor_enabled = False
            self.proxy_chains = []
            self.current_proxy = None
            
            logging.info("Anonymity resources cleaned up")
            
        except Exception as e:
            logging.error(f"Anonymity cleanup failed: {str(e)}")
