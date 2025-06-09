import requests
import random
import time
import socket
from stem import Signal
from stem.control import Controller
import socks

class AnonymityManager:
    def __init__(self):
        self.tor_enabled = False
        self.proxy_chains = []
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0'
        ]
        self.setup_tor()
    
    def setup_tor(self):
        """Setup Tor connection"""
        try:
            # Test if Tor is running
            socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 9050)
            socket.socket = socks.socksocket
            
            # Test connection
            response = requests.get('http://httpbin.org/ip', timeout=10)
            if response.status_code == 200:
                self.tor_enabled = True
                print("Tor connection established")
            else:
                self.tor_enabled = False
        except Exception as e:
            print(f"Tor setup failed: {e}")
            self.tor_enabled = False
    
    def get_new_tor_identity(self):
        """Request new Tor identity"""
        if not self.tor_enabled:
            return False
        
        try:
            with Controller.from_port(port=9051) as controller:
                controller.authenticate()
                controller.signal(Signal.NEWNYM)
                time.sleep(controller.get_newnym_wait())
                return True
        except Exception as e:
            print(f"Failed to get new Tor identity: {e}")
            return False
    
    def get_random_user_agent(self):
        """Get random user agent"""
        return random.choice(self.user_agents)
    
    def create_anonymized_session(self):
        """Create requests session with anonymization"""
        session = requests.Session()
        
        # Set random user agent
        session.headers.update({
            'User-Agent': self.get_random_user_agent(),
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive'
        })
        
        # Configure proxy if Tor is available
        if self.tor_enabled:
            session.proxies = {
                'http': 'socks5://127.0.0.1:9050',
                'https': 'socks5://127.0.0.1:9050'
            }
        
        return session
    
    def obfuscate_timing(self, min_delay=1, max_delay=5):
        """Add random delay to obfuscate timing patterns"""
        delay = random.uniform(min_delay, max_delay)
        time.sleep(delay)
    
    def rotate_identity(self):
        """Rotate identity and get new IP"""
        if self.tor_enabled:
            self.get_new_tor_identity()
    
    def check_anonymity(self):
        """Check current IP and anonymity status"""
        try:
            session = self.create_anonymized_session()
            response = session.get('http://httpbin.org/ip', timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'status': 'anonymous' if self.tor_enabled else 'direct',
                    'ip': data.get('origin'),
                    'tor_enabled': self.tor_enabled
                }
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e),
                'tor_enabled': self.tor_enabled
            }
    
    def generate_fake_headers(self):
        """Generate realistic HTTP headers"""
        return {
            'User-Agent': self.get_random_user_agent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0'
        }

# Global anonymity manager instance
anonymity_manager = AnonymityManager()
