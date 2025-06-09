"""
Red Team Platform - P2P Mesh Network with I2P/Tor Integration
Decentralized connection system with randomized path selection
"""

import socket
import threading
import time
import json
import random
import hashlib
import base64
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import subprocess
import logging

class P2PMeshNetwork:
    """Decentralized P2P mesh network with Tor/I2P integration"""
    
    def __init__(self):
        self.nodes = {}
        self.trusted_nodes = []
        self.active_connections = {}
        self.relay_servers = []
        self.current_relay = None
        self.mesh_active = False
        self.tor_active = False
        self.i2p_active = False
        self.encryption_key = None
        self.node_id = None
        self.relay_rotation_timer = None
        
    def initialize_mesh(self):
        """Initialize P2P mesh network"""
        try:
            # Generate unique node ID
            self.node_id = self._generate_node_id()
            
            # Initialize encryption
            self.encryption_key = Fernet.generate_key()
            
            # Bootstrap trusted nodes
            self._bootstrap_trusted_nodes()
            
            # Initialize Tor/I2P connections
            self._initialize_anonymity_networks()
            
            # Start relay rotation
            self._start_relay_rotation()
            
            # Begin mesh discovery
            self._start_mesh_discovery()
            
            self.mesh_active = True
            logging.info(f"P2P mesh initialized with node ID: {self.node_id}")
            
            return {
                'success': True,
                'node_id': self.node_id,
                'tor_active': self.tor_active,
                'i2p_active': self.i2p_active,
                'trusted_nodes': len(self.trusted_nodes)
            }
            
        except Exception as e:
            logging.error(f"Mesh initialization failed: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _generate_node_id(self):
        """Generate unique node identifier"""
        timestamp = str(int(time.time()))
        random_data = base64.b64encode(random.randbytes(16)).decode()
        node_data = f"{timestamp}-{random_data}"
        
        digest = hashes.Hash(hashes.SHA256())
        digest.update(node_data.encode())
        node_hash = digest.finalize()
        
        return base64.b64encode(node_hash).decode()[:32]
    
    def _bootstrap_trusted_nodes(self):
        """Bootstrap with hardcoded trusted nodes"""
        # Simulated trusted node endpoints
        bootstrap_nodes = [
            {'id': 'node_alpha', 'host': '127.0.0.1', 'port': 9001, 'type': 'bootstrap'},
            {'id': 'node_beta', 'host': '127.0.0.1', 'port': 9002, 'type': 'bootstrap'},
            {'id': 'node_gamma', 'host': '127.0.0.1', 'port': 9003, 'type': 'bootstrap'},
        ]
        
        for node in bootstrap_nodes:
            self.trusted_nodes.append(node)
            self.nodes[node['id']] = {
                'host': node['host'],
                'port': node['port'],
                'trust_level': 1.0,
                'last_seen': datetime.utcnow(),
                'connection_attempts': 0,
                'success_rate': 1.0
            }
    
    def _initialize_anonymity_networks(self):
        """Initialize Tor and I2P connections"""
        # Initialize Tor
        try:
            self._setup_tor_connection()
            self.tor_active = True
        except Exception as e:
            logging.warning(f"Tor initialization failed: {str(e)}")
            self.tor_active = False
        
        # Initialize I2P
        try:
            self._setup_i2p_connection()
            self.i2p_active = True
        except Exception as e:
            logging.warning(f"I2P initialization failed: {str(e)}")
            self.i2p_active = False
    
    def _setup_tor_connection(self):
        """Set up Tor connection"""
        # Check if Tor is available
        try:
            # Test Tor SOCKS proxy
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect(('127.0.0.1', 9050))
            sock.close()
            
            logging.info("Tor SOCKS proxy detected")
            return True
        except Exception:
            # Try to start Tor service
            try:
                subprocess.run(['tor', '--version'], capture_output=True, timeout=5)
                logging.info("Tor available but not running")
                return False
            except Exception:
                logging.warning("Tor not available")
                return False
    
    def _setup_i2p_connection(self):
        """Set up I2P connection"""
        try:
            # Check for I2P HTTP proxy
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect(('127.0.0.1', 4444))
            sock.close()
            
            logging.info("I2P HTTP proxy detected")
            return True
        except Exception:
            logging.warning("I2P not available")
            return False
    
    def _start_relay_rotation(self):
        """Start automatic relay server rotation"""
        def rotate_relays():
            while self.mesh_active:
                try:
                    self._rotate_relay_server()
                    time.sleep(300)  # Rotate every 5 minutes
                except Exception as e:
                    logging.error(f"Relay rotation error: {str(e)}")
                    time.sleep(60)
        
        self.relay_rotation_timer = threading.Thread(target=rotate_relays, daemon=True)
        self.relay_rotation_timer.start()
    
    def _rotate_relay_server(self):
        """Rotate to a new relay server"""
        available_relays = [
            {'host': '127.0.0.1', 'port': 8001, 'region': 'local'},
            {'host': '127.0.0.1', 'port': 8002, 'region': 'local'},
            {'host': '127.0.0.1', 'port': 8003, 'region': 'local'},
        ]
        
        # Select random relay different from current
        available = [r for r in available_relays if r != self.current_relay]
        if available:
            self.current_relay = random.choice(available)
            logging.info(f"Rotated to relay: {self.current_relay['host']}:{self.current_relay['port']}")
    
    def _start_mesh_discovery(self):
        """Start mesh node discovery"""
        def discovery_loop():
            while self.mesh_active:
                try:
                    self._discover_nodes()
                    self._update_node_status()
                    time.sleep(30)  # Discovery every 30 seconds
                except Exception as e:
                    logging.error(f"Mesh discovery error: {str(e)}")
                    time.sleep(60)
        
        discovery_thread = threading.Thread(target=discovery_loop, daemon=True)
        discovery_thread.start()
    
    def _discover_nodes(self):
        """Discover new mesh nodes"""
        for node_id, node_info in list(self.nodes.items()):
            if node_id not in self.active_connections:
                try:
                    # Attempt connection through anonymity network
                    connection = self._connect_to_node(node_info)
                    if connection:
                        self.active_connections[node_id] = connection
                        node_info['last_seen'] = datetime.utcnow()
                        node_info['success_rate'] = min(1.0, node_info['success_rate'] + 0.1)
                except Exception as e:
                    node_info['connection_attempts'] += 1
                    node_info['success_rate'] = max(0.0, node_info['success_rate'] - 0.05)
                    logging.warning(f"Failed to connect to node {node_id}: {str(e)}")
    
    def _connect_to_node(self, node_info):
        """Connect to a mesh node through anonymity network"""
        try:
            # Create connection through current relay
            if self.current_relay:
                # Simulate relay connection
                connection = {
                    'type': 'relay',
                    'target': node_info,
                    'relay': self.current_relay,
                    'established': datetime.utcnow(),
                    'encrypted': True
                }
                return connection
            
            # Direct connection fallback
            connection = {
                'type': 'direct',
                'target': node_info,
                'established': datetime.utcnow(),
                'encrypted': True
            }
            return connection
            
        except Exception as e:
            logging.error(f"Node connection failed: {str(e)}")
            return None
    
    def _update_node_status(self):
        """Update node status and remove stale connections"""
        current_time = datetime.utcnow()
        stale_threshold = timedelta(minutes=10)
        
        # Remove stale connections
        stale_connections = []
        for node_id, connection in self.active_connections.items():
            if current_time - connection['established'] > stale_threshold:
                stale_connections.append(node_id)
        
        for node_id in stale_connections:
            del self.active_connections[node_id]
            logging.info(f"Removed stale connection to {node_id}")
    
    def send_encrypted_message(self, target_node, message):
        """Send encrypted message through mesh"""
        try:
            if target_node not in self.active_connections:
                raise Exception(f"No active connection to {target_node}")
            
            # Encrypt message
            fernet = Fernet(self.encryption_key)
            encrypted_msg = fernet.encrypt(json.dumps(message).encode())
            
            # Create message packet
            packet = {
                'from': self.node_id,
                'to': target_node,
                'timestamp': datetime.utcnow().isoformat(),
                'encrypted_data': base64.b64encode(encrypted_msg).decode(),
                'signature': self._sign_message(encrypted_msg)
            }
            
            # Route through randomized path
            path = self._select_routing_path(target_node)
            
            # Simulate message transmission
            logging.info(f"Sent encrypted message to {target_node} via {len(path)} hops")
            
            return {'success': True, 'hops': len(path)}
            
        except Exception as e:
            logging.error(f"Message send failed: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _select_routing_path(self, target_node):
        """Select randomized routing path to target"""
        available_nodes = list(self.active_connections.keys())
        if target_node in available_nodes:
            available_nodes.remove(target_node)
        
        # Select 1-3 intermediate hops
        hop_count = random.randint(1, min(3, len(available_nodes)))
        if hop_count > 0:
            hops = random.sample(available_nodes, hop_count)
            return hops + [target_node]
        else:
            return [target_node]
    
    def _sign_message(self, message):
        """Sign message for integrity verification"""
        digest = hashes.Hash(hashes.SHA256())
        digest.update(message)
        message_hash = digest.finalize()
        return base64.b64encode(message_hash).decode()[:32]
    
    def broadcast_to_mesh(self, message):
        """Broadcast message to all connected nodes"""
        results = {}
        
        for node_id in self.active_connections:
            result = self.send_encrypted_message(node_id, message)
            results[node_id] = result
        
        successful = sum(1 for r in results.values() if r.get('success'))
        
        return {
            'total_nodes': len(results),
            'successful': successful,
            'results': results
        }
    
    def get_mesh_status(self):
        """Get current mesh network status"""
        return {
            'mesh_active': self.mesh_active,
            'node_id': self.node_id,
            'tor_active': self.tor_active,
            'i2p_active': self.i2p_active,
            'trusted_nodes': len(self.trusted_nodes),
            'active_connections': len(self.active_connections),
            'current_relay': self.current_relay,
            'nodes': {
                node_id: {
                    'trust_level': info['trust_level'],
                    'success_rate': info['success_rate'],
                    'last_seen': info['last_seen'].isoformat(),
                    'connected': node_id in self.active_connections
                }
                for node_id, info in self.nodes.items()
            }
        }
    
    def shutdown_mesh(self):
        """Shutdown mesh network"""
        try:
            self.mesh_active = False
            
            # Close all connections
            self.active_connections.clear()
            
            # Clear sensitive data
            self.encryption_key = None
            self.node_id = None
            
            logging.info("P2P mesh network shutdown complete")
            return True
            
        except Exception as e:
            logging.error(f"Mesh shutdown error: {str(e)}")
            return False

# Global mesh network instance
mesh_network = P2PMeshNetwork()