#!/usr/bin/env python3
"""
Core Firewall Functionality
Handles network blocking across VMs
"""
import subprocess
import ipaddress
import logging
import socket
import re
import json
import yaml
import os
from typing import Set, List, Dict, Optional
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class VMFirewallCore:
    def __init__(self, config_path="config.yaml"):
        self.load_config(config_path)
        self.blocked_ips: Set[str] = set()
        self.blocked_domains: Set[str] = set()
        self.allowed_ips: Set[str] = set()
        self.blocked_subnets: Set[str] = set()
        self.vm_ips: Set[str] = set()
        
        # Network interfaces
        self.interface = self.config['network']['interface']
        
        # Load existing rules
        self.load_rules()
        
        # Discover VMs on network
        if self.config['network']['block_all_vms']:
            self.discover_vm_network()
    
    def load_config(self, config_path: str):
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                self.config = yaml.safe_load(f)
        except FileNotFoundError:
            # Default config
            self.config = {
                'firewall': {
                    'chain_name': 'VM_FIREWALL',
                    'log_file': '/var/log/vm_firewall.log',
                    'rules_file': 'firewall_rules.json'
                },
                'network': {
                    'vm_network_range': '192.168.1.0/24',
                    'interface': 'eth0',
                    'block_all_vms': True,
                    'broadcast_block': True
                }
            }
    
    def discover_vm_network(self):
        """Discover all VMs on the same network"""
        try:
            import netifaces
            # Get network interfaces
            interfaces = netifaces.interfaces()
            
            for iface in interfaces:
                if iface.startswith('eth') or iface.startswith('enp'):
                    addrs = netifaces.ifaddresses(iface)
                    if netifaces.AF_INET in addrs:
                        for addr_info in addrs[netifaces.AF_INET]:
                            ip = addr_info['addr']
                            netmask = addr_info['netmask']
                            
                            # Calculate network range
                            network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                            
                            logger.info(f"Found network: {network} on {iface}")
                            
                            # Scan for other VMs (simple ARP scan)
                            self.scan_network_for_vms(str(network))
        except ImportError:
            logger.warning("netifaces not installed, using config network range")
            self.scan_network_for_vms(self.config['network']['vm_network_range'])
    
    def scan_network_for_vms(self, network_range: str):
        """Scan network for other VMs"""
        try:
            import scapy.all as scapy
            
            logger.info(f"Scanning network: {network_range}")
            
            # Create ARP request
            arp_request = scapy.ARP(pdst=network_range)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast/arp_request
            
            # Send and receive with timeout
            answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
            
            for element in answered_list:
                ip = element[1].psrc
                mac = element[1].hwsrc
                
                # Skip self
                if ip != self.get_local_ip():
                    self.vm_ips.add(ip)
                    logger.info(f"Found VM: {ip} ({mac})")
            
            logger.info(f"Total VMs found: {len(self.vm_ips)}")
            
        except ImportError:
            logger.warning("Scapy not installed, using nmap for scanning")
            self.scan_with_nmap(network_range)
        except Exception as e:
            logger.error(f"Scanning failed: {e}")
    
    def scan_with_nmap(self, network_range: str):
        """Scan using nmap"""
        try:
            result = subprocess.run(
                ['nmap', '-sn', network_range],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Parse nmap output for IPs
            lines = result.stdout.split('\n')
            for line in lines:
                if 'Nmap scan report for' in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        ip = parts[-1].strip('()')
                        self.vm_ips.add(ip)
            
        except (subprocess.SubprocessError, FileNotFoundError):
            logger.error("nmap not available, using simple ping scan")
            self.ping_scan(network_range)
    
    def ping_scan(self, network_range: str):
        """Simple ping scan"""
        import concurrent.futures
        
        def ping_ip(ip):
            try:
                result = subprocess.run(
                    ['ping', '-c', '1', '-W', '1', ip],
                    capture_output=True,
                    timeout=2
                )
                if result.returncode == 0:
                    return ip
            except:
                pass
            return None
        
        network = ipaddress.ip_network(network_range)
        ip_list = [str(ip) for ip in network.hosts()]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            results = executor.map(ping_ip, ip_list)
            
            for ip in results:
                if ip and ip != self.get_local_ip():
                    self.vm_ips.add(ip)
    
    def get_local_ip(self) -> str:
        """Get local IP address"""
        try:
            # Create a dummy socket to get local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def block_ip_vm_network(self, ip: str) -> bool:
        """Block IP across all VMs on network"""
        success = True
        
        # Block on local VM
        if not self.block_ip_local(ip):
            success = False
        
        # If configured to block across all VMs
        if self.config['network']['block_all_vms']:
            for vm_ip in self.vm_ips:
                if vm_ip != self.get_local_ip():
                    if not self.block_ip_remote(vm_ip, ip):
                        success = False
        
        return success
    
    def block_ip_local(self, ip: str) -> bool:
        """Block IP on local system"""
        try:
            # Add to iptables
            commands = [
                ['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'],
                ['iptables', '-A', 'FORWARD', '-s', ip, '-j', 'DROP'],
                ['iptables', '-A', 'OUTPUT', '-d', ip, '-j', 'DROP']
            ]
            
            for cmd in commands:
                subprocess.run(cmd, check=True, capture_output=True)
            
            self.blocked_ips.add(ip)
            logger.info(f"Blocked IP locally: {ip}")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to block IP {ip}: {e.stderr.decode()}")
            return False
    
    def block_ip_remote(self, vm_ip: str, target_ip: str) -> bool:
        """Attempt to block IP on remote VM using SSH"""
        try:
            # This requires SSH access to other VMs
            # You'll need to configure SSH keys for passwordless access
            ssh_cmd = [
                'ssh', f'root@{vm_ip}',
                f'iptables -A INPUT -s {target_ip} -j DROP && '
                f'iptables -A FORWARD -s {target_ip} -j DROP && '
                f'iptables -A OUTPUT -d {target_ip} -j DROP'
            ]
            
            result = subprocess.run(
                ssh_cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                logger.info(f"Blocked {target_ip} on remote VM {vm_ip}")
                return True
            else:
                logger.warning(f"Failed to block on {vm_ip}: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            logger.warning(f"Timeout blocking on remote VM {vm_ip}")
            return False
        except Exception as e:
            logger.error(f"Error blocking on remote VM {vm_ip}: {e}")
            return False
    
    def block_domain(self, domain: str) -> bool:
        """Block domain and all its IPs across network"""
        try:
            # Resolve domain
            ips = self.resolve_domain(domain)
            
            if not ips:
                logger.warning(f"No IPs found for domain: {domain}")
                return False
            
            self.blocked_domains.add(domain)
            
            # Block all IPs
            success = True
            for ip in ips:
                if not self.block_ip_vm_network(ip):
                    success = False
            
            logger.info(f"Blocked domain {domain} ({len(ips)} IPs)")
            return success
            
        except Exception as e:
            logger.error(f"Failed to block domain {domain}: {e}")
            return False
    
    def resolve_domain(self, domain: str) -> List[str]:
        """Resolve domain to IP addresses"""
        try:
            ips = []
            
            # Get IPv4 addresses
            for info in socket.getaddrinfo(domain, None, socket.AF_INET):
                ip = info[4][0]
                if ip not in ips:
                    ips.append(ip)
            
            # Also try direct resolution
            try:
                hostname, aliaslist, ipaddrlist = socket.gethostbyname_ex(domain)
                for ip in ipaddrlist:
                    if ip not in ips:
                        ips.append(ip)
            except:
                pass
            
            return ips
            
        except socket.gaierror as e:
            logger.error(f"DNS resolution failed for {domain}: {e}")
            return []
    
    def block_subnet(self, subnet: str) -> bool:
        """Block entire subnet"""
        try:
            # Validate subnet
            network = ipaddress.ip_network(subnet, strict=False)
            
            # Block the entire range
            cmd = [
                'iptables', '-A', 'INPUT',
                '-s', subnet,
                '-j', 'DROP'
            ]
            
            subprocess.run(cmd, check=True)
            self.blocked_subnets.add(subnet)
            
            logger.info(f"Blocked subnet: {subnet}")
            return True
            
        except (ValueError, subprocess.CalledProcessError) as e:
            logger.error(f"Failed to block subnet {subnet}: {e}")
            return False
    
    def unblock_ip(self, ip: str) -> bool:
        """Unblock IP"""
        try:
            # Remove from local
            commands = [
                ['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'],
                ['iptables', '-D', 'FORWARD', '-s', ip, '-j', 'DROP'],
                ['iptables', '-D', 'OUTPUT', '-d', ip, '-j', 'DROP']
            ]
            
            for cmd in commands:
                subprocess.run(cmd, capture_output=True, stderr=subprocess.DEVNULL)
            
            self.blocked_ips.discard(ip)
            
            # Remove from remote VMs
            if self.config['network']['block_all_vms']:
                for vm_ip in self.vm_ips:
                    self.unblock_ip_remote(vm_ip, ip)
            
            logger.info(f"Unblocked IP: {ip}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to unblock IP {ip}: {e}")
            return False
    
    def unblock_ip_remote(self, vm_ip: str, target_ip: str) -> bool:
        """Unblock IP on remote VM"""
        try:
            ssh_cmd = [
                'ssh', f'root@{vm_ip}',
                f'iptables -D INPUT -s {target_ip} -j DROP 2>/dev/null; '
                f'iptables -D FORWARD -s {target_ip} -j DROP 2>/dev/null; '
                f'iptables -D OUTPUT -d {target_ip} -j DROP 2>/dev/null'
            ]
            
            subprocess.run(ssh_cmd, capture_output=True, timeout=10)
            return True
            
        except:
            return False
    
    def list_blocked(self) -> Dict[str, List[str]]:
        """List all blocked items"""
        return {
            'ips': sorted(list(self.blocked_ips)),
            'domains': sorted(list(self.blocked_domains)),
            'subnets': sorted(list(self.blocked_subnets)),
            'vms_discovered': sorted(list(self.vm_ips))
        }
    
    def save_rules(self):
        """Save rules to file"""
        rules = {
            'blocked_ips': list(self.blocked_ips),
            'blocked_domains': list(self.blocked_domains),
            'blocked_subnets': list(self.blocked_subnets),
            'allowed_ips': list(self.allowed_ips),
            'timestamp': datetime.now().isoformat()
        }
        
        with open(self.config['firewall']['rules_file'], 'w') as f:
            json.dump(rules, f, indent=2)
    
    def load_rules(self):
        """Load rules from file"""
        rules_file = self.config['firewall']['rules_file']
        
        if os.path.exists(rules_file):
            try:
                with open(rules_file, 'r') as f:
                    rules = json.load(f)
                
                self.blocked_ips = set(rules.get('blocked_ips', []))
                self.blocked_domains = set(rules.get('blocked_domains', []))
                self.blocked_subnets = set(rules.get('blocked_subnets', []))
                self.allowed_ips = set(rules.get('allowed_ips', []))
                
                logger.info(f"Loaded {len(self.blocked_ips)} blocked IPs")
                
            except json.JSONDecodeError:
                logger.warning("Corrupted rules file, starting fresh")
    
    def flush_rules(self):
        """Flush all firewall rules"""
        try:
            # Flush all chains
            subprocess.run(['iptables', '-F'], check=True)
            subprocess.run(['iptables', '-X'], check=True)
            
            # Reset to default policies
            subprocess.run(['iptables', '-P', 'INPUT', 'ACCEPT'], check=True)
            subprocess.run(['iptables', '-P', 'FORWARD', 'ACCEPT'], check=True)
            subprocess.run(['iptables', '-P', 'OUTPUT', 'ACCEPT'], check=True)
            
            self.blocked_ips.clear()
            self.blocked_domains.clear()
            self.blocked_subnets.clear()
            
            logger.info("Flushed all firewall rules")
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to flush rules: {e}")
    
    def test_blocking(self, test_ip: str = "8.8.8.8") -> bool:
        """Test if blocking is working"""
        try:
            # Try to ping the test IP
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '2', test_ip],
                capture_output=True,
                text=True
            )
            
            # Block the IP
            self.block_ip_local(test_ip)
            
            # Try to ping again
            result2 = subprocess.run(
                ['ping', '-c', '1', '-W', '2', test_ip],
                capture_output=True,
                text=True
            )
            
            # Unblock
            self.unblock_ip(test_ip)
            
            if result.returncode == 0 and result2.returncode != 0:
                logger.info("✓ Blocking test PASSED")
                return True
            else:
                logger.warning("✗ Blocking test FAILED")
                return False
                
        except Exception as e:
            logger.error(f"Test failed: {e}")
            return False