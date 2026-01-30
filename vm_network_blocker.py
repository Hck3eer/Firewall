#!/usr/bin/env python3
"""
VM Network Blocker - Cross-VM Traffic Blocking
Manages blocking across multiple virtual machines on the same network
"""
import subprocess
import socket
import ipaddress
import paramiko
import threading
import queue
import time
import json
import os
import re
from typing import List, Dict, Set, Optional, Tuple
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class VMNetworkBlocker:
    """
    Manages network blocking across multiple VMs
    """
    def __init__(self, config_path: str = "config.yaml"):
        self.vms: Dict[str, Dict] = {}  # ip -> {info}
        self.ssh_clients: Dict[str, paramiko.SSHClient] = {}
        self.ssh_keys: Dict[str, paramiko.RSAKey] = {}
        self.block_queue = queue.Queue()
        self.worker_thread = None
        self.is_running = False
        
        # Load configuration
        self.load_config(config_path)
        
        # Initialize SSH
        self.load_ssh_keys()
        
        # Start worker thread
        self.start_worker()
    
    def load_config(self, config_path: str):
        """Load configuration from YAML file"""
        import yaml
        
        default_config = {
            'network': {
                'vm_network_range': '192.168.1.0/24',
                'scan_interval': 300,  # 5 minutes
                'auto_discover': True,
                'max_workers': 10
            },
            'ssh': {
                'username': 'root',
                'port': 22,
                'timeout': 10,
                'key_path': '~/.ssh/id_rsa'
            },
            'blocking': {
                'max_retries': 3,
                'retry_delay': 2
            }
        }
        
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                self.config = {**default_config, **yaml.safe_load(f)}
        else:
            self.config = default_config
            logger.warning(f"Config file {config_path} not found, using defaults")
    
    def load_ssh_keys(self):
        """Load SSH keys for authentication"""
        key_path = os.path.expanduser(self.config['ssh']['key_path'])
        
        if os.path.exists(key_path):
            try:
                self.ssh_key = paramiko.RSAKey.from_private_key_file(key_path)
                logger.info(f"Loaded SSH key from {key_path}")
            except Exception as e:
                logger.error(f"Failed to load SSH key: {e}")
                self.ssh_key = None
        else:
            logger.warning(f"SSH key not found at {key_path}")
            self.ssh_key = None
    
    def start_worker(self):
        """Start worker thread for processing blocking tasks"""
        self.is_running = True
        self.worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self.worker_thread.start()
        logger.info("VM Network Blocker worker started")
    
    def stop_worker(self):
        """Stop worker thread"""
        self.is_running = False
        if self.worker_thread:
            self.worker_thread.join(timeout=5)
        logger.info("VM Network Blocker worker stopped")
    
    def _worker_loop(self):
        """Worker thread loop for processing blocking tasks"""
        while self.is_running:
            try:
                # Get task from queue (with timeout to allow checking is_running)
                try:
                    task = self.block_queue.get(timeout=1)
                except queue.Empty:
                    continue
                
                # Process task
                self._process_task(task)
                
                # Mark task as done
                self.block_queue.task_done()
                
            except Exception as e:
                logger.error(f"Error in worker loop: {e}")
    
    def _process_task(self, task: Dict):
        """Process a blocking task"""
        task_type = task.get('type')
        target = task.get('target')
        
        logger.info(f"Processing task: {task_type} {target}")
        
        if task_type == 'block_ip':
            ip = target
            self.block_ip_all_vms(ip)
        
        elif task_type == 'unblock_ip':
            ip = target
            self.unblock_ip_all_vms(ip)
        
        elif task_type == 'block_domain':
            domain = target
            self.block_domain_all_vms(domain)
        
        elif task_type == 'sync_rules':
            self.sync_rules_all_vms()
        
        elif task_type == 'discover_vms':
            self.discover_vms_network()
    
    def discover_vms_network(self) -> Dict[str, Dict]:
        """
        Discover VMs on the network
        Returns: Dict of VM IPs with their information
        """
        logger.info("Starting VM network discovery...")
        
        # Get network range from config
        network_range = self.config['network']['vm_network_range']
        
        # Methods to try for discovery
        discovery_methods = [
            self._discover_vms_arp,
            self._discover_vms_nmap,
            self._discover_vms_ping,
            self._discover_vms_known_hosts
        ]
        
        discovered_vms = {}
        
        for method in discovery_methods:
            try:
                vms = method(network_range)
                if vms:
                    discovered_vms.update(vms)
                    break  # Stop at first successful method
            except Exception as e:
                logger.warning(f"Discovery method failed: {e}")
                continue
        
        # Filter out localhost
        local_ips = self._get_local_ips()
        discovered_vms = {ip: info for ip, info in discovered_vms.items() 
                         if ip not in local_ips}
        
        # Test SSH connectivity
        for vm_ip in list(discovered_vms.keys()):
            if self.test_ssh_connection(vm_ip):
                discovered_vms[vm_ip]['ssh_accessible'] = True
                discovered_vms[vm_ip]['last_seen'] = datetime.now().isoformat()
            else:
                discovered_vms[vm_ip]['ssh_accessible'] = False
        
        self.vms = discovered_vms
        
        logger.info(f"Discovered {len(self.vms)} VMs on network")
        
        # Save discovery results
        self.save_discovery_results()
        
        return discovered_vms
    
    def _discover_vms_arp(self, network_range: str) -> Dict[str, Dict]:
        """Discover VMs using ARP scanning"""
        try:
            import scapy.all as scapy
            
            logger.info(f"ARP scanning network: {network_range}")
            
            arp_request = scapy.ARP(pdst=network_range)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast/arp_request
            
            answered_list = scapy.srp(
                arp_request_broadcast,
                timeout=2,
                verbose=False
            )[0]
            
            discovered_vms = {}
            for sent, received in answered_list:
                ip = received.psrc
                mac = received.hwsrc
                
                discovered_vms[ip] = {
                    'ip': ip,
                    'mac': mac,
                    'method': 'arp',
                    'vendor': self._get_mac_vendor(mac),
                    'type': self._detect_vm_type(mac)
                }
            
            return discovered_vms
            
        except ImportError:
            logger.warning("Scapy not available for ARP scanning")
            return {}
    
    def _discover_vms_nmap(self, network_range: str) -> Dict[str, Dict]:
        """Discover VMs using nmap"""
        try:
            import nmap
            
            logger.info(f"Nmap scanning network: {network_range}")
            
            nm = nmap.PortScanner()
            nm.scan(hosts=network_range, arguments='-sn')
            
            discovered_vms = {}
            for host in nm.all_hosts():
                if nm[host].state() == 'up':
                    discovered_vms[host] = {
                        'ip': host,
                        'method': 'nmap',
                        'hostname': nm[host].hostname(),
                        'vendor': nm[host].get('vendor', {}),
                        'type': 'Unknown'
                    }
            
            return discovered_vms
            
        except ImportError:
            logger.warning("python-nmap not available")
            return {}
    
    def _discover_vms_ping(self, network_range: str) -> Dict[str, Dict]:
        """Discover VMs using ping sweep"""
        logger.info(f"Ping scanning network: {network_range}")
        
        import concurrent.futures
        
        network = ipaddress.ip_network(network_range)
        ip_list = [str(ip) for ip in network.hosts()]
        
        discovered_vms = {}
        
        def ping_ip(ip):
            try:
                result = subprocess.run(
                    ['ping', '-c', '1', '-W', '1', ip],
                    capture_output=True,
                    timeout=2
                )
                return ip if result.returncode == 0 else None
            except:
                return None
        
        max_workers = self.config['network'].get('max_workers', 10)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(ping_ip, ip): ip for ip in ip_list}
            
            for future in concurrent.futures.as_completed(futures):
                ip = futures[future]
                try:
                    result = future.result(timeout=3)
                    if result:
                        discovered_vms[result] = {
                            'ip': result,
                            'method': 'ping',
                            'type': 'Unknown'
                        }
                except:
                    pass
        
        return discovered_vms
    
    def _discover_vms_known_hosts(self, network_range: str) -> Dict[str, Dict]:
        """Check known hosts from SSH config"""
        logger.info("Checking known SSH hosts...")
        
        discovered_vms = {}
        
        # Check SSH known_hosts
        known_hosts_path = os.path.expanduser('~/.ssh/known_hosts')
        
        if os.path.exists(known_hosts_path):
            try:
                with open(known_hosts_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            parts = line.split()
                            if parts:
                                host = parts[0]
                                # Extract IP from hostname
                                ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', host)
                                if ip_match:
                                    ip = ip_match.group()
                                    # Check if IP is in network range
                                    if ipaddress.ip_address(ip) in ipaddress.ip_network(network_range):
                                        discovered_vms[ip] = {
                                            'ip': ip,
                                            'method': 'ssh_known_hosts',
                                            'hostname': host.split(',')[0] if ',' in host else host,
                                            'type': 'Known SSH Host'
                                        }
            except Exception as e:
                logger.warning(f"Error reading known_hosts: {e}")
        
        return discovered_vms
    
    def _get_local_ips(self) -> Set[str]:
        """Get local IP addresses"""
        local_ips = set()
        
        try:
            # Get all network interfaces
            import netifaces
            
            for interface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    for addr_info in addrs[netifaces.AF_INET]:
                        ip = addr_info.get('addr')
                        if ip:
                            local_ips.add(ip)
        except ImportError:
            # Fallback method
            try:
                # Get primary IP
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                local_ips.add(s.getsockname()[0])
                s.close()
            except:
                pass
        
        # Always include localhost
        local_ips.update(['127.0.0.1', 'localhost'])
        
        return local_ips
    
    def _get_mac_vendor(self, mac: str) -> str:
        """Get vendor from MAC address"""
        # Common VM MAC prefixes
        vm_prefixes = {
            '00:05:69': 'VMware',
            '00:0C:29': 'VMware',
            '00:1C:14': 'VMware',
            '00:50:56': 'VMware',
            '08:00:27': 'VirtualBox',
            '00:1C:42': 'Parallels',
            '00:15:5D': 'Microsoft Hyper-V',
            '00:16:3E': 'Xen',
            '52:54:00': 'QEMU/KVM'
        }
        
        mac_upper = mac.upper().replace('-', ':')
        for prefix, vendor in vm_prefixes.items():
            if mac_upper.startswith(prefix):
                return vendor
        
        return "Unknown"
    
    def _detect_vm_type(self, mac: str) -> str:
        """Detect if device is a VM"""
        vendor = self._get_mac_vendor(mac)
        
        if vendor != "Unknown":
            return f"{vendor} VM"
        
        return "Physical Host"
    
    def test_ssh_connection(self, vm_ip: str) -> bool:
        """
        Test SSH connection to VM
        Returns: True if connection successful
        """
        try:
            client = self._get_ssh_client(vm_ip)
            if client:
                # Execute a simple command to test
                stdin, stdout, stderr = client.exec_command('echo "SSH Test"', timeout=5)
                output = stdout.read().decode().strip()
                
                if output == "SSH Test":
                    logger.debug(f"SSH connection successful to {vm_ip}")
                    return True
                else:
                    client.close()
                    return False
            else:
                return False
                
        except Exception as e:
            logger.debug(f"SSH connection failed to {vm_ip}: {e}")
            return False
    
    def _get_ssh_client(self, vm_ip: str) -> Optional[paramiko.SSHClient]:
        """
        Get or create SSH client for VM
        Returns: SSHClient or None if connection fails
        """
        if vm_ip in self.ssh_clients:
            # Check if existing client is still connected
            client = self.ssh_clients[vm_ip]
            try:
                # Try to execute a simple command to test connection
                stdin, stdout, stderr = client.exec_command('echo "test"', timeout=2)
                return client
            except:
                # Connection lost, remove and reconnect
                client.close()
                del self.ssh_clients[vm_ip]
        
        # Create new connection
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            ssh_config = self.config['ssh']
            username = ssh_config.get('username', 'root')
            port = ssh_config.get('port', 22)
            timeout = ssh_config.get('timeout', 10)
            
            if self.ssh_key:
                # Use key-based authentication
                client.connect(
                    hostname=vm_ip,
                    username=username,
                    pkey=self.ssh_key,
                    port=port,
                    timeout=timeout,
                    banner_timeout=timeout
                )
            else:
                # Try passwordless login (might work for some setups)
                client.connect(
                    hostname=vm_ip,
                    username=username,
                    port=port,
                    timeout=timeout,
                    banner_timeout=timeout
                )
            
            self.ssh_clients[vm_ip] = client
            return client
            
        except Exception as e:
            logger.warning(f"Failed to create SSH connection to {vm_ip}: {e}")
            return None
    
    def block_ip_all_vms(self, ip: str) -> Dict[str, Dict]:
        """
        Block IP on all discovered VMs
        Returns: Dict with results for each VM
        """
        logger.info(f"Blocking IP {ip} on all VMs")
        
        results = {}
        
        # Create threads for parallel blocking
        threads = []
        result_queue = queue.Queue()
        
        for vm_ip, vm_info in self.vms.items():
            if vm_info.get('ssh_accessible', False):
                thread = threading.Thread(
                    target=self._block_ip_on_vm_thread,
                    args=(vm_ip, ip, result_queue)
                )
                threads.append(thread)
                thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join(timeout=30)
        
        # Collect results
        while not result_queue.empty():
            vm_ip, success, message = result_queue.get()
            results[vm_ip] = {
                'success': success,
                'message': message
            }
        
        # Log summary
        success_count = sum(1 for r in results.values() if r['success'])
        total_count = len(results)
        
        logger.info(f"Blocked {ip} on {success_count}/{total_count} VMs")
        
        return results
    
    def _block_ip_on_vm_thread(self, vm_ip: str, target_ip: str, result_queue: queue.Queue):
        """Thread function to block IP on a VM"""
        try:
            success = self._block_ip_on_vm(vm_ip, target_ip)
            result_queue.put((vm_ip, success, "Blocked" if success else "Failed"))
        except Exception as e:
            result_queue.put((vm_ip, False, str(e)))
    
    def _block_ip_on_vm(self, vm_ip: str, target_ip: str) -> bool:
        """Block IP on specific VM"""
        client = self._get_ssh_client(vm_ip)
        if not client:
            return False
        
        try:
            # Block in INPUT chain
            stdin, stdout, stderr = client.exec_command(
                f'sudo iptables -A INPUT -s {target_ip} -j DROP',
                timeout=10
            )
            stdout.read()
            stderr.read()
            
            # Block in FORWARD chain
            stdin, stdout, stderr = client.exec_command(
                f'sudo iptables -A FORWARD -s {target_ip} -j DROP',
                timeout=10
            )
            stdout.read()
            stderr.read()
            
            # Block in OUTPUT chain
            stdin, stdout, stderr = client.exec_command(
                f'sudo iptables -A OUTPUT -d {target_ip} -j DROP',
                timeout=10
            )
            stdout.read()
            stderr.read()
            
            logger.debug(f"Successfully blocked {target_ip} on {vm_ip}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to block {target_ip} on {vm_ip}: {e}")
            return False
    
    def unblock_ip_all_vms(self, ip: str) -> Dict[str, Dict]:
        """
        Unblock IP on all discovered VMs
        Returns: Dict with results for each VM
        """
        logger.info(f"Unblocking IP {ip} on all VMs")
        
        results = {}
        
        for vm_ip, vm_info in self.vms.items():
            if vm_info.get('ssh_accessible', False):
                success = self._unblock_ip_on_vm(vm_ip, ip)
                results[vm_ip] = {
                    'success': success,
                    'message': "Unblocked" if success else "Failed"
                }
        
        return results
    
    def _unblock_ip_on_vm(self, vm_ip: str, target_ip: str) -> bool:
        """Unblock IP on specific VM"""
        client = self._get_ssh_client(vm_ip)
        if not client:
            return False
        
        try:
            # Remove from all chains
            chains = ['INPUT', 'FORWARD', 'OUTPUT']
            
            for chain in chains:
                # Get rule numbers
                stdin, stdout, stderr = client.exec_command(
                    f'sudo iptables -L {chain} --line-numbers -n',
                    timeout=10
                )
                output = stdout.read().decode()
                
                # Find rules with target IP
                lines = output.split('\n')
                rule_numbers = []
                
                for line in lines:
                    if target_ip in line and ('DROP' in line or 'REJECT' in line):
                        # Extract rule number
                        match = re.match(r'^(\d+)', line.strip())
                        if match:
                            rule_numbers.append(match.group(1))
                
                # Remove rules (in reverse order to maintain indices)
                for rule_num in sorted(rule_numbers, reverse=True):
                    stdin, stdout, stderr = client.exec_command(
                        f'sudo iptables -D {chain} {rule_num}',
                        timeout=10
                    )
                    stdout.read()
                    stderr.read()
            
            logger.debug(f"Successfully unblocked {target_ip} on {vm_ip}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to unblock {target_ip} on {vm_ip}: {e}")
            return False
    
    def block_domain_all_vms(self, domain: str) -> Dict[str, Dict]:
        """
        Block domain on all discovered VMs
        Returns: Dict with results for each VM
        """
        logger.info(f"Blocking domain {domain} on all VMs")
        
        # Resolve domain to IPs
        ips = self._resolve_domain(domain)
        
        if not ips:
            logger.warning(f"No IPs found for domain {domain}")
            return {}
        
        results = {}
        
        # Block each IP on all VMs
        for ip in ips:
            ip_results = self.block_ip_all_vms(ip)
            
            # Combine results
            for vm_ip, result in ip_results.items():
                if vm_ip not in results:
                    results[vm_ip] = result
                else:
                    # Update existing result
                    if result['success']:
                        results[vm_ip]['success'] = True
                        results[vm_ip]['message'] = f"Multiple IPs blocked"
        
        logger.info(f"Blocked domain {domain} ({len(ips)} IPs) on all VMs")
        return results
    
    def _resolve_domain(self, domain: str) -> List[str]:
        """Resolve domain to IP addresses"""
        try:
            ips = []
            
            # Get all IP addresses for domain
            addrinfo = socket.getaddrinfo(domain, None)
            
            for info in addrinfo:
                ip = info[4][0]
                if ip not in ips and self._is_valid_ip(ip):
                    ips.append(ip)
            
            return ips
            
        except socket.gaierror as e:
            logger.error(f"Failed to resolve domain {domain}: {e}")
            return []
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Check if IP is valid and not private/local"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Skip private IPs for domain blocking (usually not what we want)
            if ip_obj.is_private:
                return False
            
            # Skip loopback
            if ip_obj.is_loopback:
                return False
            
            return True
            
        except ValueError:
            return False
    
    def sync_rules_all_vms(self, rules_file: str = "firewall_rules.json") -> Dict[str, Dict]:
        """
        Sync firewall rules to all VMs
        Returns: Dict with sync results for each VM
        """
        logger.info("Syncing firewall rules to all VMs")
        
        # Load rules from file
        if not os.path.exists(rules_file):
            logger.error(f"Rules file not found: {rules_file}")
            return {}
        
        try:
            with open(rules_file, 'r') as f:
                rules = json.load(f)
        except Exception as e:
            logger.error(f"Failed to load rules: {e}")
            return {}
        
        blocked_ips = rules.get('blocked_ips', [])
        
        results = {}
        
        # Sync each rule to each VM
        for vm_ip, vm_info in self.vms.items():
            if vm_info.get('ssh_accessible', False):
                vm_results = []
                
                for ip in blocked_ips:
                    success = self._block_ip_on_vm(vm_ip, ip)
                    vm_results.append({
                        'ip': ip,
                        'success': success
                    })
                
                success_count = sum(1 for r in vm_results if r['success'])
                results[vm_ip] = {
                    'success': success_count == len(blocked_ips),
                    'blocked': success_count,
                    'total': len(blocked_ips)
                }
        
        logger.info("Rules sync completed")
        return results
    
    def get_vm_status(self) -> Dict[str, Dict]:
        """
        Get status of all VMs
        Returns: Dict with VM status information
        """
        status = {}
        
        for vm_ip, vm_info in self.vms.items():
            # Test SSH connection
            ssh_accessible = self.test_ssh_connection(vm_ip)
            
            # Get firewall status
            firewall_status = self._get_vm_firewall_status(vm_ip) if ssh_accessible else {}
            
            status[vm_ip] = {
                **vm_info,
                'ssh_accessible': ssh_accessible,
                'firewall_status': firewall_status,
                'last_checked': datetime.now().isoformat()
            }
        
        return status
    
    def _get_vm_firewall_status(self, vm_ip: str) -> Dict:
        """Get firewall status from VM"""
        client = self._get_ssh_client(vm_ip)
        if not client:
            return {}
        
        try:
            # Get iptables rules count
            stdin, stdout, stderr = client.exec_command(
                'sudo iptables -L INPUT -n | grep -c DROP',
                timeout=10
            )
            drop_count = stdout.read().decode().strip()
            
            # Get firewall service status
            stdin, stdout, stderr = client.exec_command(
                'systemctl is-active iptables 2>/dev/null || echo "inactive"',
                timeout=10
            )
            service_status = stdout.read().decode().strip()
            
            return {
                'drop_rules': drop_count,
                'service_status': service_status,
                'active': service_status == 'active'
            }
            
        except Exception as e:
            logger.error(f"Failed to get firewall status from {vm_ip}: {e}")
            return {}
    
    def save_discovery_results(self, filename: str = "vm_discovery.json"):
        """Save VM discovery results to file"""
        results = {
            'vms': self.vms,
            'timestamp': datetime.now().isoformat(),
            'total_vms': len(self.vms),
            'accessible_vms': sum(1 for v in self.vms.values() if v.get('ssh_accessible', False))
        }
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        
        logger.info(f"Discovery results saved to {filename}")
    
    def load_discovery_results(self, filename: str = "vm_discovery.json"):
        """Load VM discovery results from file"""
        if os.path.exists(filename):
            try:
                with open(filename, 'r') as f:
                    results = json.load(f)
                
                self.vms = results.get('vms', {})
                logger.info(f"Loaded discovery results from {filename}")
                
            except Exception as e:
                logger.error(f"Failed to load discovery results: {e}")
    
    def cleanup(self):
        """Cleanup resources"""
        self.stop_worker()
        
        # Close SSH connections
        for vm_ip, client in self.ssh_clients.items():
            try:
                client.close()
            except:
                pass
        
        self.ssh_clients.clear()
        logger.info("VM Network Blocker cleaned up")

# Command-line interface for VM Network Blocker
def cli():
    """Command-line interface"""
    import argparse
    
    parser = argparse.ArgumentParser(description="VM Network Blocker")
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Discover command
    discover_parser = subparsers.add_parser('discover', help='Discover VMs on network')
    discover_parser.add_argument('--range', help='Network range', default='192.168.1.0/24')
    
    # Block command
    block_parser = subparsers.add_parser('block', help='Block IP/domain on all VMs')
    block_parser.add_argument('target', help='IP address or domain to block')
    block_parser.add_argument('--domain', action='store_true', help='Target is a domain')
    
    # Unblock command
    unblock_parser = subparsers.add_parser('unblock', help='Unblock IP on all VMs')
    unblock_parser.add_argument('ip', help='IP address to unblock')
    
    # Status command
    subparsers.add_parser('status', help='Show VM status')
    
    # Sync command
    subparsers.add_parser('sync', help='Sync rules to all VMs')
    
    # List command
    subparsers.add_parser('list', help='List discovered VMs')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Create blocker instance
    blocker = VMNetworkBlocker()
    
    try:
        if args.command == 'discover':
            print(f"Discovering VMs on network {args.range}...")
            vms = blocker.discover_vms_network()
            
            print(f"\nDiscovered {len(vms)} VMs:")
            print("-" * 80)
            for ip, info in vms.items():
                vm_type = info.get('type', 'Unknown')
                accessible = "✓" if info.get('ssh_accessible', False) else "✗"
                print(f"{accessible} {ip:15} {vm_type:20} {info.get('vendor', 'Unknown')}")
        
        elif args.command == 'block':
            if args.domain:
                print(f"Blocking domain {args.target} on all VMs...")
                results = blocker.block_domain_all_vms(args.target)
            else:
                print(f"Blocking IP {args.target} on all VMs...")
                results = blocker.block_ip_all_vms(args.target)
            
            print(f"\nBlocking results:")
            print("-" * 80)
            for vm_ip, result in results.items():
                status = "✓ Success" if result['success'] else "✗ Failed"
                print(f"{vm_ip:15} {status:15} {result.get('message', '')}")
        
        elif args.command == 'unblock':
            print(f"Unblocking IP {args.ip} on all VMs...")
            results = blocker.unblock_ip_all_vms(args.ip)
            
            print(f"\nUnblocking results:")
            print("-" * 80)
            for vm_ip, result in results.items():
                status = "✓ Success" if result['success'] else "✗ Failed"
                print(f"{vm_ip:15} {status:15} {result.get('message', '')}")
        
        elif args.command == 'status':
            print("Getting VM status...")
            status = blocker.get_vm_status()
            
            print(f"\nVM Status ({len(status)} VMs):")
            print("-" * 80)
            for vm_ip, info in status.items():
                ssh = "✓ SSH" if info.get('ssh_accessible', False) else "✗ No SSH"
                fw_status = info.get('firewall_status', {})
                active = "✓ FW Active" if fw_status.get('active', False) else "✗ FW Inactive"
                print(f"{vm_ip:15} {ssh:10} {active:15}")
        
        elif args.command == 'sync':
            print("Syncing rules to all VMs...")
            results = blocker.sync_rules_all_vms()
            
            print(f"\nSync results:")
            print("-" * 80)
            for vm_ip, result in results.items():
                if result['success']:
                    print(f"✓ {vm_ip}: {result['blocked']}/{result['total']} rules synced")
                else:
                    print(f"✗ {vm_ip}: Failed to sync rules")
        
        elif args.command == 'list':
            print(f"Discovered VMs ({len(blocker.vms)}):")
            print("-" * 80)
            for vm_ip, info in blocker.vms.items():
                vm_type = info.get('type', 'Unknown')
                accessible = "✓ SSH" if info.get('ssh_accessible', False) else "✗ No SSH"
                print(f"{vm_ip:15} {vm_type:20} {accessible}")
        
    finally:
        blocker.cleanup()

if __name__ == "__main__":
    # For testing
    # python3 vm_network_blocker.py discover
    # python3 vm_network_blocker.py block 8.8.8.8
    cli()