#!/usr/bin/env python3
"""
Network Scanning Utilities for VM Discovery
"""
import subprocess
import ipaddress
import socket
import concurrent.futures
from typing import List, Set, Dict
import json

class NetworkScanner:
    def __init__(self, network_range: str = "192.168.1.0/24"):
        self.network_range = network_range
        self.discovered_hosts: Dict[str, Dict] = {}
    
    def scan_arp(self) -> Dict[str, Dict]:
        """Scan using ARP requests"""
        try:
            import scapy.all as scapy
            
            print(f"Scanning {self.network_range} with ARP...")
            
            arp_request = scapy.ARP(pdst=self.network_range)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast/arp_request
            
            answered_list = scapy.srp(
                arp_request_broadcast,
                timeout=2,
                verbose=False
            )[0]
            
            for sent, received in answered_list:
                ip = received.psrc
                mac = received.hwsrc
                
                self.discovered_hosts[ip] = {
                    'ip': ip,
                    'mac': mac,
                    'hostname': self.get_hostname(ip),
                    'vendor': self.get_mac_vendor(mac),
                    'type': self.detect_device_type(mac)
                }
            
            return self.discovered_hosts
            
        except ImportError:
            print("Scapy not available, using ping scan")
            return self.scan_ping()
    
    def scan_ping(self) -> Dict[str, Dict]:
        """Scan using ICMP ping"""
        network = ipaddress.ip_network(self.network_range)
        ip_list = [str(ip) for ip in network.hosts()]
        
        print(f"Pinging {len(ip_list)} hosts...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            future_to_ip = {
                executor.submit(self.ping_host, ip): ip 
                for ip in ip_list
            }
            
            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    result = future.result(timeout=2)
                    if result:
                        self.discovered_hosts[ip] = {
                            'ip': ip,
                            'mac': 'Unknown',
                            'hostname': self.get_hostname(ip),
                            'vendor': 'Unknown',
                            'type': 'Unknown'
                        }
                except:
                    pass
        
        return self.discovered_hosts
    
    def ping_host(self, ip: str) -> bool:
        """Ping a single host"""
        try:
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '1', ip],
                capture_output=True,
                timeout=2
            )
            return result.returncode == 0
        except:
            return False
    
    def get_hostname(self, ip: str) -> str:
        """Try to get hostname for IP"""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except:
            return "Unknown"
    
    def get_mac_vendor(self, mac: str) -> str:
        """Get vendor from MAC address (first 3 bytes)"""
        # Simple MAC vendor lookup
        vendors = {
            '00:00:00': 'XEROX',
            '00:50:56': 'VMware',
            '00:0C:29': 'VMware',
            '00:1C:14': 'VMware',
            '00:05:69': 'VMware',
            '08:00:27': 'VirtualBox',
            '00:1C:42': 'Parallels',
            '00:15:5D': 'Microsoft Hyper-V',
            '00:16:3E': 'Xen',
            '00:1B:21': 'Intel',
            '00:1C:C0': 'Fujitsu',
            '00:24:81': 'Huawei',
            '00:26:AB': 'Apple',
            '00:50:F2': 'Microsoft',
            '00:E0:4C': 'Realtek'
        }
        
        mac_prefix = mac.upper()[:8]
        for prefix, vendor in vendors.items():
            if mac_prefix.startswith(prefix):
                return vendor
        
        return "Unknown"
    
    def detect_device_type(self, mac: str) -> str:
        """Detect device type from MAC"""
        mac_prefix = mac.upper()[:8]
        
        # VMware MAC ranges
        vmware_prefixes = ['00:50:56', '00:0C:29', '00:1C:14', '00:05:69']
        virtualbox_prefixes = ['08:00:27']
        parallels_prefixes = ['00:1C:42']
        hyperv_prefixes = ['00:15:5D']
        xen_prefixes = ['00:16:3E']
        
        if any(mac_prefix.startswith(p) for p in vmware_prefixes):
            return "VMware VM"
        elif any(mac_prefix.startswith(p) for p in virtualbox_prefixes):
            return "VirtualBox VM"
        elif any(mac_prefix.startswith(p) for p in parallels_prefixes):
            return "Parallels VM"
        elif any(mac_prefix.startswith(p) for p in hyperv_prefixes):
            return "Hyper-V VM"
        elif any(mac_prefix.startswith(p) for p in xen_prefixes):
            return "Xen VM"
        else:
            return "Physical Host"
    
    def scan_ports(self, ip: str, ports: List[int] = None) -> Dict[int, str]:
        """Scan common ports on host"""
        if ports is None:
            ports = [22, 80, 443, 3389, 5900, 8080]
        
        open_ports = {}
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = "Unknown"
                    open_ports[port] = service
            except:
                pass
        
        return open_ports
    
    def export_results(self, filename: str = "network_scan.json"):
        """Export scan results to JSON"""
        with open(filename, 'w') as f:
            json.dump(self.discovered_hosts, f, indent=2)
    
    def load_results(self, filename: str = "network_scan.json"):
        """Load scan results from JSON"""
        try:
            with open(filename, 'r') as f:
                self.discovered_hosts = json.load(f)
        except:
            self.discovered_hosts = {}
    
    def get_vms(self) -> Dict[str, Dict]:
        """Get only VMs from discovered hosts"""
        vms = {}
        for ip, info in self.discovered_hosts.items():
            if 'VM' in info.get('type', '') or 'Virtual' in info.get('type', ''):
                vms[ip] = info
        return vms

def main():
    scanner = NetworkScanner("192.168.1.0/24")
    results = scanner.scan_arp()
    
    print(f"\nDiscovered {len(results)} hosts:")
    print("-" * 60)
    for ip, info in results.items():
        print(f"IP: {ip}")
        print(f"  MAC: {info['mac']}")
        print(f"  Hostname: {info['hostname']}")
        print(f"  Vendor: {info['vendor']}")
        print(f"  Type: {info['type']}")
        print()
    
    # Export results
    scanner.export_results()

if __name__ == "__main__":
    main()