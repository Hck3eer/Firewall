#!/usr/bin/env python3
"""
Command Line Interface for VM Firewall
"""
import argparse
import sys
import json
from typing import Optional
from firewall_core import VMFirewallCore

class FirewallCLI:
    def __init__(self):
        self.firewall = VMFirewallCore()
    
    def block_ip(self, ip: str, subnet: bool = False):
        """Block IP or subnet"""
        if subnet:
            success = self.firewall.block_subnet(ip)
        else:
            success = self.firewall.block_ip_vm_network(ip)
        
        if success:
            print(f"✓ Blocked: {ip}")
            self.firewall.save_rules()
        else:
            print(f"✗ Failed to block: {ip}")
            sys.exit(1)
    
    def block_domain(self, domain: str):
        """Block domain"""
        success = self.firewall.block_domain(domain)
        
        if success:
            print(f"✓ Blocked domain: {domain}")
            self.firewall.save_rules()
        else:
            print(f"✗ Failed to block domain: {domain}")
            sys.exit(1)
    
    def unblock(self, target: str):
        """Unblock IP, domain, or subnet"""
        # Check if it's an IP
        import ipaddress
        try:
            ipaddress.ip_address(target)
            success = self.firewall.unblock_ip(target)
            if success:
                print(f"✓ Unblocked: {target}")
            else:
                print(f"✗ Failed to unblock: {target}")
        except ValueError:
            # Might be a domain
            if target in self.firewall.blocked_domains:
                self.firewall.blocked_domains.discard(target)
                print(f"✓ Unblocked domain: {target}")
            else:
                print(f"✗ Not found in blocked items: {target}")
        
        self.firewall.save_rules()
    
    def list_blocked(self, json_output: bool = False):
        """List blocked items"""
        blocked = self.firewall.list_blocked()
        
        if json_output:
            print(json.dumps(blocked, indent=2))
        else:
            print("\n=== BLOCKED ITEMS ===")
            
            if blocked['ips']:
                print(f"\nIP Addresses ({len(blocked['ips'])}):")
                for ip in blocked['ips']:
                    print(f"  🔴 {ip}")
            
            if blocked['domains']:
                print(f"\nDomains ({len(blocked['domains'])}):")
                for domain in blocked['domains']:
                    print(f"  🔴 {domain}")
            
            if blocked['subnets']:
                print(f"\nSubnets ({len(blocked['subnets'])}):")
                for subnet in blocked['subnets']:
                    print(f"  🔴 {subnet}")
            
            if blocked['vms_discovered']:
                print(f"\nVMs on Network ({len(blocked['vms_discovered'])}):")
                for vm in blocked['vms_discovered']:
                    print(f"  ⚡ {vm}")
            
            print(f"\nTotal blocked: {len(blocked['ips']) + len(blocked['domains'])}")
    
    def status(self):
        """Show firewall status"""
        blocked = self.firewall.list_blocked()
        
        print("\n=== FIREWALL STATUS ===")
        print(f"Active: ✓")
        print(f"Blocked IPs: {len(blocked['ips'])}")
        print(f"Blocked Domains: {len(blocked['domains'])}")
        print(f"VMs on Network: {len(blocked['vms_discovered'])}")
        print(f"Cross-VM Blocking: {'Enabled' if self.firewall.config['network']['block_all_vms'] else 'Disabled'}")
    
    def test(self):
        """Test firewall functionality"""
        print("Testing firewall...")
        success = self.firewall.test_blocking()
        
        if success:
            print("✓ Firewall is working correctly")
        else:
            print("✗ Firewall test failed")
            sys.exit(1)
    
    def flush(self):
        """Flush all rules"""
        confirm = input("Are you sure you want to flush ALL firewall rules? (yes/no): ")
        if confirm.lower() == 'yes':
            self.firewall.flush_rules()
            print("✓ All rules flushed")
        else:
            print("Cancelled")

def main():
    parser = argparse.ArgumentParser(description="VM Network Firewall CLI")
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Block IP
    block_ip_parser = subparsers.add_parser('block-ip', help='Block IP address')
    block_ip_parser.add_argument('ip', help='IP address to block')
    block_ip_parser.add_argument('--subnet', action='store_true', help='Block as subnet')
    
    # Block domain
    block_domain_parser = subparsers.add_parser('block-domain', help='Block domain')
    block_domain_parser.add_argument('domain', help='Domain to block')
    
    # Unblock
    unblock_parser = subparsers.add_parser('unblock', help='Unblock IP or domain')
    unblock_parser.add_argument('target', help='IP or domain to unblock')
    
    # List blocked
    list_parser = subparsers.add_parser('list', help='List blocked items')
    list_parser.add_argument('--json', action='store_true', help='JSON output')
    
    # Status
    subparsers.add_parser('status', help='Show firewall status')
    
    # Test
    subparsers.add_parser('test', help='Test firewall')
    
    # Flush
    subparsers.add_parser('flush', help='Flush all rules')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    cli = FirewallCLI()
    
    try:
        if args.command == 'block-ip':
            cli.block_ip(args.ip, args.subnet)
        elif args.command == 'block-domain':
            cli.block_domain(args.domain)
        elif args.command == 'unblock':
            cli.unblock(args.target)
        elif args.command == 'list':
            cli.list_blocked(args.json)
        elif args.command == 'status':
            cli.status()
        elif args.command == 'test':
            cli.test()
        elif args.command == 'flush':
            cli.flush()
    except KeyboardInterrupt:
        print("\nOperation cancelled")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()