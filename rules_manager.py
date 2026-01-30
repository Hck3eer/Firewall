#!/usr/bin/env python3
"""
Rules Management and Persistence
"""
import json
import yaml
import os
from datetime import datetime
from typing import Dict, List, Set
import hashlib

class RulesManager:
    def __init__(self, rules_file: str = "firewall_rules.json"):
        self.rules_file = rules_file
        self.backup_dir = "rules_backup"
        self.rules: Dict = {
            'blocked_ips': set(),
            'blocked_domains': set(),
            'blocked_subnets': set(),
            'allowed_ips': set(),
            'allowed_domains': set(),
            'timestamp': None,
            'version': '1.0'
        }
        
        # Create backup directory
        os.makedirs(self.backup_dir, exist_ok=True)
        
        # Load existing rules
        self.load()
    
    def save(self):
        """Save rules to file"""
        # Convert sets to lists for JSON serialization
        save_data = {
            'blocked_ips': list(self.rules['blocked_ips']),
            'blocked_domains': list(self.rules['blocked_domains']),
            'blocked_subnets': list(self.rules['blocked_subnets']),
            'allowed_ips': list(self.rules['allowed_ips']),
            'allowed_domains': list(self.rules['allowed_domains']),
            'timestamp': datetime.now().isoformat(),
            'version': self.rules['version']
        }
        
        # Create backup before saving
        self.create_backup()
        
        with open(self.rules_file, 'w') as f:
            json.dump(save_data, f, indent=2, sort_keys=True)
        
        # Update hash
        self.current_hash = self.calculate_hash()
    
    def load(self):
        """Load rules from file"""
        if os.path.exists(self.rules_file):
            try:
                with open(self.rules_file, 'r') as f:
                    data = json.load(f)
                
                # Convert lists back to sets
                self.rules['blocked_ips'] = set(data.get('blocked_ips', []))
                self.rules['blocked_domains'] = set(data.get('blocked_domains', []))
                self.rules['blocked_subnets'] = set(data.get('blocked_subnets', []))
                self.rules['allowed_ips'] = set(data.get('allowed_ips', []))
                self.rules['allowed_domains'] = set(data.get('allowed_domains', []))
                self.rules['timestamp'] = data.get('timestamp')
                self.rules['version'] = data.get('version', '1.0')
                
                self.current_hash = self.calculate_hash()
                
            except json.JSONDecodeError:
                print("Warning: Corrupted rules file, starting fresh")
                self.rules['timestamp'] = datetime.now().isoformat()
        else:
            self.rules['timestamp'] = datetime.now().isoformat()
            self.save()
    
    def create_backup(self):
        """Create backup of rules"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_file = os.path.join(self.backup_dir, f"rules_backup_{timestamp}.json")
        
        if os.path.exists(self.rules_file):
            import shutil
            shutil.copy2(self.rules_file, backup_file)
            
            # Keep only last 10 backups
            self.cleanup_backups()
    
    def cleanup_backups(self, keep_last: int = 10):
        """Clean up old backups"""
        import glob
        
        backups = glob.glob(os.path.join(self.backup_dir, "rules_backup_*.json"))
        backups.sort(key=os.path.getmtime)
        
        if len(backups) > keep_last:
            for old_backup in backups[:-keep_last]:
                os.remove(old_backup)
    
    def calculate_hash(self) -> str:
        """Calculate hash of current rules"""
        data = json.dumps({
            'blocked_ips': sorted(list(self.rules['blocked_ips'])),
            'blocked_domains': sorted(list(self.rules['blocked_domains'])),
            'blocked_subnets': sorted(list(self.rules['blocked_subnets'])),
            'allowed_ips': sorted(list(self.rules['allowed_ips'])),
            'allowed_domains': sorted(list(self.rules['allowed_domains']))
        }, sort_keys=True)
        
        return hashlib.sha256(data.encode()).hexdigest()
    
    def has_changed(self) -> bool:
        """Check if rules have changed since last save"""
        return self.calculate_hash() != self.current_hash
    
    def add_blocked_ip(self, ip: str):
        """Add IP to blocked list"""
        self.rules['blocked_ips'].add(ip)
        self.rules['allowed_ips'].discard(ip)
    
    def remove_blocked_ip(self, ip: str):
        """Remove IP from blocked list"""
        self.rules['blocked_ips'].discard(ip)
    
    def add_allowed_ip(self, ip: str):
        """Add IP to allowed list"""
        self.rules['allowed_ips'].add(ip)
        self.rules['blocked_ips'].discard(ip)
    
    def add_blocked_domain(self, domain: str):
        """Add domain to blocked list"""
        self.rules['blocked_domains'].add(domain)
        self.rules['allowed_domains'].discard(domain)
    
    def add_blocked_subnet(self, subnet: str):
        """Add subnet to blocked list"""
        self.rules['blocked_subnets'].add(subnet)
    
    def export_to_yaml(self, filename: str):
        """Export rules to YAML format"""
        export_data = {
            'firewall_rules': {
                'blocked': {
                    'ips': sorted(list(self.rules['blocked_ips'])),
                    'domains': sorted(list(self.rules['blocked_domains'])),
                    'subnets': sorted(list(self.rules['blocked_subnets']))
                },
                'allowed': {
                    'ips': sorted(list(self.rules['allowed_ips'])),
                    'domains': sorted(list(self.rules['allowed_domains']))
                },
                'metadata': {
                    'timestamp': self.rules['timestamp'],
                    'version': self.rules['version'],
                    'total_blocked': len(self.rules['blocked_ips']) + 
                                    len(self.rules['blocked_domains']) + 
                                    len(self.rules['blocked_subnets'])
                }
            }
        }
        
        with open(filename, 'w') as f:
            yaml.dump(export_data, f, default_flow_style=False)
    
    def import_from_yaml(self, filename: str):
        """Import rules from YAML format"""
        try:
            with open(filename, 'r') as f:
                data = yaml.safe_load(f)
            
            if 'firewall_rules' in data:
                rules = data['firewall_rules']
                
                # Clear existing rules
                self.rules['blocked_ips'].clear()
                self.rules['blocked_domains'].clear()
                self.rules['blocked_subnets'].clear()
                self.rules['allowed_ips'].clear()
                self.rules['allowed_domains'].clear()
                
                # Import blocked items
                for ip in rules.get('blocked', {}).get('ips', []):
                    self.rules['blocked_ips'].add(ip)
                
                for domain in rules.get('blocked', {}).get('domains', []):
                    self.rules['blocked_domains'].add(domain)
                
                for subnet in rules.get('blocked', {}).get('subnets', []):
                    self.rules['blocked_subnets'].add(subnet)
                
                # Import allowed items
                for ip in rules.get('allowed', {}).get('ips', []):
                    self.rules['allowed_ips'].add(ip)
                
                for domain in rules.get('allowed', {}).get('domains', []):
                    self.rules['allowed_domains'].add(domain)
                
                self.save()
                return True
                
        except Exception as e:
            print(f"Error importing rules: {e}")
            return False
    
    def get_stats(self) -> Dict:
        """Get statistics about rules"""
        return {
            'total_blocked_ips': len(self.rules['blocked_ips']),
            'total_blocked_domains': len(self.rules['blocked_domains']),
            'total_blocked_subnets': len(self.rules['blocked_subnets']),
            'total_allowed_ips': len(self.rules['allowed_ips']),
            'total_allowed_domains': len(self.rules['allowed_domains']),
            'last_modified': self.rules['timestamp'],
            'has_changed': self.has_changed()
        }
    
    def search(self, query: str) -> Dict[str, List[str]]:
        """Search for items matching query"""
        results = {
            'blocked_ips': [],
            'blocked_domains': [],
            'allowed_ips': [],
            'allowed_domains': []
        }
        
        query = query.lower()
        
        for ip in self.rules['blocked_ips']:
            if query in ip:
                results['blocked_ips'].append(ip)
        
        for domain in self.rules['blocked_domains']:
            if query in domain:
                results['blocked_domains'].append(domain)
        
        for ip in self.rules['allowed_ips']:
            if query in ip:
                results['allowed_ips'].append(ip)
        
        for domain in self.rules['allowed_domains']:
            if query in domain:
                results['allowed_domains'].append(domain)
        
        return results
    
    def validate_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        import re
        pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        if not pattern.match(ip):
            return False
        parts = ip.split('.')
        return all(0 <= int(part) <= 255 for part in parts)
    
    def validate_subnet(self, subnet: str) -> bool:
        """Validate subnet format"""
        try:
            from ipaddress import ip_network
            ip_network(subnet, strict=False)
            return True
        except ValueError:
            return False

# Example usage
if __name__ == "__main__":
    manager = RulesManager()
    
    # Add some test rules
    manager.add_blocked_ip("192.168.1.100")
    manager.add_blocked_domain("malicious.com")
    manager.add_blocked_subnet("10.0.0.0/8")
    
    # Save rules
    manager.save()
    
    # Get stats
    stats = manager.get_stats()
    print("Firewall Rules Statistics:")
    print(json.dumps(stats, indent=2))
    
    # Export to YAML
    manager.export_to_yaml("firewall_rules.yaml")