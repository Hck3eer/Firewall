#!/usr/bin/env python3
"""
iptables Management Utilities
"""
import subprocess
import re
import json
from typing import List, Dict, Optional

class IPTablesManager:
    def __init__(self):
        self.chains = ['INPUT', 'OUTPUT', 'FORWARD']
        self.custom_chain = 'VM_FIREWALL'
    
    def execute(self, command: List[str]) -> Dict:
        """Execute iptables command"""
        try:
            result = subprocess.run(
                ['iptables'] + command,
                capture_output=True,
                text=True,
                timeout=5
            )
            
            return {
                'success': result.returncode == 0,
                'stdout': result.stdout,
                'stderr': result.stderr
            }
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Timeout'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def block_ip(self, ip: str, chain: str = 'INPUT') -> bool:
        """Block IP in specified chain"""
        commands = [
            ['-A', chain, '-s', ip, '-j', 'DROP'],
            ['-A', 'FORWARD', '-s', ip, '-j', 'DROP'],
            ['-A', 'OUTPUT', '-d', ip, '-j', 'DROP']
        ]
        
        success = True
        for cmd in commands:
            result = self.execute(cmd)
            if not result['success']:
                success = False
        
        return success
    
    def unblock_ip(self, ip: str) -> bool:
        """Remove IP blocks"""
        success = True
        
        # Try to remove from all chains
        for chain in self.chains:
            # Count how many rules for this IP
            list_cmd = ['-L', chain, '-n', '--line-numbers']
            result = self.execute(list_cmd)
            
            if result['success']:
                lines = result['stdout'].split('\n')
                for line in lines:
                    if ip in line and ('DROP' in line or 'REJECT' in line):
                        # Extract rule number
                        match = re.match(r'^(\d+)', line.strip())
                        if match:
                            rule_num = match.group(1)
                            # Delete the rule
                            del_result = self.execute(['-D', chain, rule_num])
                            if not del_result['success']:
                                success = False
        
        return success
    
    def create_custom_chain(self, chain_name: str) -> bool:
        """Create custom iptables chain"""
        # Check if chain exists
        result = self.execute(['-L', chain_name, '-n'])
        
        if 'No chain/target/match' in result.get('stderr', ''):
            # Create chain
            result = self.execute(['-N', chain_name])
            return result['success']
        
        return True
    
    def add_to_custom_chain(self, ip: str, chain_name: str) -> bool:
        """Add rule to custom chain"""
        cmd = ['-A', chain_name, '-s', ip, '-j', 'DROP']
        result = self.execute(cmd)
        return result['success']
    
    def list_rules(self, chain: Optional[str] = None) -> List[Dict]:
        """List iptables rules"""
        cmd = ['-L', '-n', '-v'] + ([chain] if chain else [])
        result = self.execute(cmd)
        
        rules = []
        if result['success']:
            lines = result['stdout'].split('\n')
            current_chain = None
            
            for line in lines:
                # Check for chain header
                chain_match = re.match(r'^Chain (\w+)', line)
                if chain_match:
                    current_chain = chain_match.group(1)
                    continue
                
                # Parse rule line
                rule_match = re.match(r'^\s*(\d+)\s+(\d+)\s+(\w+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)', line)
                if rule_match and current_chain:
                    rules.append({
                        'chain': current_chain,
                        'num': rule_match.group(1),
                        'pkts': rule_match.group(2),
                        'bytes': rule_match.group(3),
                        'target': rule_match.group(4),
                        'prot': rule_match.group(5),
                        'opt': rule_match.group(6),
                        'in': rule_match.group(7),
                        'out': rule_match.group(8),
                        'source': rule_match.group(9).split()[0] if rule_match.group(9) else '',
                        'destination': rule_match.group(9).split()[2] if len(rule_match.group(9).split()) > 2 else '',
                        'options': ' '.join(rule_match.group(9).split()[3:]) if len(rule_match.group(9).split()) > 3 else ''
                    })
        
        return rules
    
    def get_statistics(self) -> Dict:
        """Get firewall statistics"""
        stats = {
            'total_rules': 0,
            'block_rules': 0,
            'chains': {}
        }
        
        for chain in self.chains + [self.custom_chain]:
            rules = self.list_rules(chain)
            stats['chains'][chain] = len(rules)
            stats['total_rules'] += len(rules)
            
            # Count block rules
            for rule in rules:
                if rule['target'] in ['DROP', 'REJECT']:
                    stats['block_rules'] += 1
        
        return stats
    
    def save_rules(self, filename: str = 'iptables_backup.rules') -> bool:
        """Save iptables rules to file"""
        result = self.execute(['-S'])
        if result['success']:
            with open(filename, 'w') as f:
                f.write(result['stdout'])
            return True
        return False
    
    def restore_rules(self, filename: str) -> bool:
        """Restore iptables rules from file"""
        try:
            with open(filename, 'r') as f:
                rules = f.readlines()
            
            # Flush existing rules first
            self.execute(['-F'])
            
            for rule in rules:
                rule = rule.strip()
                if rule and not rule.startswith('#'):
                    parts = rule.split()
                    result = self.execute(parts)
                    if not result['success']:
                        return False
            
            return True
            
        except Exception as e:
            print(f"Error restoring rules: {e}")
            return False
    
    def is_blocked(self, ip: str) -> bool:
        """Check if IP is blocked"""
        for chain in self.chains + [self.custom_chain]:
            rules = self.list_rules(chain)
            for rule in rules:
                if rule['source'] == ip and rule['target'] in ['DROP', 'REJECT']:
                    return True
        return False