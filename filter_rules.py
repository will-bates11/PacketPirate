
import json
import os

class FilterRules:
    def __init__(self):
        self.rules = {
            'http': 'tcp port 80',
            'https': 'tcp port 443',
            'dns': 'udp port 53',
            'ssh': 'tcp port 22',
            'ftp': 'tcp port (20 or 21)',
            'smtp': 'tcp port 25',
            'telnet': 'tcp port 23',
            'rdp': 'tcp port 3389',
            'icmp': 'icmp',
            'high_ports': 'portrange 1024-65535',
            'dhcp': 'udp port (67 or 68)',
            'ntp': 'udp port 123',
            'mysql': 'tcp port 3306',
            'postgres': 'tcp port 5432',
            'mongodb': 'tcp port 27017',
            'redis': 'tcp port 6379',
            'ldap': 'tcp port 389',
            'smb': 'tcp port 445',
            'all_tcp': 'tcp',
            'all_udp': 'udp',
            'broadcast': 'ether broadcast',
            'multicast': 'ether multicast',
            'large_packets': 'greater 1500',
            'small_packets': 'less 64'
        }
        self.load_custom_rules()
    
    def add_rule(self, name, filter_str):
        """Add or update a filter rule"""
        if not name or not filter_str:
            raise ValueError("Name and filter string cannot be empty")
        if not self._validate_filter(filter_str):
            raise ValueError("Invalid filter syntax")
        self.rules[name] = filter_str
        self.save_custom_rules()
        
    def _validate_filter(self, filter_str):
        """Validate BPF filter syntax"""
        try:
            from scapy.all import conf
            conf.L3socket(filter=filter_str)
            return True
        except Exception:
            return False
        
    def get_rule(self, name):
        """Get a filter rule by name"""
        return self.rules.get(name)
        
    def list_rules(self):
        """List all available rules"""
        return list(self.rules.keys())
        
    def delete_rule(self, name):
        """Delete a custom rule"""
        if name in self.rules and name not in self._get_default_rules():
            del self.rules[name]
            self.save_custom_rules()
            return True
        return False
    
    def _get_default_rules(self):
        """Get list of default rules that cannot be deleted"""
        return ['http', 'https', 'dns', 'ssh', 'ftp', 'smtp', 'telnet', 'rdp', 'icmp', 'high_ports']
    
    def save_custom_rules(self):
        """Save custom rules to file"""
        custom_rules = {k: v for k, v in self.rules.items() 
                       if k not in self._get_default_rules()}
        with open('custom_filters.json', 'w') as f:
            json.dump(custom_rules, f)
    
    def load_custom_rules(self):
        """Load custom rules from file"""
        try:
            if os.path.exists('custom_filters.json'):
                with open('custom_filters.json', 'r') as f:
                    custom_rules = json.load(f)
                    self.rules.update(custom_rules)
        except Exception as e:
            print(f"Error loading custom rules: {e}")
