
class FilterRules:
    def __init__(self):
        self.rules = {
            'http': 'tcp port 80',
            'https': 'tcp port 443',
            'dns': 'udp port 53',
            'ssh': 'tcp port 22'
        }
    
    def add_rule(self, name, filter_str):
        self.rules[name] = filter_str
        
    def get_rule(self, name):
        return self.rules.get(name)
        
    def list_rules(self):
        return list(self.rules.keys())
