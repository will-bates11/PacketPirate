
import threading
import time
import requests
import smtplib
from email.mime.text import MIMEText
import json
from typing import Dict, List

class AlertRule:
    def __init__(self, name: str, condition: str, threshold: int):
        self.name = name
        self.condition = condition  # 'greater_than', 'less_than', 'equals'
        self.threshold = threshold

class Monitor:
    def __init__(self, threshold=1000):
        self.packet_count = 0
        self.threshold = threshold
        self.alerts = []
        self.alert_rules = []
        self.webhook_urls = []
        self.email_config = {
            'smtp_server': 'smtp.gmail.com',
            'smtp_port': 587,
            'sender_email': '',
            'sender_password': '',
            'recipient_email': ''
        }
        
    def add_alert_rule(self, name: str, condition: str, threshold: int):
        """Add a custom alert rule."""
        self.alert_rules.append(AlertRule(name, condition, threshold))
        
    def add_webhook(self, url: str):
        """Add a webhook URL for notifications."""
        self.webhook_urls.append(url)
        
    def configure_email(self, smtp_server: str, smtp_port: int, sender: str, 
                       password: str, recipient: str):
        """Configure email settings."""
        self.email_config.update({
            'smtp_server': smtp_server,
            'smtp_port': smtp_port,
            'sender_email': sender,
            'sender_password': password,
            'recipient_email': recipient
        })
        
    def send_email_alert(self, message: str):
        """Send email notification."""
        if not all(self.email_config.values()):
            return
            
        msg = MIMEText(message)
        msg['Subject'] = 'PacketPirate Alert'
        msg['From'] = self.email_config['sender_email']
        msg['To'] = self.email_config['recipient_email']
        
        try:
            with smtplib.SMTP(self.email_config['smtp_server'], 
                             self.email_config['smtp_port']) as server:
                server.starttls()
                server.login(self.email_config['sender_email'], 
                           self.email_config['sender_password'])
                server.send_message(msg)
        except Exception as e:
            print(f"Failed to send email: {e}")
            
    def send_webhook_alert(self, message: str):
        """Send webhook notification."""
        payload = {
            'text': message,
            'timestamp': time.time()
        }
        
        for url in self.webhook_urls:
            try:
                requests.post(url, json=payload)
            except Exception as e:
                print(f"Failed to send webhook to {url}: {e}")
                
    def check_rules(self) -> List[str]:
        """Check all alert rules and return triggered alerts."""
        triggered = []
        for rule in self.alert_rules:
            if (rule.condition == 'greater_than' and self.packet_count > rule.threshold) or \
               (rule.condition == 'less_than' and self.packet_count < rule.threshold) or \
               (rule.condition == 'equals' and self.packet_count == rule.threshold):
                triggered.append(f"Alert '{rule.name}': Packet count {self.packet_count}")
        return triggered
        
    def start_monitoring(self):
        """Start the monitoring thread."""
        threading.Thread(target=self._monitor_loop).start()
        
    def _monitor_loop(self):
        """Main monitoring loop."""
        while True:
            # Check default threshold
            if self.packet_count > self.threshold:
                message = f'High traffic detected: {self.packet_count} packets'
                self.alerts.append({
                    'timestamp': time.time(),
                    'message': message
                })
                self.send_email_alert(message)
                self.send_webhook_alert(message)
            
            # Check custom rules
            triggered_alerts = self.check_rules()
            for alert in triggered_alerts:
                self.alerts.append({
                    'timestamp': time.time(),
                    'message': alert
                })
                self.send_email_alert(alert)
                self.send_webhook_alert(alert)
                
            time.sleep(60)
            
    def add_packet(self):
        """Increment packet count."""
        self.packet_count += 1
