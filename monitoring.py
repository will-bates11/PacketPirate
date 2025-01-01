
import threading
import time
import requests
import smtplib
from email.mime.text import MIMEText
import json
from typing import Dict, List

class AlertRule:
    """A rule for triggering alerts based on packet count conditions.
    
    Attributes:
        name (str): Name of the alert rule
        condition (str): Type of condition ('greater_than', 'less_than', 'equals')
        threshold (int): Threshold value for triggering the alert
    """
    def __init__(self, name: str, condition: str, threshold: int):
        self.name = name
        self.condition = condition
        self.threshold = threshold

class Monitor:
    """Network traffic monitor that triggers alerts based on packet counts.
    
    Attributes:
        packet_count (int): Current count of packets
        threshold (int): Default threshold for alerting
        alerts (list): History of triggered alerts
        alert_rules (list): List of custom alert rules
        webhook_urls (list): URLs for webhook notifications
        email_config (dict): Email notification settings
    """
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
        """Add a custom alert rule.
        
        Args:
            name: Name of the rule
            condition: Type of condition ('greater_than', 'less_than', 'equals')
            threshold: Value to trigger the alert
        """
        self.alert_rules.append(AlertRule(name, condition, threshold))
        
    def add_webhook(self, url: str):
        """Add a webhook URL for notifications.
        
        Args:
            url: Webhook endpoint URL
        """
        self.webhook_urls.append(url)
        
    def configure_email(self, smtp_server: str, smtp_port: int, sender: str, 
                       password: str, recipient: str):
        """Configure email notification settings.
        
        Args:
            smtp_server: SMTP server address
            smtp_port: SMTP server port
            sender: Sender email address
            password: Sender email password
            recipient: Recipient email address
        """
        self.email_config.update({
            'smtp_server': smtp_server,
            'smtp_port': smtp_port,
            'sender_email': sender,
            'sender_password': password,
            'recipient_email': recipient
        })
        
    def send_email_alert(self, message: str):
        """Send email notification.
        
        Args:
            message: Alert message to send
        """
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
        """Send webhook notification.
        
        Args:
            message: Alert message to send
        """
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
        """Check all alert rules and return triggered alerts.
        
        Returns:
            List of triggered alert messages
        """
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
        """Main monitoring loop that checks thresholds and sends alerts."""
        while True:
            if self.packet_count > self.threshold:
                message = f'High traffic detected: {self.packet_count} packets'
                self.alerts.append({
                    'timestamp': time.time(),
                    'message': message
                })
                self.send_email_alert(message)
                self.send_webhook_alert(message)
            
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
