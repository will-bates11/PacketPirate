
import unittest
from monitoring import Monitor, AlertRule
from unittest.mock import patch, MagicMock

class TestMonitoring(unittest.TestCase):
    def setUp(self):
        self.monitor = Monitor(threshold=100)
        
    def test_add_alert_rule(self):
        self.monitor.add_alert_rule("test_rule", "greater_than", 50)
        self.assertEqual(len(self.monitor.alert_rules), 1)
        self.assertEqual(self.monitor.alert_rules[0].name, "test_rule")
        
    def test_check_rules(self):
        self.monitor.add_alert_rule("high_traffic", "greater_than", 50)
        self.monitor.packet_count = 51
        alerts = self.monitor.check_rules()
        self.assertEqual(len(alerts), 1)
        
    @patch('smtplib.SMTP')
    def test_send_email_alert(self, mock_smtp):
        self.monitor.configure_email('smtp.test.com', 587, 'test@test.com', 
                                   'password', 'recipient@test.com')
        self.monitor.send_email_alert("Test alert")
        mock_smtp.return_value.__enter__.return_value.send_message.assert_called_once()
        
    @patch('requests.post')
    def test_send_webhook_alert(self, mock_post):
        self.monitor.add_webhook("http://test.com/webhook")
        self.monitor.send_webhook_alert("Test alert")
        mock_post.assert_called_once()

if __name__ == '__main__':
    unittest.main()
