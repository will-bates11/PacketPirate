
import unittest
from packet_pirate import ip_to_int, analyze_packets, network_behavior_analysis, capture_packets
import pandas as pd
import numpy as np
from unittest.mock import patch, MagicMock

class TestPacketPirate(unittest.TestCase):
    def test_ip_to_int(self):
        self.assertEqual(ip_to_int('192.168.1.1'), 3232235777)
        self.assertEqual(ip_to_int('127.0.0.1'), 2130706433)
    
    def test_network_behavior_analysis(self):
        df = pd.DataFrame({
            'src': [1, 2, 3],
            'dst': [4, 5, 6],
            'protocol': [6, 17, 1],
            'length': [64, 128, 256],
            'ttl': [64, 128, 255]
        })
        result = network_behavior_analysis(df)
        self.assertIn('cluster', result.columns)
        self.assertIn('anomaly_score', result.columns)
        self.assertIn('is_anomaly', result.columns)
        
    def test_packet_stats(self):
        df = pd.DataFrame({'protocol': [6, 17, 1], 'length': [64, 128, 256]})
        stats = df.describe()
        self.assertGreater(stats['length']['mean'], 0)
        self.assertEqual(len(df), 3)
        
    @patch('scapy.all.sniff')
    def test_capture_packets(self, mock_sniff):
        mock_sniff.return_value = []
        packets = capture_packets(interface='eth0', count=10)
        mock_sniff.assert_called_once_with(iface='eth0', count=10, timeout=10, filter=None)
        
    def test_analyze_packets_empty(self):
        result = analyze_packets(None)
        self.assertIsNone(result)
        
    def test_analyze_packets_invalid_data(self):
        result = analyze_packets([])
        self.assertIsNone(result)

if __name__ == '__main__':
    unittest.main()
