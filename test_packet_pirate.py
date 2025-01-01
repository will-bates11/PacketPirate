
import unittest
from packet_pirate import ip_to_int, analyze_packets, network_behavior_analysis
import pandas as pd
import numpy as np

class TestPacketPirate(unittest.TestCase):
    def test_ip_to_int(self):
        self.assertEqual(ip_to_int('192.168.1.1'), 3232235777)
    
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
        
    def test_packet_stats(self):
        df = pd.DataFrame({'protocol': [6, 17, 1], 'length': [64, 128, 256]})
        stats = df.describe()
        self.assertGreater(stats['length']['mean'], 0)

if __name__ == '__main__':
    unittest.main()
