
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
            'dst': [4, 5, 6]
        })
        result = network_behavior_analysis(df)
        self.assertIn('cluster', result.columns)

if __name__ == '__main__':
    unittest.main()
