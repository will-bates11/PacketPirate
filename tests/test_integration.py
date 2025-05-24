
import unittest
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pandas as pd
from packet_pirate import capture_packets, analyze_packets, network_behavior_analysis
from monitoring import Monitor
from elastic_logger import PacketLogger

class TestIntegration(unittest.TestCase):
    def setUp(self):
        self.monitor = Monitor(threshold=100)
        self.logger = PacketLogger()
        
    def test_capture_to_analysis_flow(self):
        # Capture packets
        packets = capture_packets(count=5)
        self.assertIsNotNone(packets)
        
        # Analyze packets
        df = analyze_packets(packets)
        self.assertIsInstance(df, pd.DataFrame)
        
        # Perform behavior analysis
        result = network_behavior_analysis(df)
        self.assertIn('cluster', result.columns)
        
        # Test monitoring integration
        self.monitor.add_packet()
        alerts = self.monitor.check_rules()
        self.assertIsInstance(alerts, list)
        
    def test_logging_integration(self):
        packets = capture_packets(count=1)
        df = analyze_packets(packets)
        if df is not None and not df.empty:
            packet_data = df.iloc[0].to_dict()
            self.logger.log_packet(packet_data)

if __name__ == '__main__':
    unittest.main()
