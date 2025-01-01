
import unittest
from packet_pirate import ip_to_int, analyze_packets

class TestPacketPirate(unittest.TestCase):
    def test_ip_to_int(self):
        self.assertEqual(ip_to_int('192.168.1.1'), 3232235777)
        
    def test_analyze_packets_empty(self):
        self.assertIsNone(analyze_packets(None))

if __name__ == '__main__':
    unittest.main()
