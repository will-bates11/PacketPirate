
import threading
import time
import requests

class Monitor:
    def __init__(self, threshold=1000):
        self.packet_count = 0
        self.threshold = threshold
        self.alerts = []
        
    def start_monitoring(self):
        threading.Thread(target=self._monitor_loop).start()
        
    def _monitor_loop(self):
        while True:
            if self.packet_count > self.threshold:
                self.alerts.append({
                    'timestamp': time.time(),
                    'message': f'High traffic detected: {self.packet_count} packets'
                })
            time.sleep(60)
            
    def add_packet(self):
        self.packet_count += 1
