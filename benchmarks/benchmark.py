
import time
import sys
sys.path.append('..')
from packet_pirate import capture_packets, analyze_packets

def benchmark_capture():
    """Benchmark packet capture performance."""
    start_time = time.time()
    packets = capture_packets(count=1000)
    end_time = time.time()
    return end_time - start_time

def main():
    capture_time = benchmark_capture()
    print(f"Packet Capture Time (1000 packets): {capture_time:.2f} seconds")

if __name__ == "__main__":
    main()
