import scapy.all as scapy
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
import networkx as nx
import socket
import struct
import collections
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def ip_to_int(ip):
    """Convert an IP string to a long integer."""
    return struct.unpack("!I", socket.inet_aton(ip))[0]

def capture_packets(interface='eth0', count=100, filter_str=None):
    """Capture network packets using Scapy with optional filtering."""
    try:
        packets = scapy.sniff(iface=interface, count=count, timeout=10, 
                            filter=filter_str)
        return packets
    except Exception as e:
        print(f"Error capturing packets: {e}")
        return None

def analyze_packets(packets):
    """Analyze captured packets and create a DataFrame with statistics."""
    packet_stats = {'total_packets': 0, 'protocols': collections.Counter()}
    records = []
    if packets is not None:
        for pkt in packets:
            if scapy.IP in pkt:
                payload_len = len(pkt[scapy.IP].payload) if pkt.haslayer(scapy.IP) else 0
                record = {'timestamp': pkt.time,
                          'src': ip_to_int(pkt[scapy.IP].src),
                          'dst': ip_to_int(pkt[scapy.IP].dst),
                          'protocol': pkt[scapy.IP].proto,
                          'length': payload_len,
                          'ttl': pkt[scapy.IP].ttl}
                records.append(record)
    return pd.DataFrame(records) if records else None

def network_behavior_analysis(df):
    """Perform network behavior analysis using KMeans clustering."""
    try:
        scaler = StandardScaler()
        df_scaled = scaler.fit_transform(df[['src', 'dst']])
        kmeans = KMeans(n_clusters=2)
        df['cluster'] = kmeans.fit_predict(df_scaled)
        return df
    except Exception as e:
        print(f"Error in network behavior analysis: {e}")
        return df

def plot_statistics(df):
    """Plot packet statistics."""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
    df['protocol'].value_counts().plot(kind='bar', ax=ax1, title='Protocol Distribution')
    df['length'].hist(ax=ax2, bins=50, title='Packet Size Distribution')
    plt.tight_layout()
    plt.show()

def enhanced_visualization(df):
    """Create an enhanced network graph visualization."""
    plot_statistics(df)
    try:
        G = nx.from_pandas_edgelist(df, 'src', 'dst', create_using=nx.DiGraph())
        pos = nx.spring_layout(G)
        colors = ['red' if node in df[df['cluster'] == 0]['src'].values else 'blue' for node in G.nodes()]
        nx.draw(G, pos, with_labels=True, node_color=colors, edge_color='gray', alpha=0.7, linewidths=1, node_size=500)
        plt.show()
    except Exception as e:
        print(f"Error in data visualization: {e}")

def validate_interface(interface):
    """Validate if interface exists."""
    try:
        interfaces = scapy.get_if_list()
        if interface not in interfaces:
            raise ValueError(f"Interface {interface} not found. Available interfaces: {interfaces}")
        return True
    except Exception as e:
        logger.error(f"Interface validation failed: {e}")
        return False

def main():
    """Main function to orchestrate packet capture and analysis."""
    import argparse
    parser = argparse.ArgumentParser(description='PacketPirate: Network Packet Analyzer')
    parser.add_argument('-i', '--interface', default='eth0', help='Network interface to capture')
    parser.add_argument('-c', '--count', type=int, default=100, help='Number of packets to capture')
    parser.add_argument('-f', '--filter', help='BPF filter string')
    parser.add_argument('-o', '--output', help='Save results to file')
    parser.add_argument('--format', choices=['csv', 'json', 'pcap'], default='csv',
                       help='Output format (default: csv)')
    args = parser.parse_args()
    
    packets = capture_packets(interface=args.interface, count=args.count, filter_str=args.filter)
    if packets:
        df = analyze_packets(packets)
        if df is not None and not df.empty:
            df = network_behavior_analysis(df)
            enhanced_visualization(df)
            if args.output:
                df.to_csv(args.output, index=False)
                print(f"Results saved to {args.output}")
        else:
            print("No data to analyze.")
    else:
        print("Packet capture failed.")

if __name__ == "__main__":
    main()