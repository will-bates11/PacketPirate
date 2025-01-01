import scapy.all as scapy
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
import networkx as nx
import socket
import struct
import collections

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
                record = {'timestamp': pkt.time,
                          'src': ip_to_int(pkt[scapy.IP].src),
                          'dst': ip_to_int(pkt[scapy.IP].dst),
                          'protocol': pkt[scapy.IP].proto}
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

def enhanced_visualization(df):
    """Create an enhanced network graph visualization."""
    try:
        G = nx.from_pandas_edgelist(df, 'src', 'dst', create_using=nx.DiGraph())
        pos = nx.spring_layout(G)
        colors = ['red' if node in df[df['cluster'] == 0]['src'].values else 'blue' for node in G.nodes()]
        nx.draw(G, pos, with_labels=True, node_color=colors, edge_color='gray', alpha=0.7, linewidths=1, node_size=500)
        plt.show()
    except Exception as e:
        print(f"Error in data visualization: {e}")

def main():
    """Main function to orchestrate packet capture and analysis."""
    packets = capture_packets()
    if packets:
        df = analyze_packets(packets)
        if df is not None and not df.empty:
            df = network_behavior_analysis(df)
            enhanced_visualization(df)
        else:
            print("No data to analyze.")
    else:
        print("Packet capture failed.")

if __name__ == "__main__":
    main()