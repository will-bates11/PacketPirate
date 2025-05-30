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
import os
import time
import argparse
from flask import Flask, request, jsonify, render_template
from functools import wraps

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default-secret-key')

# Global variables
packet_history = []

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
    """Analyze captured packets and store historical data."""
    global packet_history
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
    df = pd.DataFrame(records) if records else None
    if df is not None and not df.empty:
        df.to_csv('packet_history.csv', mode='a', header=not os.path.exists('packet_history.csv'), index=False)
    return df

def network_behavior_analysis(df):
    """Perform network behavior analysis using KMeans clustering and anomaly detection."""
    try:
        # Scale features
        scaler = StandardScaler()
        features = ['src', 'dst', 'length', 'ttl']
        df_scaled = scaler.fit_transform(df[features])
        
        # Clustering for behavior analysis
        kmeans = KMeans(n_clusters=3)
        df['cluster'] = kmeans.fit_predict(df_scaled)
        
        # Anomaly detection using cluster distances
        distances = kmeans.transform(df_scaled)
        df['anomaly_score'] = distances.min(axis=1)
        df['is_anomaly'] = df['anomaly_score'] > df['anomaly_score'].quantile(0.95)
        
        # Traffic pattern prediction (time series forecasting)
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            df.set_index('timestamp', inplace=True)
            df['packet_count'] = 1
            traffic_pattern = df.resample('1min').count()['packet_count']
            
            # Simple moving average prediction
            window_size = 5
            traffic_pattern['predicted_next'] = traffic_pattern.rolling(window=window_size).mean().shift(-1)
            df['predicted_traffic'] = df.index.map(traffic_pattern['predicted_next'])
        
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
    """Create an enhanced network graph visualization with anomalies and predictions."""
    try:
        fig = plt.figure(figsize=(15, 10))
        
        # Traffic patterns and anomalies
        ax1 = plt.subplot(221)
        df.reset_index()['timestamp'].hist(bins=50, ax=ax1)
        ax1.set_title('Traffic Distribution')
        
        # Protocol distribution
        ax2 = plt.subplot(222)
        df['protocol'].value_counts().plot(kind='bar', ax=ax2)
        ax2.set_title('Protocol Distribution')
        
        # Network graph with anomalies
        ax3 = plt.subplot(223)
        G = nx.from_pandas_edgelist(df, 'src', 'dst', create_using=nx.DiGraph())
        pos = nx.spring_layout(G)
        colors = ['red' if node in df[df['is_anomaly']]['src'].values else 'blue' for node in G.nodes()]
        nx.draw(G, pos, with_labels=True, node_color=colors, edge_color='gray', alpha=0.7, linewidths=1, node_size=500, ax=ax3)
        ax3.set_title('Network Graph (Red: Anomalies)')
        
        # Traffic prediction
        if 'predicted_traffic' in df.columns:
            ax4 = plt.subplot(224)
            df['packet_count'].plot(ax=ax4, label='Actual')
            df['predicted_traffic'].plot(ax=ax4, label='Predicted', style='--')
            ax4.set_title('Traffic Pattern Prediction')
            ax4.legend()
        
        plt.tight_layout()
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

# Import additional modules
try:
    from filter_rules import FilterRules
    from auth import token_required, init_auth, sanitize_input, validate_input, limiter
    from monitoring import Monitor
    # Initialize auth components
    init_auth(app)
except ImportError as e:
    logger.warning(f"Some modules not available: {e}")
    # Define a dummy token_required decorator if auth module is not available
    def token_required(f):
        @wraps(f)
        def decorator(*args, **kwargs):
            return f(*args, **kwargs)
        return decorator
    limiter = None

def main():
    """Main function to orchestrate packet capture and analysis."""
    try:
        filter_rules = FilterRules()
    except:
        logger.warning("FilterRules not available, using basic functionality")
        filter_rules = None
    
    parser = argparse.ArgumentParser(description='PacketPirate: Network Packet Analyzer')
    parser.add_argument('-i', '--interface', default='eth0', help='Network interface to capture')
    parser.add_argument('-c', '--count', type=int, default=100, help='Number of packets to capture')
    parser.add_argument('-f', '--filter', help='BPF filter string or preset name')
    parser.add_argument('--add-filter', nargs=2, metavar=('NAME', 'FILTER'), help='Add custom filter')
    parser.add_argument('--list-filters', action='store_true', help='List available filters')
    parser.add_argument('--delete-filter', metavar='NAME', help='Delete custom filter')
    parser.add_argument('-o', '--output', help='Save results to file')
    parser.add_argument('--format', choices=['csv', 'json', 'pcap'], default='csv',
                       help='Output format (default: csv)')
    args = parser.parse_args()
    
    if args.list_filters and filter_rules:
        print("Available filters:", ", ".join(filter_rules.list_rules()))
        return
        
    if args.add_filter and filter_rules:
        name, filter_str = args.add_filter
        filter_rules.add_rule(name, filter_str)
        print(f"Added filter '{name}': {filter_str}")
        return
        
    if args.delete_filter and filter_rules:
        if filter_rules.delete_rule(args.delete_filter):
            print(f"Deleted filter '{args.delete_filter}'")
        else:
            print(f"Cannot delete filter '{args.delete_filter}'")
        return
        
    filter_str = args.filter
    if filter_rules and args.filter and args.filter in filter_rules.rules:
        filter_str = filter_rules.get_rule(args.filter)
        
    packets = capture_packets(interface=args.interface, count=args.count, filter_str=filter_str)
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

@app.route('/api/capture', methods=['POST'])
@token_required
def api_capture():
    try:
        data = request.get_json() or {}
        packets = capture_packets(
            interface=data.get('interface', 'eth0'),
            count=data.get('count', 100),
            filter_str=data.get('filter')
        )
        df = analyze_packets(packets)
        if df is not None:
            return jsonify(df.to_dict())
        else:
            return jsonify({'error': 'No packets captured'}), 400
    except Exception as e:
        logger.error(f"Error in API capture: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/analyze', methods=['POST'])
@token_required
def api_analyze():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        df = pd.DataFrame(data)
        result = network_behavior_analysis(df)
        return jsonify(result.to_dict())
    except Exception as e:
        logger.error(f"Error in API analyze: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/health')
def health_check():
    """Basic health check endpoint."""
    return jsonify({'status': 'healthy', 'timestamp': time.time()})

@app.route('/health/detailed')
@token_required
def detailed_health():
    """Detailed health check with system metrics."""
    try:
        monitor = Monitor()
        metrics = monitor.get_system_metrics()
        alerts = monitor.check_system_health()
        
        return jsonify({
            'status': 'healthy' if not alerts else 'warning',
            'timestamp': time.time(),
            'metrics': metrics,
            'alerts': alerts
        })
    except Exception as e:
        logger.warning(f"Monitor not available: {e}")
        return jsonify({
            'status': 'healthy',
            'timestamp': time.time(),
            'message': 'Basic health check - monitoring unavailable'
        })

@app.route('/api/stats')
@token_required
def get_stats():
    df = pd.read_csv('packet_history.csv') if os.path.exists('packet_history.csv') else pd.DataFrame()
    
    stats = {
        'timestamps': df['timestamp'].tolist() if not df.empty else [],
        'packet_counts': df.groupby('timestamp').size().tolist() if not df.empty else [],
        'protocol_counts': {
            'labels': df['protocol'].value_counts().index.tolist() if not df.empty else [],
            'values': df['protocol'].value_counts().tolist() if not df.empty else []
        },
        'packet_sizes': df['length'].tolist() if not df.empty else []
    }
    return jsonify(stats)

@app.route('/api/login', methods=['POST'])
def login():
    """User login endpoint."""
    try:
        import jwt
        import datetime
        data = sanitize_input(request.get_json()) if 'sanitize_input' in globals() else request.get_json()
        if not data or 'username' not in data or 'password' not in data:
            return jsonify({'message': 'Invalid credentials'}), 400
        
        # Here you would verify against your user database
        # This is a placeholder for demonstration
        if data['username'] == 'admin' and data['password'] == 'secure_password':
            session_id = str(datetime.datetime.now().timestamp())
            session['session_id'] = session_id
            token = jwt.encode({
                'user': data['username'],
                'session_id': session_id,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }, app.config['SECRET_KEY'])
            return jsonify({'token': token})
        return jsonify({'message': 'Invalid credentials'}), 401
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'message': 'Login failed'}), 500

@app.route('/api/logout', methods=['POST'])
@token_required
def logout():
    """User logout endpoint."""
    session.clear()
    return jsonify({'message': 'Logged out successfully'})

# Health check endpoint already defined above

def start_web_server():
    """Start the Flask web server."""
    app.run(host='0.0.0.0', port=8080, debug=False)

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == '--web':
        print("Starting web server...")
        start_web_server()
    else:
        main()