
# PacketPirate API Documentation

## Functions

### capture_packets(interface='eth0', count=100, filter_str=None)
Captures network packets using specified parameters.

### analyze_packets(packets)
Analyzes captured packets and returns a DataFrame with statistics.

### network_behavior_analysis(df)
Performs network behavior analysis using KMeans clustering.

### plot_statistics(df)
Generates visualizations of packet statistics.

## Usage Examples
```python
# Capture and analyze packets
packets = capture_packets(interface='eth0', count=100)
df = analyze_packets(packets)

# Analyze network behavior
df = network_behavior_analysis(df)

# Visualize results
plot_statistics(df)
```
