
# PacketPirate API Documentation

## REST Endpoints

### Packet Capture
- `POST /api/capture`
  - Requires authentication token
  - Request body:
    ```json
    {
      "interface": "eth0",
      "count": 100,
      "filter": "tcp port 80"
    }
    ```
  - Response: DataFrame in JSON format

### Network Analysis
- `POST /api/analyze`
  - Requires authentication token
  - Request body: DataFrame in JSON format
  - Response: Analysis results with clustering and anomalies

### Statistics
- `GET /api/stats`
  - Requires authentication token
  - Response:
    ```json
    {
      "timestamps": [...],
      "packet_counts": [...],
      "protocol_counts": {
        "labels": [...],
        "values": [...]
      },
      "packet_sizes": [...]
    }
    ```

## Functions

### capture_packets(interface='eth0', count=100, filter_str=None)
Captures network packets using specified parameters.

### analyze_packets(packets)
Analyzes captured packets and returns a DataFrame with statistics.

### network_behavior_analysis(df)
Performs network behavior analysis using KMeans clustering.

### plot_statistics(df)
Generates visualizations of packet statistics.
