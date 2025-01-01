
# PacketPirate Developer Documentation

## Project Structure
```
├── packet_pirate.py     # Core packet capture and analysis
├── monitoring.py        # Network monitoring and alerts
├── auth.py             # Authentication and security
├── config.py           # Configuration management
├── elastic_logger.py   # Elasticsearch logging
├── filter_rules.py     # BPF filter management
└── tests/              # Test suite
```

## Core Components

### Packet Capture (packet_pirate.py)
- `capture_packets()`: Captures network packets using Scapy
- `analyze_packets()`: Processes captured packets into DataFrame
- `network_behavior_analysis()`: Performs clustering and anomaly detection
- `enhanced_visualization()`: Creates network visualizations

### Monitoring System (monitoring.py)
- `Monitor`: Main monitoring class
- `AlertRule`: Alert configuration class
- Supports email and webhook notifications
- System health monitoring

### Authentication (auth.py)
- JWT-based authentication
- Rate limiting
- CSRF protection
- Input sanitization

## Development Setup

1. Clone the repository on Replit
2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure environment variables in config.py
4. Run tests:
```bash
python -m pytest
```

## API Reference
See [API.md](API.md) for REST endpoint documentation

## Testing
- Unit tests: test_packet_pirate.py
- Integration tests: tests/test_integration.py
- Benchmarks: benchmarks/benchmark.py

## Contributing
See [CONTRIBUTING.md](../CONTRIBUTING.md)
