
# PacketPirate 🏴‍☠️

A Python-based network packet analyzer for capturing, analyzing, and visualizing network traffic patterns.

## Features
- Real-time packet capture and analysis
- Network behavior clustering using K-means
- Interactive network visualization
- BPF filter support
- Customizable packet count and interface selection
- Email and webhook alerts
- REST API

## Installation

1. Clone the repository
2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure alerts (optional):
   - Create a `.env` file with email settings
   - Add webhook URLs in the configuration

4. Start the application:
```bash
python packet_pirate.py -i eth0 -c 100 -f "tcp port 80"
```

## Web Interface

Access the dashboard at `http://0.0.0.0:8080` to view:
- Real-time traffic statistics
- Protocol distribution
- Packet size analysis
- Anomaly detection results
- Alert history

### Arguments
- `-i, --interface`: Network interface (default: eth0)
- `-c, --count`: Number of packets to capture (default: 100)
- `-f, --filter`: BPF filter string
- `-o, --output`: Save results to file

## API Usage
See [API Documentation](docs/API.md) for REST endpoints and examples.

## Contributing
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## License
MIT License
