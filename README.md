
# PacketPirate 🏴‍☠️

A Python-based network packet analyzer for capturing, analyzing, and visualizing network traffic patterns.

## Features
- Real-time packet capture and analysis
- Network behavior clustering using K-means
- Interactive network visualization
- BPF filter support
- Customizable packet count and interface selection

## Installation
```bash
pip install -r requirements.txt
```

## Usage
```bash
python packet_pirate.py -i eth0 -c 100 -f "tcp port 80"
```

### Arguments
- `-i, --interface`: Network interface (default: eth0)
- `-c, --count`: Number of packets to capture (default: 100)
- `-f, --filter`: BPF filter string
- `-o, --output`: Save results to file

## Contributing
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## License
MIT License
