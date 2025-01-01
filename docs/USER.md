
# PacketPirate User Guide

## Overview
PacketPirate is a network packet analyzer for capturing, analyzing, and visualizing network traffic patterns.

## Features
- Real-time packet capture
- Network behavior analysis
- Traffic visualization
- Anomaly detection
- Custom BPF filters
- Email/webhook alerts

## Installation
1. Fork on Replit
2. Configure alerts in config.py (optional)
3. Start the application

## Usage

### Command Line
```bash
python packet_pirate.py -i eth0 -c 100 -f "tcp port 80"
```

Arguments:
- `-i, --interface`: Network interface
- `-c, --count`: Packet count
- `-f, --filter`: BPF filter
- `-o, --output`: Output file

### Web Interface
Access dashboard at http://0.0.0.0:8080

Features:
- Traffic statistics
- Protocol distribution
- Packet size analysis
- Anomaly detection
- Alert history

### Alert Configuration
1. Email Alerts:
   - Configure SMTP settings in config.py
   - Set threshold in Monitor class

2. Webhook Alerts:
   - Add webhook URLs using Monitor.add_webhook()
   - Alerts trigger on threshold breach

## Troubleshooting
- Check permissions for packet capture
- Verify network interface exists
- Ensure valid BPF filter syntax
