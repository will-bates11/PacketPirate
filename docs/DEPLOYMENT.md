
# PacketPirate Deployment Guide

## Deployment on Replit

1. Setup
   - Fork the repository on Replit
   - Install dependencies automatically via requirements.txt

2. Configuration
   - Update config.py with your settings
   - Configure monitoring thresholds
   - Set up alert endpoints

3. Deploy
   - Click "Deploy" in Replit
   - Choose "Autoscale" deployment
   - Set run command: `python packet_pirate.py`
   - Configure domain name

4. Monitoring
   - Check logs in Replit console
   - Monitor system health at /health
   - View metrics at /api/stats

## Security Considerations
- Use environment variables for sensitive data
- Enable authentication for API endpoints
- Configure rate limiting
- Set up CSRF protection

## Performance Tuning
- Adjust packet capture count
- Configure monitoring intervals
- Set appropriate alert thresholds
- Use efficient BPF filters
