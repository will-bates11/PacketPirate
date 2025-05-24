
from elasticsearch import Elasticsearch
import datetime
import logging

# Handle different versions of elasticsearch
try:
    from elasticsearch import ElasticsearchException
except ImportError:
    # In newer versions, use the base Exception class
    ElasticsearchException = Exception

class PacketLogger:
    def __init__(self):
        try:
            self.es = Elasticsearch(['http://0.0.0.0:9200'])
            if not self.es.ping():
                raise ConnectionError("Failed to connect to Elasticsearch")
        except Exception as e:
            logging.error(f"Failed to initialize Elasticsearch: {e}")
            self.es = None
        
    def log_packet(self, packet_data):
        if not self.es:
            logging.error("Elasticsearch connection not available")
            return False
            
        try:
            doc = {
                'timestamp': datetime.datetime.now(),
                'source': packet_data.get('src'),
                'destination': packet_data.get('dst'),
                'protocol': packet_data.get('protocol')
            }
            self.es.index(index="packets", document=doc)
            return True
        except ElasticsearchException as e:
            logging.error(f"Failed to log packet: {e}")
            return False
