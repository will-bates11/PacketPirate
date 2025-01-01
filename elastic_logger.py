
from elasticsearch import Elasticsearch
import datetime

class PacketLogger:
    def __init__(self):
        self.es = Elasticsearch(['http://localhost:9200'])
        
    def log_packet(self, packet_data):
        doc = {
            'timestamp': datetime.datetime.now(),
            'source': packet_data['src'],
            'destination': packet_data['dst'],
            'protocol': packet_data['protocol']
        }
        self.es.index(index="packets", document=doc)
