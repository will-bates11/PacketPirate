
import os

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'default-secret-key')
    ES_HOST = os.getenv('ES_HOST', 'http://0.0.0.0:9200')
    SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
    SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
    SMTP_EMAIL = os.getenv('SMTP_EMAIL', '')
    SMTP_PASSWORD = os.getenv('SMTP_PASSWORD', '')
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    PACKET_HISTORY_FILE = 'packet_history.csv'
    CUSTOM_FILTERS_FILE = 'custom_filters.json'
