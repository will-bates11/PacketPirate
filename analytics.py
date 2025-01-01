
import pandas as pd
from sklearn.ensemble import IsolationForest
from statsmodels.tsa.holtwinters import ExponentialSmoothing

class AdvancedAnalytics:
    def __init__(self):
        self.model = IsolationForest(contamination=0.1)
        
    def detect_threats(self, traffic_data):
        return self.model.fit_predict(traffic_data)
        
    def forecast_traffic(self, historical_data, periods=24):
        model = ExponentialSmoothing(historical_data)
        return model.fit().forecast(periods)
        
    def export_results(self, data, format='csv'):
        if format == 'csv':
            return data.to_csv()
        return data.to_json()
