
import plotly.graph_objects as go
import networkx as nx

class NetworkVisualizer:
    def create_topology_map(self, connections):
        G = nx.from_pandas_edgelist(connections)
        pos = nx.spring_layout(G)
        return go.Figure(data=[go.Scatter(x=list(pos.values()))])
        
    def create_time_series(self, traffic_data):
        return go.Figure(data=[go.Scatter(y=traffic_data)])
        
    def protocol_distribution(self, protocol_data):
        return go.Figure(data=[go.Pie(labels=protocol_data.index)])
