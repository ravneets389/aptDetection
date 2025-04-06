import scapy.all as scapy
import pandas as pd
import numpy as np
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

def process_pcap(pcap_path):
    packets = scapy.rdpcap(pcap_path)
    features = []
    
    for packet in packets:
        # Initialize feature dictionary
        pkt_features = {}
        
        # Frame features
        pkt_features['frame.time'] = float(packet.time)
        pkt_features['frame.len'] = len(packet)
        pkt_features['frame.protocols'] = '_'.join([layer.name for layer in packet.layers()])
        
        # Ethernet features
        if Ether in packet:
            pkt_features['eth.src'] = packet[Ether].src
            pkt_features['eth.dst'] = packet[Ether].dst
        else:
            pkt_features['eth.src'] = '00:00:00:00:00:00'
            pkt_features['eth.dst'] = '00:00:00:00:00:00'
            
        # IP features
        if IP in packet:
            ip_layer = packet[IP]
            pkt_features['ip.dst'] = ip_layer.dst
            pkt_features['ip.src'] = ip_layer.src
            pkt_features['ip.flags'] = ip_layer.flags
            pkt_features['ip.ttl'] = ip_layer.ttl
            pkt_features['ip.proto'] = ip_layer.proto
            pkt_features['ip.checksum'] = ip_layer.chksum
            pkt_features['ip.tos'] = ip_layer.tos
        else:
            pkt_features['ip.dst'] = '0.0.0.0'
            pkt_features['ip.src'] = '0.0.0.0'
            pkt_features['ip.flags'] = 0
            pkt_features['ip.ttl'] = 0
            pkt_features['ip.proto'] = 0
            pkt_features['ip.checksum'] = 0
            pkt_features['ip.tos'] = 0
            
        # TCP features
        if TCP in packet:
            tcp_layer = packet[TCP]
            pkt_features['tcp.srcport'] = tcp_layer.sport
            pkt_features['tcp.dstport'] = tcp_layer.dport
            pkt_features['tcp.flags'] = tcp_layer.flags
            pkt_features['tcp.window_size_value'] = tcp_layer.window
            pkt_features['tcp.window_size_scalefactor'] = getattr(tcp_layer, 'window_scale', 1)
            pkt_features['tcp.checksum'] = tcp_layer.chksum
            pkt_features['tcp.options'] = str(tcp_layer.options)
            pkt_features['tcp.pdu.size'] = len(tcp_layer.payload)
        else:
            pkt_features['tcp.srcport'] = 0
            pkt_features['tcp.dstport'] = 0
            pkt_features['tcp.flags'] = 0
            pkt_features['tcp.window_size_value'] = 0
            pkt_features['tcp.window_size_scalefactor'] = 0
            pkt_features['tcp.checksum'] = 0
            pkt_features['tcp.options'] = ''
            pkt_features['tcp.pdu.size'] = 0
            
        # UDP features
        if UDP in packet:
            udp_layer = packet[UDP]
            pkt_features['udp.srcport'] = udp_layer.sport
            pkt_features['udp.dstport'] = udp_layer.dport
        else:
            pkt_features['udp.srcport'] = 0
            pkt_features['udp.dstport'] = 0
            
        # Label (this should be set based on your classification needs)
        pkt_features['label'] = 0  # Default to benign
            
        features.append(pkt_features)
    
    # Convert to DataFrame
    df = pd.DataFrame(features)
    
    # Ensure all numeric columns are float type
    numeric_columns = df.select_dtypes(include=[np.number]).columns
    df[numeric_columns] = df[numeric_columns].astype(float)
    
    # Return the features as a numpy array
    return df.values


# 📌 Extract Features from CSV (MTA-KDD 19 Format)
def process_csv(csv_path):
    df = pd.read_csv(csv_path)

    # Select relevant columns for APT detection(to be added acc to model)
    selected_features = df[["Flow Duration", "Total Fwd Packets", "Total Backward Packets"]].values[0]
    
    return selected_features
