import scapy.all as scapy
import pandas as pd
import numpy as np

# 📌 Extract Features from PCAP
def process_pcap(pcap_path):
    packets = scapy.rdpcap(pcap_path)
    
    # Feature Extraction Example
    packet_count = len(packets)
    unique_ips = set(pkt[scapy.IP].src for pkt in packets if scapy.IP in pkt)
    ip_entropy = len(unique_ips) / packet_count if packet_count > 0 else 0

    return np.array([packet_count, ip_entropy])

# 📌 Extract Features from CSV (MTA-KDD 19 Format)
def process_csv(csv_path):
    df = pd.read_csv(csv_path)

    # Select relevant columns for APT detection(to be added acc to model)
    selected_features = df[["Flow Duration", "Total Fwd Packets", "Total Backward Packets"]].values[0]
    
    return selected_features
