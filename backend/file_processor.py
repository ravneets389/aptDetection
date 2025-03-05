import scapy.all as scapy
import pandas as pd
import numpy as np

def process_pcap(pcap_path):
    packets = scapy.rdpcap(pcap_path)
    
    # Feature 1: Packet Count
    packet_count = len(packets)

    # Feature 2: Unique Source IPs
    unique_ips = set(pkt[scapy.IP].src for pkt in packets if scapy.IP in pkt)
    ip_entropy = len(unique_ips) / packet_count if packet_count > 0 else 0.0

    # Feature 3: Average Packet Size
    avg_pkt_size = np.mean([len(pkt) for pkt in packets]) if packet_count > 0 else 0.0

    # Feature 4: Unique Protocols Used
    unique_protocols = len(set(pkt[scapy.IP].proto for pkt in packets if scapy.IP in pkt))

    # Feature 5: Variance in Packet Inter-Arrival Time (Fixed)
    timestamps = [float(pkt.time) for pkt in packets]  # Ensure timestamps are floats
    pkt_iat_var = float(np.var(np.diff(sorted(timestamps)))) if len(timestamps) > 1 else 0.0

    return np.array([packet_count, ip_entropy, avg_pkt_size, unique_protocols, pkt_iat_var])


# 📌 Extract Features from CSV (MTA-KDD 19 Format)
def process_csv(csv_path):
    df = pd.read_csv(csv_path)

    # Select relevant columns for APT detection(to be added acc to model)
    selected_features = df[["Flow Duration", "Total Fwd Packets", "Total Backward Packets"]].values[0]
    
    return selected_features
