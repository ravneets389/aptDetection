import scapy.all as scapy
import numpy as np
from collections import defaultdict
import time
import uuid
import json
import os
from datetime import datetime

# Global variables
FLOWS = []  # Ensure FLOWS is always a list
FLOWS_FILE = "flows.json"
BACKUP_FILE = "flows_backup.json"

def load_flows():
    """Load flows from a JSON file with backup recovery"""
    global FLOWS
    try:
        # Try to load from the main file first
        if os.path.exists(FLOWS_FILE):
            with open(FLOWS_FILE, "r") as f:
                loaded_flows = json.load(f)
                # Ensure loaded_flows is a list
                if isinstance(loaded_flows, dict):
                    FLOWS = list(loaded_flows.values())
                elif isinstance(loaded_flows, list):
                    FLOWS = loaded_flows
                else:
                    FLOWS = []
                print(f"Loaded {len(FLOWS)} flows from {FLOWS_FILE}")
                return
        
        # If main file doesn't exist, try to load from backup
        if os.path.exists(BACKUP_FILE):
            with open(BACKUP_FILE, "r") as f:
                loaded_flows = json.load(f)
                # Ensure loaded_flows is a list
                if isinstance(loaded_flows, dict):
                    FLOWS = list(loaded_flows.values())
                elif isinstance(loaded_flows, list):
                    FLOWS = loaded_flows
                else:
                    FLOWS = []
                print(f"Loaded {len(FLOWS)} flows from backup {BACKUP_FILE}")
                # Restore the main file from backup
                save_flows()
                return
        
        # If neither file exists, start with empty flows
        FLOWS = []
        print("No flows files found, starting with empty flows")
    except Exception as e:
        print(f"Error loading flows: {str(e)}")
        # Try to recover from backup if main file is corrupted
        try:
            if os.path.exists(BACKUP_FILE):
                with open(BACKUP_FILE, "r") as f:
                    loaded_flows = json.load(f)
                    # Ensure loaded_flows is a list
                    if isinstance(loaded_flows, dict):
                        FLOWS = list(loaded_flows.values())
                    elif isinstance(loaded_flows, list):
                        FLOWS = loaded_flows
                    else:
                        FLOWS = []
                print(f"Recovered {len(FLOWS)} flows from backup after error")
                # Restore the main file from backup
                save_flows()
            else:
                FLOWS = []
                print("Could not recover from backup, starting with empty flows")
        except Exception as backup_error:
            print(f"Error recovering from backup: {str(backup_error)}")
            FLOWS = []

def save_flows():
    """Save flows to a JSON file with backup"""
    try:
        # Convert flows to a serializable format
        serializable_flows = []
        for flow in FLOWS:
            # Create a copy of the flow without packet data
            serializable_flow = {k: v for k, v in flow.items() if k != "packets"}
            
            # Convert features to list if it's a numpy array
            if "features" in serializable_flow:
                if isinstance(serializable_flow["features"], np.ndarray):
                    serializable_flow["features"] = serializable_flow["features"].tolist()
                elif not isinstance(serializable_flow["features"], list):
                    serializable_flow["features"] = list(serializable_flow["features"])
            
            serializable_flows.append(serializable_flow)
        
        # First save to backup file
        with open(BACKUP_FILE, "w") as f:
            json.dump(serializable_flows, f, indent=2)
        
        # Then save to main file
        with open(FLOWS_FILE, "w") as f:
            json.dump(serializable_flows, f, indent=2)
        
        print(f"Saved {len(serializable_flows)} flows to {FLOWS_FILE} and backup")
    except Exception as e:
        print(f"Error saving flows: {str(e)}")
        # If saving to main file fails, at least we have the backup

def get_flows():
    """Get all flows"""
    global FLOWS
    # Ensure FLOWS is a list
    if not isinstance(FLOWS, list):
        FLOWS = []
    return FLOWS

def get_flow_by_id(flow_id):
    """Get a flow by its ID with improved error handling"""
    global FLOWS
    try:
        if not flow_id:
            print("No flow ID provided")
            return None
            
        print(f"Looking for flow with ID: {flow_id}")
        
        # Ensure FLOWS is a list
        if not isinstance(FLOWS, list):
            FLOWS = []
        
        # Find the flow with the matching ID
        for flow in FLOWS:
            if flow.get("id") == flow_id:
                print(f"Found flow: {flow.get('id')} - {flow.get('source_ip')}:{flow.get('source_port')} -> {flow.get('dest_ip')}:{flow.get('dest_port')}")
                return flow
                
        print(f"Flow with ID {flow_id} not found")
        return None
    except Exception as e:
        print(f"Error getting flow by ID: {str(e)}")
        return None

def extract_flows(pcap_file):
    """Extract flows from a PCAP file with improved error handling"""
    global FLOWS
    
    # Ensure FLOWS is a list
    if not isinstance(FLOWS, list):
        FLOWS = []
    
    # Don't reset flows here, just append new ones
    new_flows = []
    
    try:
        print(f"Attempting to read PCAP file: {pcap_file}")
        if not os.path.exists(pcap_file):
            print(f"Error: PCAP file does not exist: {pcap_file}")
            return []
            
        # Read the PCAP file
        packets = scapy.rdpcap(pcap_file)
        print(f"Read {len(packets)} packets from {pcap_file}")
        
        if not packets:
            print(f"No packets found in {pcap_file}")
            return []
        
        # Count packets with IP layer
        ip_packets = [p for p in packets if scapy.IP in p]
        print(f"Found {len(ip_packets)} packets with IP layer")
        
        if not ip_packets:
            print(f"No IP packets found in {pcap_file}")
            return []
        
        # Group packets by flow
        flows = {}
        for packet in ip_packets:
            try:
                # Extract flow key (src_ip, src_port, dst_ip, dst_port, protocol)
                src_ip = packet[scapy.IP].src
                dst_ip = packet[scapy.IP].dst
                protocol = packet[scapy.IP].proto
                
                # Get ports if available
                src_port = packet[scapy.TCP].sport if scapy.TCP in packet else packet[scapy.UDP].sport if scapy.UDP in packet else 0
                dst_port = packet[scapy.TCP].dport if scapy.TCP in packet else packet[scapy.UDP].dport if scapy.UDP in packet else 0
                
                # Create flow key
                flow_key = (src_ip, src_port, dst_ip, dst_port, protocol)
                
                # Add packet to flow
                if flow_key not in flows:
                    flows[flow_key] = {
                        "id": str(uuid.uuid4()),
                        "source_ip": src_ip,
                        "source_port": src_port,
                        "dest_ip": dst_ip,
                        "dest_port": dst_port,
                        "protocol": protocol,
                        "packet_count": 0,
                        "byte_count": 0,
                        "start_time": float(packet.time),
                        "end_time": float(packet.time),
                        "packets": []
                    }
                
                # Update flow statistics
                flows[flow_key]["packet_count"] += 1
                flows[flow_key]["byte_count"] += len(packet)
                flows[flow_key]["end_time"] = float(packet.time)
                flows[flow_key]["packets"].append(packet)
            except Exception as packet_error:
                print(f"Error processing packet: {str(packet_error)}")
                continue
        
        print(f"Extracted {len(flows)} unique flows from packets")
        
        # Convert flows dictionary to list
        new_flows = list(flows.values())
        
        # Calculate additional features for each flow
        for flow in new_flows:
            if "packets" in flow and flow["packets"]:
                # Calculate IP entropy
                unique_ips = set()
                for pkt in flow["packets"]:
                    if scapy.IP in pkt:
                        unique_ips.add(pkt[scapy.IP].src)
                        unique_ips.add(pkt[scapy.IP].dst)
                flow["ip_entropy"] = len(unique_ips) / flow["packet_count"] if flow["packet_count"] > 0 else 0.0
                
                # Calculate average packet size
                flow["avg_packet_size"] = flow["byte_count"] / flow["packet_count"] if flow["packet_count"] > 0 else 0.0
                
                # Calculate unique protocols
                flow["unique_protocols"] = len(set(pkt[scapy.IP].proto for pkt in flow["packets"] if scapy.IP in pkt))
                
                # Calculate packet IAT variance
                timestamps = [float(pkt.time) for pkt in flow["packets"]]
                flow["packet_iat_variance"] = float(np.var(np.diff(sorted(timestamps)))) if len(timestamps) > 1 else 0.0
            else:
                # Set default values if no packet data
                flow["ip_entropy"] = 0.0
                flow["avg_packet_size"] = 0.0
                flow["unique_protocols"] = 1
                flow["packet_iat_variance"] = 0.0
        
        # Add new flows to existing flows
        FLOWS.extend(new_flows)
        
        # Save flows to file
        save_flows()
        
        print(f"Successfully extracted and saved {len(new_flows)} flows")
        return new_flows
    except Exception as e:
        print(f"Error extracting flows from {pcap_file}: {str(e)}")
        import traceback
        traceback.print_exc()
        return []

def extract_flow_features(flow):
    """Extract features from a flow for ML prediction with improved error handling"""
    try:
        if not flow:
            print("No flow provided")
            return None
            
        # Check if we have packet data
        if "packets" in flow and flow["packets"]:
            # Calculate features from packet data
            packet_count = len(flow["packets"])
            ip_entropy = calculate_ip_entropy(flow["packets"])
            avg_packet_size = sum(len(packet) for packet in flow["packets"]) / packet_count
            unique_protocols = len(set(packet[23] for packet in flow["packets"]))
            packet_iat_variance = calculate_packet_iat_variance(flow["packets"])
        else:
            # Use flow statistics if packet data is not available
            packet_count = flow.get("packet_count", 0)
            ip_entropy = flow.get("ip_entropy", 0.0)
            avg_packet_size = flow.get("avg_packet_size", 0.0)
            unique_protocols = flow.get("unique_protocols", 0)
            packet_iat_variance = flow.get("packet_iat_variance", 0.0)
        
        # Create a list of features first
        features_list = [
            float(packet_count),
            float(ip_entropy),
            float(avg_packet_size),
            float(unique_protocols),
            float(packet_iat_variance)
        ]
        
        # Convert to numpy array
        features = np.array(features_list, dtype=np.float64)
        
        # Check if the array is valid
        if np.isnan(features).any() or np.isinf(features).any():
            print("Invalid feature values detected (NaN or Inf)")
            return None
            
        return features
    except Exception as e:
        print(f"Error extracting flow features: {str(e)}")
        import traceback
        traceback.print_exc()
        return None

def calculate_ip_entropy(packets):
    """Calculate IP entropy from a list of packets with improved error handling"""
    try:
        if not packets:
            return 0.0
        
        # Count unique IPs
        unique_ips = set()
        for packet in packets:
            if scapy.IP in packet:
                unique_ips.add(packet[scapy.IP].src)
                unique_ips.add(packet[scapy.IP].dst)
        
        # Calculate entropy
        packet_count = len(packets)
        if packet_count == 0:
            return 0.0
        
        return len(unique_ips) / packet_count
    except Exception as e:
        print(f"Error calculating IP entropy: {str(e)}")
        return 0.0

def calculate_packet_iat_variance(packets):
    """Calculate packet inter-arrival time variance from a list of packets with improved error handling"""
    try:
        if not packets or len(packets) < 2:
            return 0.0
        
        # Extract timestamps
        timestamps = [float(packet.time) for packet in packets]
        
        # Calculate IAT variance
        iat = np.diff(sorted(timestamps))
        return float(np.var(iat)) if len(iat) > 0 else 0.0
    except Exception as e:
        print(f"Error calculating packet IAT variance: {str(e)}")
        return 0.0

# Load flows when module is imported
load_flows() 