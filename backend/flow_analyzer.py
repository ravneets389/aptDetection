import os
import json
import numpy as np
import pandas as pd
from datetime import datetime
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
import scapy.all as scapy
from collections import defaultdict
import time
import uuid

# Constants
FLOWS_FILE = "flows.json"
BACKUP_FILE = "flows_backup.json"
FLOWS = []

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
                
                # Get protocol names safely
                protocol_names = []
                for layer in packet.layers():
                    try:
                        # Try to get the name attribute, fallback to class name
                        proto_name = getattr(layer, 'name', layer.__name__ if hasattr(layer, '__name__') else layer.__class__.__name__)
                        if isinstance(proto_name, str):
                            protocol_names.append(proto_name)
                    except Exception as e:
                        print(f"Error getting protocol name: {str(e)}")
                        continue
                
                # Add packet to flow
                if flow_key not in flows:
                    # Initialize flow with basic features
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
                        # Store features from the first packet
                        "frame_protocols": '_'.join(protocol_names) if protocol_names else 'unknown',
                        "eth_src": packet[Ether].src if Ether in packet else "00:00:00:00:00:00",
                        "eth_dst": packet[Ether].dst if Ether in packet else "00:00:00:00:00:00",
                        "ip_flags": int(packet[IP].flags) if IP in packet else 0,
                        "ip_ttl": packet[IP].ttl if IP in packet else 64,
                        "ip_tos": packet[IP].tos if IP in packet else 0,
                        "tcp_flags": int(packet[TCP].flags) if TCP in packet else 0,
                        "tcp_window": packet[TCP].window if TCP in packet else 0,
                        "tcp_scale": getattr(packet[TCP], 'window_scale', 1) if TCP in packet else 1,
                        "tcp_options": str(packet[TCP].options) if TCP in packet else "",
                        "tcp_checksum": packet[TCP].chksum if TCP in packet else 0
                    }
                
                # Update flow statistics
                flow = flows[flow_key]
                flow["packet_count"] += 1
                flow["byte_count"] += len(packet)
                
            except Exception as packet_error:
                print(f"Error processing packet: {str(packet_error)}")
                continue
        
        print(f"Extracted {len(flows)} unique flows from packets")
        
        # Convert flows dictionary to list
        new_flows = list(flows.values())
        
        if new_flows:  # Only update FLOWS and save if we have new flows
            # Add new flows to existing flows
            FLOWS.extend(new_flows)
            
            # Save flows to file
            save_flows()
        
        # Return the new flows
        return new_flows
        
    except Exception as e:
        print(f"Error extracting flows: {str(e)}")
        import traceback
        traceback.print_exc()
        return []

def extract_flow_features(flow):
    """Extract features from a flow for ML prediction"""
    try:
        if not flow:
            print("DEBUG: No flow provided (flow is None or empty)")
            return None
            
        print(f"DEBUG: Flow ID: {flow.get('id')}")
        
        # Initialize features dictionary with exactly the 23 required features
        features = {
            # Frame features
            'frame.time': flow.get('start_time', 0),
            'frame.len': flow.get('byte_count', 0),
            'frame.protocols': flow.get('frame_protocols', ''),
            
            # Ethernet features
            'eth.src': flow.get('eth_src', '00:00:00:00:00:00'),
            'eth.dst': flow.get('eth_dst', '00:00:00:00:00:00'),
            
            # IP features
            'ip.dst': flow.get('dest_ip', '0.0.0.0'),
            'ip.src': flow.get('source_ip', '0.0.0.0'),
            'ip.flags': flow.get('ip_flags', 0),
            'ip.ttl': flow.get('ip_ttl', 64),
            'ip.proto': flow.get('protocol', 0),
            'ip.checksum': flow.get('tcp_checksum', 0),
            'ip.tos': flow.get('ip_tos', 0),
            
            # TCP features
            'tcp.srcport': flow.get('source_port', 0),
            'tcp.dstport': flow.get('dest_port', 0),
            'tcp.flags': flow.get('tcp_flags', 0),
            'tcp.window_size_value': flow.get('tcp_window', 0),
            'tcp.window_size_scalefactor': flow.get('tcp_scale', 1),
            'tcp.checksum': flow.get('tcp_checksum', 0),
            'tcp.options': flow.get('tcp_options', ''),
            'tcp.pdu.size': flow.get('byte_count', 0) / flow.get('packet_count', 1),
            
            # UDP features
            'udp.srcport': flow.get('source_port', 0) if flow.get('protocol') == 17 else 0,
            'udp.dstport': flow.get('dest_port', 0) if flow.get('protocol') == 17 else 0
        }
        
        print(f"DEBUG: All raw features collected: {features}")
        
        # Convert categorical features to numerical using one-hot encoding
        categorical_features = ['frame.protocols', 'eth.src', 'eth.dst', 'ip.dst', 'ip.src', 
                              'ip.flags', 'ip.proto', 'tcp.options']
        
        # Create a pandas DataFrame with one row
        df = pd.DataFrame([features])
        print("DEBUG: Created DataFrame from features")
        
        # Apply one-hot encoding to categorical features
        df_encoded = pd.get_dummies(df, columns=categorical_features)
        print(f"DEBUG: One-hot encoding applied. Number of features: {df_encoded.shape[1]}")
        
        # Convert to numpy array and ensure all values are float
        features_array = df_encoded.values.astype(float)
        print(f"DEBUG: Converted to numpy array. Shape: {features_array.shape}")
        
        # Verify we have valid data
        if np.isnan(features_array).any():
            print("DEBUG: NaN values detected in features")
            return None
        if np.isinf(features_array).any():
            print("DEBUG: Infinite values detected in features")
            return None
            
        print("DEBUG: Feature extraction successful")
        return features_array[0]  # Return the first (and only) row
        
    except Exception as e:
        print(f"DEBUG: Error in extract_flow_features: {str(e)}")
        print("DEBUG: Full traceback:")
        import traceback
        traceback.print_exc()
        return None

# Load flows when module is imported
load_flows() 