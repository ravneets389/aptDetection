import subprocess
import os
import re
from flow_analyzer import extract_flows

BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # Get script directory
CAPTURES_DIR = os.path.join(BASE_DIR, "..", "captures")
CAPTURE_FILE = os.path.join(CAPTURES_DIR, "live_capture.pcap")
UPLOADED_FILE = os.path.join(CAPTURES_DIR, "uploaded_file.pcap")
CAPTURE_PROCESS = None

def start_tcpdump():
    global CAPTURE_PROCESS
    if CAPTURE_PROCESS:
        return {"message": "Capture already running"}
    
    if os.path.exists(UPLOADED_FILE):
        return {"message": "Uploaded file exists, no need to start capture, using uploaded file to predict"}
    
    # Ensure the captures directory exists
    os.makedirs(CAPTURES_DIR, exist_ok=True)

    # Check if tcpdump is installed
    try:
        subprocess.run(["tcpdump", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return {"error": "tcpdump is not installed or not found in PATH"}

    interface = "any"

    try:
        CAPTURE_PROCESS = subprocess.Popen(
            ["sudo", "tcpdump", "-i", interface, "-w", CAPTURE_FILE, "-s", "0"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        return {"message": f"Packet capture started on interface : {interface}"}
    except Exception as e:
        return {"error": f"Failed to start capture: {str(e)}"}

def stop_tcpdump():
    global CAPTURE_PROCESS
    if not CAPTURE_PROCESS:
        return {"message": "No capture running"}

    try:
        CAPTURE_PROCESS.terminate()  # Use terminate() instead of kill() for cleaner shutdown
        CAPTURE_PROCESS.wait(timeout=5)  # Wait up to 5 seconds for the process to terminate
        CAPTURE_PROCESS = None

        # Validate capture file
        if not os.path.exists(CAPTURE_FILE) or os.path.getsize(CAPTURE_FILE) == 0:
            return {"message": "Capture stopped, but no packets recorded"}

        # Extract packet count
        try:
            packet_output = subprocess.check_output(["sudo", "tcpdump", "-r", CAPTURE_FILE, "-c", "100"], stderr=subprocess.PIPE).decode()
        except subprocess.CalledProcessError:
            packet_output = "Could not read packets"
        packet_lengths = re.findall(r'length (\d+)', packet_output)
        total_length = sum(map(int, packet_lengths)) if packet_lengths else 0
        
        # Extract flows from the capture file
        flows = extract_flows(CAPTURE_FILE)
        flow_count = len(flows) if flows else 0

        return {
            "message": f"Capture stopped with {len(packet_lengths)} packets and {flow_count} flows",
            "packet_count": len(packet_lengths),
            "flow_count": flow_count
        }
    except Exception as e:
        return {"error": f"Failed to stop capture: {str(e)}"}