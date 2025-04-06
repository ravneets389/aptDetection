import subprocess
import os
import re
from flow_analyzer import extract_flows

BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # Get script directory
CAPTURE_FILE = os.path.join(BASE_DIR, "../captures/live_capture.pcap")
UPLOADED_FILE = os.path.join(BASE_DIR, "../captures/uploaded_file.pcap")
CAPTURE_PROCESS = None

def start_tcpdump():
    global CAPTURE_PROCESS
    if CAPTURE_PROCESS:
        return {"message": "Capture already running"}
#if uploaded file exists, then no need to do anything, call directly stop function
    if os.path.exists(UPLOADED_FILE):
        return {"message": "Uploaded file exists, no need to start capture, using uploaded file to predict"}
    # Ensure `tcpdump` is installed
    if subprocess.run(["which", "tcpdump"], stdout=subprocess.PIPE).returncode != 0:
        return {"error": "tcpdump is not installed or not found in PATH"}

    # Ensure the uploads directory exists
    os.makedirs(os.path.dirname(CAPTURE_FILE), exist_ok=True)

    # Select network interface dynamically
    try:
        interfaces = subprocess.check_output(["ip", "link", "show"]).decode()
        interface = "eth0" if "eth0" in interfaces else "any"
    except Exception:
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
        CAPTURE_PROCESS.kill()
        CAPTURE_PROCESS.wait()
        CAPTURE_PROCESS = None

        # Validate capture file
        if not os.path.exists(CAPTURE_FILE) or os.path.getsize(CAPTURE_FILE) == 0:
            return {"message": "Capture stopped, but no packets recorded"}

        # Extract packet count
        try:
            packet_output = subprocess.check_output(["sudo","tcpdump", "-r", CAPTURE_FILE, "-c", "100"]).decode()
        except subprocess.CalledProcessError:
            packet_output = "Could not read packets"
        packet_lengths = re.findall(r'length (\d+)', packet_output)
        total_length = sum(map(int, packet_lengths)) if packet_lengths else 0
        
        # Extract flows from the capture file
        flows = extract_flows(CAPTURE_FILE)
        flow_count = len(flows)

        return {
            "message": f"Capture stopped with {len(packet_lengths)} packets and {flow_count} flows",
            "packet_count": len(packet_lengths),
            "flow_count": flow_count
        }
    except Exception as e:
        return {"error": f"Failed to stop capture: {str(e)}"}