import subprocess
import os

CAPTURE_FILE = "uploads/live_capture.pcap"
CAPTURE_PROCESS = None

def start_tcpdump():
    global CAPTURE_PROCESS
    if CAPTURE_PROCESS:
        return {"message": "Capture already running"}

    # Start capturing packets using tcpdump
    CAPTURE_PROCESS = subprocess.Popen(
        ["tcpdump", "-i", "eth0", "-w", CAPTURE_FILE, "-s", "0"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    return {"message": "Packet capture started"}

def stop_tcpdump():
    global CAPTURE_PROCESS
    if not CAPTURE_PROCESS:
        return {"message": "No capture running"}

    # Stop tcpdump
    CAPTURE_PROCESS.terminate()
    CAPTURE_PROCESS = None

    # Process the .pcap file to extract basic packet info
    packet_count = subprocess.check_output(["tcpdump", "-r", CAPTURE_FILE, "-c", "100"]).decode()
    
    return {"message": "Capture stopped", "packets": packet_count}
