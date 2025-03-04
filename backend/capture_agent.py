from fastapi import FastAPI
import subprocess
import os
import time

app = FastAPI()
CAPTURE_FILE = "capture.pcap"
CAPTURE_PROCESS = None

@app.get("/start_capture")
async def start_capture():
    global CAPTURE_PROCESS
    if CAPTURE_PROCESS:
        return{"message":"Capture already running."}
    
    #capture packets using tcp dump /// alt scapy but it is slow
    CAPTURE_PROCESS = subprocess.Popen(["tcpdump", "-i", "eth0", "-w", CAPTURE_FILE, "-s", "0"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return{"message":"Capture already started."}

@app.get("/stop_capture/")
async def stop_capture():
    global CAPTURE_PROCESS
    if not CAPTURE_PROCESS:
        return{"message":"No capture is running."}
    
    #Stop tcpdump process
    CAPTURE_PROCESS.terminate()
    CAPTURE_PROCESS = None

    #Process the pcap file
    packet_count = subprocess.check_output(["tcpdump","-r",CAPTURE_FILE,"-c","100"]).decode()

    return {"message":"Capture stopped", "packets":packet_count}

#Clean up the old files on startup
if os.path.exists(CAPTURE_FILE):
    os.remove(CAPTURE_FILE)