from fastapi import FastAPI, File, UploadFile, HTTPException
import os
import uvicorn
import joblib
import glob  
from capture_agent import start_tcpdump, stop_tcpdump  # ✅ Use absolute imports
from file_processor import process_pcap, process_csv  # ✅ Use absolute imports
from flow_analyzer import extract_flows, get_flows, get_flow_by_id, extract_flow_features, save_flows, load_flows  # Import flow analyzer
from fastapi.middleware.cors import CORSMiddleware
import shutil #for saving files
import time
import threading
import scapy.all as scapy
import pickle
import numpy as np
from fastapi.responses import JSONResponse
from typing import List, Dict, Any, Optional
from datetime import datetime

# Global variables for packet capture
is_capturing = False
pcap_writer = None
capture_file = None
capture_start_time = None

def capture_packets():
    """Capture packets and write them to the PCAP file"""
    global is_capturing, pcap_writer
    
    try:
        print(f"Starting packet capture to {capture_file}")
        
        # Start capturing packets
        scapy.sniff(
            prn=lambda x: pcap_writer.write(x) if is_capturing else None,
            store=False,
            stop_filter=lambda x: not is_capturing,
            timeout=None  # Run indefinitely until stopped
        )
    except Exception as e:
        print(f"Error in packet capture: {str(e)}")
        import traceback
        traceback.print_exc()
    finally:
        print("Packet capture stopped")
        if pcap_writer:
            pcap_writer.close()
            print(f"Capture file closed: {capture_file}")
            print(f"Capture file size: {os.path.getsize(capture_file)} bytes")

app = FastAPI()
UPLOAD_FOLDER = "../uploads/"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Allow frontend requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://172.21.214.198:3000"],  # Adjust this to your frontend URL
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods
    allow_headers=["*"],  # Allow all headers
)

# Load ML model
model_path = os.path.join(os.path.dirname(__file__), "..", "models", "mta_kdd_model.pkl")
try:
    model = joblib.load(model_path)
    print(f"Model loaded successfully from {model_path}")
except Exception as e:
    print(f"Error loading model: {str(e)}")
    model = None

@app.get("/")
async def root():
    """Root endpoint"""
    return {"message": "APT Detection API"}

# Start Packet Capture
@app.post("/start_capture")
async def start_capture():
    """Start capturing packets"""
    global is_capturing, pcap_writer, capture_file, capture_start_time
    
    if is_capturing:
        return JSONResponse(
            status_code=400,
            content={
                "status": "error",
                "message": "Capture is already running"
            }
        )
    
    try:
        # Create uploads directory if it doesn't exist
        os.makedirs("uploads", exist_ok=True)
        
        # Generate a unique filename for this capture
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        capture_file = f"uploads/live_capture_{timestamp}.pcap"
        
        # Open the capture file in PCAP format (not PCAP-NG)
        pcap_writer = scapy.PcapWriter(capture_file, append=False, sync=True)
        
        # Verify the file was created and is writable
        if not os.path.exists(capture_file):
            return JSONResponse(
                status_code=500,
                content={
                    "status": "error",
                    "message": "Failed to create capture file"
                }
            )
            
        # Start capturing
        is_capturing = True
        capture_start_time = time.time()
        
        # Start the capture thread
        capture_thread = threading.Thread(target=capture_packets)
        capture_thread.daemon = True
        capture_thread.start()
        
        # Wait a moment to ensure the capture has started
        time.sleep(0.5)
        
        # Verify the file is being written to
        if os.path.getsize(capture_file) == 0:
            # If the file is still empty after a moment, there might be an issue
            # with the capture process
            is_capturing = False
            if pcap_writer:
                pcap_writer.close()
                pcap_writer = None
                
            return JSONResponse(
                status_code=500,
                content={
                    "status": "error",
                    "message": "Capture started but no packets are being captured. This might be due to network interface issues or permissions."
                }
            )
        
        return {
            "status": "success",
            "message": "Capture started",
            "capture_file": capture_file
        }
    except PermissionError:
        return JSONResponse(
            status_code=403,
            content={
                "status": "error",
                "message": "Permission denied. Please run the server with sudo privileges to capture packets."
            }
        )
    except Exception as e:
        print(f"Error starting capture: {str(e)}")
        import traceback
        traceback.print_exc()
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": f"Error starting capture: {str(e)}"
            }
        )

# Stop Packet Capture
@app.post("/stop_capture")
async def stop_capture():
    """Stop capturing packets"""
    global is_capturing, pcap_writer, capture_file, capture_start_time
    
    if not is_capturing:
        return JSONResponse(
            status_code=400,
            content={
                "status": "error",
                "message": "No capture is running"
            }
        )
    
    try:
        print("Stopping capture...")
        is_capturing = False
        
        # Close the pcap writer
        if pcap_writer:
            pcap_writer.close()
            pcap_writer = None
            print(f"Capture file closed: {capture_file}")
        
        # Wait a moment for the file to be properly closed
        time.sleep(1)
        
        # Check if the capture file exists and has content
        if not os.path.exists(capture_file):
            return JSONResponse(
                status_code=500,
                content={
                    "status": "error",
                    "message": "Capture file not found"
                }
            )
            
        file_size = os.path.getsize(capture_file)
        print(f"Capture file size: {file_size} bytes")
        
        if file_size == 0:
            return JSONResponse(
                status_code=400,
                content={
                    "status": "error",
                    "message": "The capture file is empty. No packets were captured."
                }
            )
        
        # Analyze the captured packets
        capture_duration = time.time() - capture_start_time
        print(f"Capture duration: {capture_duration:.2f} seconds")
        
        # Extract flows from the capture file
        flows = extract_flows(capture_file)
        
        if not flows:
            return JSONResponse(
                status_code=404,
                content={
                    "status": "error",
                    "message": "No flows could be extracted from the capture file. This might be due to no network traffic being captured or the file format being incompatible."
                }
            )
            
        return {
            "status": "success",
            "message": f"Capture stopped after {capture_duration:.2f} seconds",
            "flows": flows
        }
    except Exception as e:
        print(f"Error stopping capture: {str(e)}")
        import traceback
        traceback.print_exc()
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": f"Error stopping capture: {str(e)}"
            }
        )

def get_latest_file():
    """Find the latest .pcap or .csv file in the uploads folder."""
    files = sorted(glob.glob(os.path.join(UPLOAD_FOLDER, "*.pcap")) + glob.glob(os.path.join(UPLOAD_FOLDER, "*.csv")), key=os.path.getmtime, reverse=True)
    return files[0] if files else None

@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    """Upload a PCAP file"""
    try:
        # Generate a unique filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"uploads/{timestamp}_{file.filename}"
        
        # Save the file
        with open(filename, "wb") as f:
            content = await file.read()
            f.write(content)
        
        # Extract flows from the file
        flows = extract_flows(filename)
        
        return {
            "status": "success",
            "message": f"File uploaded and {len(flows)} flows extracted",
            "flows": flows
        }
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": f"Error uploading file: {str(e)}"
            }
        )

@app.get("/flows")
async def get_all_flows():
    """Get all flows"""
    try:
        flows = get_flows()
        return {
            "status": "success",
            "flows": flows
        }
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": f"Error getting flows: {str(e)}"
            }
        )

@app.get("/flows/{flow_id}")
async def get_flow(flow_id: str):
    """Get a specific flow by ID"""
    try:
        flow = get_flow_by_id(flow_id)
        if not flow:
            return JSONResponse(
                status_code=404,
                content={
                    "status": "error",
                    "message": f"Flow with ID {flow_id} not found"
                }
            )
        
        return {
            "status": "success",
            "flow": flow
        }
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": f"Error getting flow: {str(e)}"
            }
        )

@app.get("/analyze_flows")
async def analyze_flows():
    """Analyze flows from the latest capture or uploaded file"""
    try:
        # First check if we have a current capture file
        if capture_file and os.path.exists(capture_file):
            print(f"Analyzing current capture file: {capture_file}")
            try:
                # Check file size
                file_size = os.path.getsize(capture_file)
                print(f"Capture file size: {file_size} bytes")
                
                if file_size == 0:
                    print(f"Capture file is empty: {capture_file}")
                    return JSONResponse(
                        status_code=400,
                        content={
                            "status": "error",
                            "message": "The capture file is empty. Please try capturing again."
                        }
                    )
                
                flows = extract_flows(capture_file)
                if not flows:
                    print(f"No flows extracted from {capture_file}")
                    return JSONResponse(
                        status_code=404,
                        content={
                            "status": "error",
                            "message": "No flows could be extracted from the capture file. This might be due to no network traffic being captured or the file format being incompatible."
                        }
                    )
            except Exception as e:
                print(f"Error extracting flows from {capture_file}: {str(e)}")
                import traceback
                traceback.print_exc()
                return JSONResponse(
                    status_code=500,
                    content={
                        "status": "error",
                        "message": f"Error extracting flows: {str(e)}"
                    }
                )
        else:
            # If no current capture, check the uploads folder
            print("No current capture file, checking uploads folder")
            latest_file = get_latest_file()
            if not latest_file:
                print("No files found in uploads folder")
                return JSONResponse(
                    status_code=404,
                    content={
                        "status": "error",
                        "message": "No capture files found. Please start a capture or upload a PCAP file."
                    }
                )
            
            if not latest_file.endswith(".pcap"):
                print(f"Latest file is not a PCAP file: {latest_file}")
                return JSONResponse(
                    status_code=400,
                    content={
                        "status": "error",
                        "message": "No PCAP files found. Please upload a PCAP file."
                    }
                )
            
            print(f"Analyzing latest file: {latest_file}")
            try:
                # Check file size
                file_size = os.path.getsize(latest_file)
                print(f"File size: {file_size} bytes")
                
                if file_size == 0:
                    print(f"File is empty: {latest_file}")
                    return JSONResponse(
                        status_code=400,
                        content={
                            "status": "error",
                            "message": "The uploaded file is empty. Please try uploading a different file."
                        }
                    )
                
                flows = extract_flows(latest_file)
                if not flows:
                    print(f"No flows extracted from {latest_file}")
                    return JSONResponse(
                        status_code=404,
                        content={
                            "status": "error",
                            "message": "No flows could be extracted from the file. This might be due to no network traffic in the file or the file format being incompatible."
                        }
                    )
            except Exception as e:
                print(f"Error extracting flows from {latest_file}: {str(e)}")
                import traceback
                traceback.print_exc()
                return JSONResponse(
                    status_code=500,
                    content={
                        "status": "error",
                        "message": f"Error extracting flows: {str(e)}"
                    }
                )
        
        # Return flows without the packet data to reduce payload size
        for flow in flows:
            if "packets" in flow:
                del flow["packets"]
        
        print(f"Returning {len(flows)} flows")
        return {
            "status": "success",
            "flows": flows
        }
    except Exception as e:
        error_msg = f"Error analyzing flows: {str(e)}"
        print(error_msg)
        import traceback
        traceback.print_exc()
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": error_msg
            }
        )

@app.get("/predict_flow/{flow_id}")
async def predict_flow(flow_id: str):
    """Predict if a flow is malicious"""
    try:
        # Get the flow
        flow = get_flow_by_id(flow_id)
        if not flow:
            return JSONResponse(
                status_code=404,
                content={
                    "status": "error",
                    "message": f"Flow with ID {flow_id} not found",
                },
            )

        # Extract features for prediction
        features = extract_flow_features(flow)
        if features is None:
            return JSONResponse(
                status_code=400,
                content={
                    "status": "error",
                    "message": "Could not extract features from flow",
                },
            )

        # Make prediction
        try:
            # Ensure features is a 2D array for prediction
            features_2d = features.reshape(1, -1)
            prediction = model.predict(features_2d)[0]
            
            # Convert numpy.bool_ to Python native bool
            is_malicious = bool(prediction)
            
            # Get feature importance
            feature_importance = model.feature_importances_
            feature_names = [
                "packet_count",
                "ip_entropy",
                "avg_pkt_size",
                "unique_protocols",
                "pkt_iat_var",
            ]
            feature_importance_dict = dict(zip(feature_names, feature_importance.tolist()))
            
            return {
                "prediction": {
                    "is_malicious": is_malicious,
                    "features": features.tolist(),
                    "feature_importance": feature_importance_dict,
                }
            }
        except Exception as e:
            print(f"Error making prediction: {str(e)}")
            import traceback
            traceback.print_exc()
            return JSONResponse(
                status_code=500,
                content={
                    "status": "error",
                    "message": f"Error making prediction: {str(e)}",
                },
            )
    except Exception as e:
        print(f"Error predicting flow: {str(e)}")
        import traceback
        traceback.print_exc()
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": f"Error predicting flow: {str(e)}",
            },
        )

@app.post("/reset_flows")
async def reset_flows():
    """Reset all flows"""
    try:
        # Reset flows
        global FLOWS
        FLOWS = []
        save_flows()
        
        return {
            "status": "success",
            "message": "All flows have been reset"
        }
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": f"Error resetting flows: {str(e)}"
            }
        )

# if __name__ == "__main__":
#     uvicorn.run(app, host="0.0.0.0", port=8000)

#uvicorn app:app --host 0.0.0.0 --port 8000 --reload