from fastapi import FastAPI, File, UploadFile, HTTPException
import os
import uvicorn
import joblib
import glob  
from capture_agent import start_tcpdump, stop_tcpdump, CAPTURE_FILE  # ✅ Use absolute imports
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
capture_file = None
capture_start_time = None

# Load the trained model and feature names
try:
    model_path = os.path.join(os.path.dirname(__file__), "../models/network_traffic_model.pkl")
    feature_names_path = os.path.join(os.path.dirname(__file__), "../models/feature_names.txt")
    
    if os.path.exists(model_path):
        model = joblib.load(model_path)
        print(f"Loaded model from {model_path}")
        
        # Load feature names
        if os.path.exists(feature_names_path):
            with open(feature_names_path, 'r') as f:
                feature_names = f.read().splitlines()
            print(f"Loaded {len(feature_names)} feature names")
        else:
            print(f"Warning: Feature names file not found at {feature_names_path}")
            feature_names = None
    else:
        print(f"Warning: Model file not found at {model_path}")
        model = None
except Exception as e:
    print(f"Error loading model: {str(e)}")
    model = None
    feature_names = None

app = FastAPI()
CAPTURES_FOLDER = "../uploads/"
os.makedirs(CAPTURES_FOLDER, exist_ok=True)

# Allow frontend requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://172.21.214.198:3000"],  # Adjust this to your frontend URL
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods
    allow_headers=["*"],  # Allow all headers
)

@app.get("/")
async def root():
    """Root endpoint"""
    return {"message": "APT Detection API"}

# Start Packet Capture
@app.post("/start_capture")
async def start_capture():
    """Start capturing packets"""
    global is_capturing, capture_file, capture_start_time
    
    if is_capturing:
        return JSONResponse(
            status_code=400,
            content={
                "status": "error",
                "message": "Capture is already running"
            }
        )
    
    try:
        # Start the capture using the existing function
        result = start_tcpdump()
        
        if "error" in result:
            return JSONResponse(
                status_code=500,
                content={
                    "status": "error",
                    "message": result["error"]
                }
            )
            
        # Update global variables
        is_capturing = True
        capture_start_time = time.time()
        capture_file = CAPTURE_FILE
        
        return {
            "status": "success",
            "message": result["message"],
            "capture_file": capture_file
        }
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
    global is_capturing, capture_file, capture_start_time
    
    if not is_capturing:
        return JSONResponse(
            status_code=400,
            content={
                "status": "error",
                "message": "No capture is running"
            }
        )
    
    try:
        # Stop the capture using the existing function
        result = stop_tcpdump()
        
        if "error" in result:
            return JSONResponse(
                status_code=500,
                content={
                    "status": "error",
                    "message": result["error"]
                }
            )
            
        # Update global variables
        is_capturing = False
        
        # Extract flows from the capture file
        flows = extract_flows(capture_file)
        
        if not flows:
            return JSONResponse(
                status_code=404,
                content={
                    "status": "error",
                    "message": "No flows could be extracted from the capture file"
                }
            )
            
        return {
            "status": "success",
            "message": result["message"],
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
    """Find the latest .pcap or .csv file in the captures folder."""
    files = sorted(glob.glob(os.path.join("../captures", "*.pcap")) + glob.glob(os.path.join("../captures", "*.csv")), key=os.path.getmtime, reverse=True)
    return files[0] if files else None

@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    """Upload a PCAP file"""
    try:
        # Create captures directory if it doesn't exist
        os.makedirs("../captures", exist_ok=True)
        
        # Generate a unique filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"../captures/uploaded_{timestamp}_{file.filename}"
        
        # Save the file
        with open(filename, "wb") as f:
            content = await file.read()
            f.write(content)
            
        # Check file size
        file_size = os.path.getsize(filename)
        if file_size == 0:
            return JSONResponse(
                status_code=400,
                content={
                    "status": "error",
                    "message": "The uploaded file is empty"
                }
            )
            
        # Extract flows from the file
        flows = extract_flows(filename)
        
        if not flows:
            return JSONResponse(
                status_code=404,
                content={
                    "status": "error",
                    "message": "No flows could be extracted from the file. This might be due to no network traffic in the file or the file format being incompatible."
                }
            )
            
        # Calculate statistics
        total_packets = sum(flow.get("packet_count", 0) for flow in flows)
        total_bytes = sum(flow.get("byte_count", 0) for flow in flows)
        unique_ips = set()
        unique_protocols = set()
        
        for flow in flows:
            unique_ips.add(flow.get("source_ip"))
            unique_ips.add(flow.get("dest_ip"))
            unique_protocols.add(flow.get("protocol"))
            
            # Extract features for prediction if model is available
            if model:
                features = extract_flow_features(flow)
                if features is not None:
                    try:
                        # Make prediction
                        prediction = model.predict([features])[0]
                        prediction_proba = model.predict_proba([features])[0]
                        
                        # Add prediction to flow
                        flow["prediction"] = int(prediction)
                        flow["prediction_probability"] = float(max(prediction_proba))
                    except Exception as pred_error:
                        print(f"Error making prediction: {str(pred_error)}")
                        flow["prediction"] = None
                        flow["prediction_probability"] = None
        
        # Remove packet data to reduce payload size
        for flow in flows:
            if "packets" in flow:
                del flow["packets"]
        
        # Calculate statistics
        stats = {
            "total_flows": len(flows),
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "unique_ips": len(unique_ips),
            "unique_protocols": len(unique_protocols),
            "avg_packets_per_flow": total_packets / len(flows) if flows else 0,
            "avg_bytes_per_flow": total_bytes / len(flows) if flows else 0,
            "malicious_flows": sum(1 for flow in flows if flow.get("prediction") == 1),
            "benign_flows": sum(1 for flow in flows if flow.get("prediction") == 0),
            "unknown_flows": sum(1 for flow in flows if flow.get("prediction") is None)
        }
        
        return {
            "status": "success",
            "message": f"File uploaded and analyzed successfully",
            "filename": filename,
            "file_size": file_size,
            "statistics": stats,
            "flows": flows
        }
    except Exception as e:
        print(f"Error uploading file: {str(e)}")
        import traceback
        traceback.print_exc()
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
                'frame.time', 'frame.len', 'frame.protocols',
                'eth.src', 'eth.dst',
                'ip.dst', 'ip.src', 'ip.flags', 'ip.ttl', 'ip.proto', 'ip.checksum', 'ip.tos',
                'tcp.srcport', 'tcp.dstport', 'tcp.flags', 'tcp.window_size_value',
                'tcp.window_size_scalefactor', 'tcp.checksum', 'tcp.options', 'tcp.pdu.size',
                'udp.srcport', 'udp.dstport'
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

def capture_packets():
    """Capture packets and save them to a PCAP file"""
    global is_capturing, capture_file, capture_start_time
    
    try:
        # Create captures directory if it doesn't exist
        os.makedirs("../captures", exist_ok=True)
        
        # Generate a unique filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        capture_file = f"../captures/capture_{timestamp}.pcap"
        
        # Start capturing packets
        result = start_tcpdump()
        
        if "error" in result:
            return JSONResponse(
                status_code=500,
                content={
                    "status": "error",
                    "message": result["error"]
                }
            )
            
        # Update global variables
        is_capturing = True
        capture_start_time = time.time()
        
        print(f"Starting capture on interface: {interface}")
        print(f"Capture file: {capture_file}")
        
        # Extract flows from the capture file
        flows = extract_flows(capture_file)
        
        if not flows:
            return JSONResponse(
                status_code=404,
                content={
                    "status": "error",
                    "message": "No flows could be extracted from the capture file"
                }
            )
            
        return {
            "status": "success",
            "message": result["message"],
            "capture_file": capture_file,
            "flows": flows
        }
    except Exception as e:
        print(f"Error in capture_packets: {str(e)}")
        import traceback
        traceback.print_exc()
        is_capturing = False

# if __name__ == "__main__":
#     uvicorn.run(app, host="0.0.0.0", port=8000)

#uvicorn app:app --host 0.0.0.0 --port 8000 --reload