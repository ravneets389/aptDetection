from fastapi import FastAPI, File, UploadFile
import os
import uvicorn
import joblib
from capture_agent import start_tcpdump, stop_tcpdump
from file_processor import process_pcap, process_csv

app = FastAPI()
UPLOAD_FOLDER = "uploads/"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Load ML model
model_path = "models/mta_kdd_model.pkl"
model = joblib.load(model_path) if os.path.exists(model_path) else None

@app.get("/")
def home():
    return {"message": "APT Detection API is running"}

# Start Packet Capture
@app.get("/start_capture/")
def start_capture():
    return start_tcpdump()

# Stop Packet Capture
@app.get("/stop_capture/")
def stop_capture():
    return stop_tcpdump()

# File Upload & Processing
@app.post("/upload/")
async def upload_file(file: UploadFile = File(...)):
    file_path = os.path.join(UPLOAD_FOLDER, file.filename)
    
    # Save file
    with open(file_path, "wb") as f:
        f.write(await file.read())

    # Process based on file type
    if file.filename.endswith(".pcap"):
        features = process_pcap(file_path)
    elif file.filename.endswith(".csv"):
        features = process_csv(file_path)
    else:
        return {"error": "Invalid file format. Upload .pcap or .csv"}

    # Make prediction using ML model
    prediction = model.predict([features]) if model else "Model not loaded"

    return {"prediction": int(prediction), "features": features.tolist()}
