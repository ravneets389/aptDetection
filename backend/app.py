from fastapi import FastAPI, File, UploadFile
import os
import uvicorn
import joblib
import glob  
from backend.capture_agent import start_tcpdump, stop_tcpdump  # ✅ Use absolute imports
from backend.file_processor import process_pcap, process_csv  # ✅ Use absolute imports
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()
UPLOAD_FOLDER = "uploads/"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Allow frontend requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Adjust this to your frontend URL
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods
    allow_headers=["*"],  # Allow all headers
)

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

def get_latest_file():
    """Find the latest .pcap or .csv file in the uploads folder."""
    files = sorted(glob.glob(os.path.join(UPLOAD_FOLDER, "*.pcap")) + glob.glob(os.path.join(UPLOAD_FOLDER, "*.csv")), key=os.path.getmtime, reverse=True)
    return files[0] if files else None

@app.get("/predict/")
async def process_latest_file():
    latest_file = get_latest_file()
    if not latest_file:
        return {"error": "No .pcap or .csv files found in uploads/"}

    # Process based on file type
    if latest_file.endswith(".pcap"):
        features = process_pcap(latest_file)
    elif latest_file.endswith(".csv"):
        features = process_csv(latest_file)
    else:
        return {"error": "Unexpected file format"}

    print("Extracted features:", features)
    print("Feature vector length:", len(features))

    # Make prediction using ML model
    prediction = model.predict([features]) if model else "Model not loaded"

    return {
        "file": latest_file,
        "prediction": "Malicious" if int(prediction) == 1 else "Genuine",
        "features": features.tolist()
    }
