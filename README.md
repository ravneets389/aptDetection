# Network Traffic Analysis System

This system analyzes network traffic for potential malicious activity using machine learning. It can process both live captures and uploaded PCAP files.

## Features

- Live packet capture
- PCAP file upload and analysis
- Flow extraction and analysis
- Machine learning-based traffic classification
- Real-time predictions
- Feature importance analysis

## Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Train the model:
```bash
cd models
python train_model.py
```

3. Start the backend server:
```bash
cd backend
uvicorn app:app --reload
```

4. Start the frontend (in a separate terminal):
```bash
cd frontend
npm install
npm start
```

## Usage

1. **Live Capture**:
   - Click "Start Capture" to begin capturing network traffic
   - Click "Stop Capture" to stop and analyze the captured traffic

2. **File Upload**:
   - Click "Choose File" to select a PCAP file
   - Click "Upload" to upload and analyze the file

3. **Flow Analysis**:
   - Select a flow from the list to view its details
   - Click "Analyze Flow" to get predictions and feature importance

## Model Details

The system uses a Random Forest Classifier trained on 23 network traffic features:

### Frame Features
- frame.time
- frame.len
- frame.protocols

### Ethernet Features
- eth.src
- eth.dst

### IP Features
- ip.dst
- ip.src
- ip.flags
- ip.ttl
- ip.proto
- ip.checksum
- ip.tos

### TCP Features
- tcp.srcport
- tcp.dstport
- tcp.flags
- tcp.window_size_value
- tcp.window_size_scalefactor
- tcp.checksum
- tcp.options
- tcp.pdu.size

### UDP Features
- udp.srcport
- udp.dstport

## Directory Structure

```
.
├── backend/
│   ├── app.py
│   ├── capture_agent.py
│   ├── file_processor.py
│   └── flow_analyzer.py
├── frontend/
│   └── src/
│       └── App.js
├── models/
│   ├── train_model.py
│   ├── network_traffic_model.pkl
│   └── feature_names.txt
├── captures/
├── requirements.txt
└── README.md
```
