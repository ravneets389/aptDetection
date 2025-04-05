import React, { useState, useEffect } from "react";
import {
  Play,
  Square,
  BarChart,
  AlertTriangle,
  CheckCircle,
} from "lucide-react";
import "./App.css";

// Define simple UI components
const Card = ({ children, className }) => (
  <div className={`card ${className || ""}`}>{children}</div>
);

const CardHeader = ({ title, subheader }) => (
  <div className="card-header">
    <h2>{title}</h2>
    {subheader && <p>{subheader}</p>}
  </div>
);

const CardContent = ({ children }) => (
  <div className="card-content">{children}</div>
);

const Button = ({ children, variant, disabled, onClick, className }) => {
  return (
    <button
      disabled={disabled}
      onClick={onClick}
      className={`button ${variant || "primary"} ${className || ""}`}
    >
      {children}
    </button>
  );
};

const Typography = ({ children, variant, className }) => {
  return (
    <div className={`typography ${variant || "body"} ${className || ""}`}>
      {children}
    </div>
  );
};

const Box = ({ children, className }) => (
  <div className={`box ${className || ""}`}>{children}</div>
);

const Paper = ({ children, className }) => (
  <div className={`paper ${className || ""}`}>{children}</div>
);

const CircularProgress = ({ value, size, thickness, color }) => (
  <div
    className="circular-progress"
    style={{
      width: `${size}px`,
      height: `${size}px`,
      borderWidth: `${thickness}px`,
      borderColor: color,
    }}
  >
    <div
      className="progress-circle"
      style={{
        width: `${value}%`,
        backgroundColor: color,
      }}
    ></div>
  </div>
);

const App = () => {
  const [isRunning, setIsRunning] = useState(false);
  const [apiData, setApiData] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [progress, setProgress] = useState(0);

  // Mock data for demonstration
  useEffect(() => {
    setApiData({
      duration: 124,
      status: "Completed",
      message: "Ready to capture packets...",
    });
  }, []);

  // Animation effect for circular progress
  useEffect(() => {
    let timer;
    if (isRunning) {
      timer = setInterval(() => {
        setProgress((prevProgress) =>
          prevProgress >= 100 ? 0 : prevProgress + 5
        );
      }, 200);
    } else {
      setProgress(0);
    }

    return () => {
      clearInterval(timer);
    };
  }, [isRunning]);

  // API calls
  const handleStart = async () => {
    setIsLoading(true);
    try {
      const response = await fetch("http://localhost:8000/start_capture", {
        method: "GET",
        headers: {
          "Content-Type": "application/json",
        },
      });
      const data = await response.json();
      console.log(data);
      setApiData(data);
      setIsRunning(true);
    } catch (error) {
      console.error("Start API error:", error);
    } finally {
      setIsLoading(false);
    }
  };

  const handleStop = async () => {
    setIsLoading(true);
    try {
      const response = await fetch("http://localhost:8000/stop_capture", {
        method: "GET",
        headers: {
          "Content-Type": "application/json",
        },
      });
      if (!response.ok) throw new Error("Network response was not ok");
      const data = await response.json();
      setApiData(data);
      console.log(data);
      setIsRunning(false);
    } catch (error) {
      console.error("Stop/Data API error:", error);
    } finally {
      setIsLoading(false);
    }
  };

  const handlePredict = async () => {
    setIsLoading(true);
    try {
      const prediction = await fetch("http://localhost:8000/predict", {
        method: "GET",
        headers: {
          "Content-Type": "application/json",
        },
      });
      if (!prediction.ok) throw new Error("Network response was not ok");
      const prediction_data = await prediction.json();
      setApiData(prediction_data);
      console.log(prediction_data);
    } catch (error) {
      console.error("Stop/Data API error:", error);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="app-container">
      <Card className="main-card">
        <CardHeader
          title="APT Detection System"
          subheader="Monitor and analyze network traffic for advanced persistent threats"
        />

        <CardContent>
          {/* Status Indicator */}
          <div className="status-indicator">
            <div
              className={`status-dot ${isRunning ? "running" : "stopped"}`}
            ></div>
            <span>{isRunning ? "Capture Active" : "Capture Inactive"}</span>
          </div>

          {/* Progress Circle */}
          <div className="progress-container">
            <div className="progress-circle-container">
              <CircularProgress
                value={progress}
                size={120}
                thickness={4}
                color={isRunning ? "#4caf50" : "#f44336"}
              />
              <div className="progress-icon">
                <BarChart
                  size={48}
                  style={{
                    color: isRunning ? "#4caf50" : "#f44336",
                  }}
                />
              </div>
            </div>
          </div>

          {/* Control Buttons */}
          <div className="button-container">
            <Button
              variant="success"
              disabled={isRunning || isLoading}
              onClick={handleStart}
              className="start-button"
            >
              <Play size={20} />
              Start Capture
            </Button>

            {!isRunning && apiData && (
              <Button
                variant="warning"
                disabled={isLoading}
                onClick={handlePredict}
                className="predict-button"
              >
                Predict
              </Button>
            )}

            <Button
              variant="error"
              disabled={!isRunning || isLoading}
              onClick={handleStop}
              className="stop-button"
            >
              <Square size={20} />
              Stop Capture
            </Button>
          </div>

          {/* Results Panel */}
          {apiData && (
            <div className="results-panel">
              <h3>Analysis Results</h3>

              {apiData.prediction && (
                <div
                  className={`prediction-badge ${
                    apiData.prediction === "Malicious" ? "malicious" : "genuine"
                  }`}
                >
                  {apiData.prediction === "Malicious" ? (
                    <AlertTriangle size={20} />
                  ) : (
                    <CheckCircle size={20} />
                  )}
                  <span>{apiData.prediction}</span>
                </div>
              )}

              <div className="message-box">
                <p>{apiData.message || "No message available"}</p>
              </div>

              {apiData.features && (
                <div className="features-grid">
                  <div className="feature-item">
                    <span className="feature-label">Packet Count</span>
                    <span className="feature-value">{apiData.features[0]}</span>
                  </div>
                  <div className="feature-item">
                    <span className="feature-label">IP Entropy</span>
                    <span className="feature-value">
                      {apiData.features[1].toFixed(2)}
                    </span>
                  </div>
                  <div className="feature-item">
                    <span className="feature-label">Avg Packet Size</span>
                    <span className="feature-value">
                      {apiData.features[2].toFixed(2)}
                    </span>
                  </div>
                  <div className="feature-item">
                    <span className="feature-label">Unique Protocols</span>
                    <span className="feature-value">{apiData.features[3]}</span>
                  </div>
                  <div className="feature-item">
                    <span className="feature-label">Packet IAT Variance</span>
                    <span className="feature-value">
                      {apiData.features[4].toFixed(2)}
                    </span>
                  </div>
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

export default App;
