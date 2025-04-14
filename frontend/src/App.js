import React, { useState, useEffect } from "react";
import {
  Box,
  Typography,
  Button,
  Paper,
  CircularProgress,
  LinearProgress,
  Alert,
  IconButton,
  Tooltip,
} from "@mui/material";
import {
  PlayArrow,
  Stop,
  Upload,
  Refresh,
  CheckCircle,
  AlertTriangle,
  BarChart,
  CloudUpload,
  CloudDone,
  CloudOff,
  Speed,
  Security,
  NetworkCheck,
  Timeline,
  Memory,
  Storage,
  Router,
  WifiTethering,
  SignalWifi4Bar,
  SignalWifiOff,
  SignalWifiStatusbar4Bar,
  SignalWifiStatusbarNull,
  SignalWifi0Bar,
  SignalWifi1Bar,
  SignalWifi2Bar,
  SignalWifi3Bar,
  Warning,
} from "@mui/icons-material";
import axios from "axios";
import "./App.css";

// Define mock Material UI components since we don't have direct access to @mui
const Card = ({ children, sx }) => (
  <div
    style={{
      backgroundColor: sx?.background || "white",
      borderRadius: sx?.borderRadius || "4px",
      boxShadow: sx?.boxShadow || "0 2px 4px rgba(0,0,0,0.1)",
      backdropFilter: sx?.backdropFilter,
      width: sx?.maxWidth ? `${sx.maxWidth}px` : "100%",
      margin: "0 auto",
    }}
    className="mui-card"
  >
    {children}
  </div>
);

const CardHeader = ({ title, subheader, sx }) => (
  <div
    style={{
      padding: "16px 16px 0 16px",
      textAlign: sx?.textAlign || "left",
    }}
    className="mui-card-header"
  >
    <h2 style={{ color: sx?.color || "inherit", margin: "0 0 8px 0" }}>
      {title}
    </h2>
    {subheader && (
      <p
        style={{
          color: sx?.["& .MuiCardHeader-subheader"]?.color || "rgba(0,0,0,0.6)",
          margin: 0,
        }}
      >
        {subheader}
      </p>
    )}
  </div>
);

const CardContent = ({ children }) => (
  <div style={{ padding: "16px" }} className="mui-card-content">
    {children}
  </div>
);

const Grid = ({ container, item, spacing, xs, children }) => {
  if (container) {
    return (
      <div
        style={{
          display: "flex",
          flexWrap: "wrap",
          margin: spacing ? `-${spacing * 4}px` : "0",
        }}
      >
        {children}
      </div>
    );
  }

  if (item) {
    return (
      <div
        style={{
          padding: spacing ? `${spacing * 4}px` : "0",
          flex: xs === 6 ? "0 0 50%" : xs === 12 ? "0 0 100%" : "auto",
          boxSizing: "border-box",
        }}
      >
        {children}
      </div>
    );
  }

  return <div>{children}</div>;
};

const App = () => {
  const [isRunning, setIsRunning] = useState(false);
  const [apiData, setApiData] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [selectedFile, setSelectedFile] = useState(null);
  const [uploadMessage, setUploadMessage] = useState("");
  const [showUploadMessage, setShowUploadMessage] = useState(false);
  // New state for flow analysis
  const [flows, setFlows] = useState([]);
  const [activeFlow, setActiveFlow] = useState(null);
  const [flowError, setFlowError] = useState(null);
  const [flowErrorList, setFlowErrorList] = useState([]);
  const [isPredicting, setIsPredicting] = useState(false);
  const [flowAnalysisInterval, setFlowAnalysisInterval] = useState(null);

  const handleFileChange = (event) => {
    setSelectedFile(event.target.files[0]);
    setShowUploadMessage(false); // Reset upload message when a new file is selected
  };

  const handleUpload = async () => {
    if (!selectedFile) {
      alert("Please select a file first.");
      return;
    }

    const formData = new FormData();
    formData.append("file", selectedFile);

    try {
      const response = await fetch("http://localhost:8000/upload/", {
        method: "POST",
        body: formData,
      });

      const result = await response.json();
      setUploadMessage(result.message);
      setShowUploadMessage(true);

      // Auto-hide the message after 5 seconds
      setTimeout(() => {
        setShowUploadMessage(false);
      }, 5000);
    } catch (error) {
      console.error("Error uploading file:", error);
      setUploadMessage("Failed to upload file.");
      setShowUploadMessage(true);
    }
  };

  // Mock data for demonstration
  useEffect(() => {
    setApiData({
      duration: 124,
      status: "Completed",
      message: "Ready to capture packects ...",
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

  // New function to analyze flows
  const analyzeFlows = async () => {
    try {
      console.log("Analyzing flows...");
      setFlowError(null); // Clear any previous errors
      setIsPredicting(true); // Show prediction status for all flows

      const response = await fetch("http://localhost:8000/analyze_flows", {
        method: "GET",
        headers: {
          "Content-Type": "application/json",
        },
      });

      const data = await response.json();
      console.log("Flow analysis response:", data);

      if (!response.ok) {
        console.error("Flow analysis error response:", data);
        throw new Error(data.message || "Failed to analyze flows");
      }

      // Update flows state with new data, ensuring it's always an array
      const flows = Array.isArray(data?.flows) ? data.flows : [];
      setFlows(flows);

      if (flows.length === 0) {
        // No flows found
        setFlowError("No flows were found. This might be because:");
        setFlowErrorList([
          "No network traffic was captured",
          "The capture file is empty or corrupted",
          "The file format is not compatible",
        ]);
        setActiveFlow(null);
      } else {
        // Clear any error messages
        setFlowError(null);
        setFlowErrorList([]);

        // If we have flows but no active flow, set the first one as active
        if (!activeFlow) {
          setActiveFlow(flows[0]?.id || null);
        }

        // Predict all flows
        const predictedFlows = await Promise.all(
          flows.map(async (flow) => {
            try {
              const predResponse = await fetch(
                `http://localhost:8000/predict_flow/${flow.id}`
              );
              const predData = await predResponse.json();

              if (!predResponse.ok) {
                console.error(`Error predicting flow ${flow.id}:`, predData);
                return flow;
              }

              return {
                ...flow,
                prediction: predData.prediction?.is_malicious
                  ? "Malicious"
                  : "Genuine",
                features: predData.prediction?.features || [],
                featureImportance: predData.prediction?.feature_importance || {},
              };
            } catch (error) {
              console.error(`Error predicting flow ${flow.id}:`, error);
              return flow;
            }
          })
        );

        // Update flows with predictions
        setFlows(predictedFlows);
      }
    } catch (error) {
      console.error("Flow analysis error:", error);
      // Show error message to user
      setFlowError(
        `Flow analysis error: ${
          error.message ||
          "Failed to analyze flows. Please check if the backend server is running."
        }`
      );
      setFlowErrorList([]);
      setShowUploadMessage(true);
    } finally {
      setIsPredicting(false); // Reset prediction status
    }
  };

  // Function to start capture
  const handleStart = async () => {
    if (isRunning) {
      console.log("Capture is already running");
      return;
    }

    try {
      console.log("Starting capture...");
      const response = await fetch("http://localhost:8000/start_capture", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
      });

      const data = await response.json();
      console.log("Start capture response:", data);

      if (!response.ok) {
        console.error("Error starting capture:", data);
        setUploadMessage(
          `Error starting capture: ${data.message || "Unknown error"}`
        );
        setShowUploadMessage(true);
        return;
      }

      // Update state
      setIsRunning(true);
      setUploadMessage("Capture started");
      setShowUploadMessage(true);

      // Start periodic flow analysis
      const interval = setInterval(analyzeFlows, 5000); // Every 5 seconds
      setFlowAnalysisInterval(interval);

      // Do an initial flow analysis
      await analyzeFlows();
    } catch (error) {
      console.error("Error starting capture:", error);
      setUploadMessage(
        `Error starting capture: ${
          error.message || "Failed to start capture. Please try again."
        }`
      );
      setShowUploadMessage(true);
    }
  };

  // Modified handleStop to check if capture is running
  const handleStop = async () => {
    if (!isRunning) {
      console.log("No capture is currently running");
      return;
    }

    setIsLoading(true);
    try {
      const response = await fetch("http://localhost:8000/stop_capture", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || "Failed to stop capture");
      }

      const data = await response.json();
      setApiData(data || {});
      console.log("Stop capture response:", data);
      setIsRunning(false);

      // Clear flow analysis interval
      if (flowAnalysisInterval) {
        clearInterval(flowAnalysisInterval);
        setFlowAnalysisInterval(null);
      }
    } catch (error) {
      console.error("Stop capture error:", error);
      setUploadMessage(error.message || "Failed to stop capture");
      setShowUploadMessage(true);
    } finally {
      setIsLoading(false);
    }
  };

  // Function to predict a specific flow
  const predictFlow = async (flowId) => {
    if (!flowId) {
      setFlowError("No flow selected. Please select a flow to analyze.");
      return;
    }

    setIsPredicting(true);
    setFlowError(null);

    try {
      // Instead of predicting just one flow, we'll analyze all flows
      await analyzeFlows();
    } catch (error) {
      console.error("Error predicting flow:", error);
      setFlowError("Failed to predict flow. Please try again.");
    } finally {
      setIsPredicting(false);
    }
  };

  // Function to handle flow selection
  const handleFlowSelect = (flowId) => {
    setActiveFlow(flowId);
    setFlowError(null);
  };

  // Clean up interval on component unmount
  useEffect(() => {
    return () => {
      if (flowAnalysisInterval) {
        clearInterval(flowAnalysisInterval);
      }
    };
  }, [flowAnalysisInterval]);

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

  const handleFileUpload = async () => {
    if (!selectedFile) {
      alert("Please select a file to upload.");
      return;
    }

    setIsLoading(true);
    const formData = new FormData();
    formData.append("file", selectedFile);

    try {
      const response = await fetch("http://localhost:8000/upload", {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        throw new Error("Failed to upload file");
      }

      const result = await response.json();
      setUploadMessage(result.message || "File uploaded successfully!");
      setShowUploadMessage(true);
      
      // Update flows with the data from the upload response
      if (result.flows && Array.isArray(result.flows)) {
        setFlows(result.flows);
        
        // If we have flows but no active flow, set the first one as active
        if (!activeFlow && result.flows.length > 0) {
          setActiveFlow(result.flows[0]?.id || null);
        }
        
        // Clear any error messages
        setFlowError(null);
        setFlowErrorList([]);
        
        // Update API data with statistics if available
        if (result.statistics) {
          setApiData(prevData => ({
            ...prevData,
            ...result.statistics,
            filename: result.filename,
            file_size: result.file_size
          }));
        }
      } else {
        // If no flows in the response, fetch them separately
        await analyzeFlows();
      }

      // Auto-hide the message after 5 seconds
      setTimeout(() => {
        setShowUploadMessage(false);
      }, 5000);
    } catch (error) {
      console.error("File upload error:", error);
      setUploadMessage("Error uploading file.");
      setShowUploadMessage(true);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Box
      sx={{
        minHeight: "100vh",
        display: "flex",
        justifyContent: "center",
        alignItems: "center",
        background: "#f5f7fa",
        padding: "2rem",
      }}
    >
      <Box
        sx={{
          display: "flex",
          maxWidth: "1200px",
          width: "100%",
          background: "white",
          borderRadius: "12px",
          boxShadow: "0 4px 20px rgba(0, 0, 0, 0.08)",
          overflow: "hidden",
        }}
      >
        {/* Sidebar */}
        <Box
          sx={{
            width: "280px",
            background: "white",
            borderRight: "1px solid #eaeaea",
            display: "flex",
            flexDirection: "column",
            zIndex: 10,
          }}
        >
          <Box
            sx={{
              p: 3,
              borderBottom: "1px solid #eaeaea",
              display: "flex",
              alignItems: "center",
              gap: 2,
            }}
          >
            <BarChart size={24} style={{ color: "#3f51b5" }} />
            <Typography variant="h6" sx={{ fontWeight: "bold", color: "#333" }}>
              APT Detection
            </Typography>
          </Box>

          <Box sx={{ p: 3, flex: 1 }}>
            {/* Status Indicators */}
            <Paper
              sx={{
                p: 2,
                mb: 3,
                background: "white",
                color: "#333",
                borderRadius: 8,
                border: "1px solid #eaeaea",
              }}
            >
              <Typography
                variant="subtitle2"
                sx={{ mb: 2, fontWeight: "bold", color: "#333" }}
              >
                System Status
              </Typography>

              <Box sx={{ display: "flex", alignItems: "center", mb: 1 }}>
                <div
                  style={{
                    width: "10px",
                    height: "10px",
                    borderRadius: "50%",
                    backgroundColor: isRunning ? "#4caf50" : "#f44336",
                    marginRight: "8px",
                    boxShadow: isRunning
                      ? "0 0 0 3px rgba(76, 175, 80, 0.2)"
                      : "0 0 0 3px rgba(244, 67, 54, 0.2)",
                  }}
                />
                <Typography variant="body2">
                  Status: {isRunning ? "Running" : "Stopped"}
                </Typography>
              </Box>

              <Box sx={{ display: "flex", alignItems: "center" }}>
                <div
                  style={{
                    width: "10px",
                    height: "10px",
                    borderRadius: "50%",
                    backgroundColor: isLoading ? "#ff9800" : "#2196f3",
                    marginRight: "8px",
                    boxShadow: isLoading
                      ? "0 0 0 3px rgba(255, 152, 0, 0.2)"
                      : "0 0 0 3px rgba(33, 150, 243, 0.2)",
                    animation: isLoading
                      ? "pulse 1.5s infinite ease-in-out"
                      : "none",
                  }}
                />
                <Typography variant="body2">
                  {isLoading ? "Processing..." : "Ready"}
                </Typography>
              </Box>
            </Paper>

            {/* Control Buttons */}
            <Paper
              sx={{
                p: 2,
                mb: 3,
                background: "white",
                borderRadius: 8,
                border: "1px solid #eaeaea",
              }}
            >
              <Typography
                variant="subtitle2"
                sx={{ mb: 2, fontWeight: "bold", color: "#333" }}
              >
                Controls
              </Typography>

              <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
                <Button
                  variant="contained"
                  color="success"
                  disabled={isRunning || isLoading}
                  onClick={handleStart}
                  sx={{
                    py: 1,
                    px: 2,
                    fontWeight: "medium",
                    boxShadow: "0 2px 4px rgba(76, 175, 80, 0.2)",
                    borderRadius: 6,
                    background: "#4caf50",
                    "&:hover": {
                      background: "#43a047",
                      boxShadow: "0 4px 8px rgba(76, 175, 80, 0.3)",
                    },
                    "&.Mui-disabled": {
                      backgroundColor: "#e0e0e0",
                      boxShadow: "none",
                    },
                  }}
                >
                  <PlayArrow size={16} style={{ marginRight: "8px" }} />
                  Start Capture
                </Button>

                {!isRunning && apiData && (
                  <Button
                    variant="contained"
                    color="primary"
                    disabled={isLoading}
                    onClick={handlePredict}
                    sx={{
                      py: 1,
                      px: 2,
                      fontWeight: "medium",
                      boxShadow: "0 2px 4px rgba(33, 150, 243, 0.2)",
                      backgroundColor: "#2196f3",
                      borderRadius: 6,
                      "&:hover": {
                        backgroundColor: "#1976d2",
                        boxShadow: "0 4px 8px rgba(33, 150, 243, 0.3)",
                      },
                      "&.Mui-disabled": {
                        backgroundColor: "#e0e0e0",
                        boxShadow: "none",
                      },
                    }}
                  >
                    Predict
                  </Button>
                )}

                <Button
                  variant="contained"
                  color="error"
                  disabled={!isRunning || isLoading}
                  onClick={handleStop}
                  sx={{
                    py: 1,
                    px: 2,
                    fontWeight: "medium",
                    boxShadow: "0 2px 4px rgba(244, 67, 54, 0.2)",
                    borderRadius: 6,
                    background: "#f44336",
                    "&:hover": {
                      background: "#e53935",
                      boxShadow: "0 4px 8px rgba(244, 67, 54, 0.3)",
                    },
                    "&.Mui-disabled": {
                      backgroundColor: "#e0e0e0",
                      boxShadow: "none",
                    },
                  }}
                >
                  <Stop size={16} style={{ marginRight: "8px" }} />
                  Stop Capture
                </Button>
              </Box>
            </Paper>

            {/* File Upload Section */}
            <Paper
              sx={{
                p: 2,
                background: "white",
                borderRadius: 8,
                border: "1px solid #eaeaea",
              }}
            >
              <Typography
                variant="subtitle2"
                sx={{ mb: 2, fontWeight: "bold", color: "#333" }}
              >
                Upload Network Capture
              </Typography>

              <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
                <input
                  type="file"
                  onChange={handleFileChange}
                  style={{
                    display: "block",
                    padding: "8px",
                    borderRadius: "6px",
                    border: "1px solid #eaeaea",
                    backgroundColor: "white",
                    color: "#333",
                    width: "100%",
                    cursor: "pointer",
                    fontSize: "0.875rem",
                  }}
                />

                <Button
                  variant="contained"
                  color="primary"
                  disabled={!selectedFile || isLoading}
                  onClick={handleFileUpload}
                  sx={{
                    py: 1,
                    px: 2,
                    fontWeight: "medium",
                    boxShadow: "0 2px 4px rgba(76, 175, 80, 0.2)",
                    backgroundColor: "#4caf50",
                    borderRadius: 6,
                    "&:hover": {
                      backgroundColor: "#43a047",
                      boxShadow: "0 4px 8px rgba(76, 175, 80, 0.3)",
                    },
                    "&.Mui-disabled": {
                      backgroundColor: "#e0e0e0",
                      boxShadow: "none",
                    },
                  }}
                >
                  Upload File
                </Button>
              </Box>
            </Paper>

            {/* Upload Feedback Message */}
            {showUploadMessage && (
              <Paper
                sx={{
                  p: 1.5,
                  mt: 2,
                  background: uploadMessage.includes("successfully")
                    ? "rgba(76, 175, 80, 0.1)"
                    : "rgba(244, 67, 54, 0.1)",
                  color: uploadMessage.includes("successfully")
                    ? "#2e7d32"
                    : "#d32f2f",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  animation: "fadeIn 0.5s ease-in-out",
                  borderRadius: 6,
                  border: uploadMessage.includes("successfully")
                    ? "1px solid rgba(76, 175, 80, 0.3)"
                    : "1px solid rgba(244, 67, 54, 0.3)",
                }}
              >
                <Box sx={{ display: "flex", alignItems: "center" }}>
                  {uploadMessage.includes("successfully") ? (
                    <CheckCircle size={16} style={{ marginRight: "8px" }} />
                  ) : (
                    <Warning size={16} style={{ marginRight: "8px" }} />
                  )}
                  <Typography variant="body2">{uploadMessage}</Typography>
                </Box>
                <Button
                  variant="text"
                  onClick={() => setShowUploadMessage(false)}
                  sx={{
                    color: "inherit",
                    p: 0,
                    minWidth: "auto",
                    "&:hover": {
                      background: "transparent",
                      opacity: 0.8,
                    },
                  }}
                >
                  <Refresh size={14} />
                </Button>
              </Paper>
            )}
          </Box>
        </Box>

        {/* Main Content */}
        <Box
          sx={{
            flex: 1,
            p: 4,
            display: "flex",
            flexDirection: "column",
            overflow: "auto",
          }}
        >
          <Box
            sx={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              mb: 4,
            }}
          >
            <Typography variant="h5" sx={{ fontWeight: "bold", color: "#333" }}>
              Network Traffic Analysis
            </Typography>

            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <CircularProgress
                variant="determinate"
                value={progress}
                size={40}
                thickness={4}
                sx={{
                  color: isRunning ? "#4caf50" : "#f44336",
                }}
              />
              <Typography variant="body2" sx={{ color: "#666" }}>
                {isRunning ? "Capturing..." : "Stopped"}
              </Typography>
            </Box>
          </Box>
          {/* Flow Analysis Section */}

          <Paper
            sx={{
              p: 3,
              background: "white",
              color: "#333",
              borderRadius: 8,
              border: "1px solid #eaeaea",
              boxShadow: "0 2px 8px rgba(0, 0, 0, 0.05)",
              mb: 3,
            }}
          >
            {/* Active Flow Details */}
            {activeFlow && (
              <Paper
                sx={{
                  p: 3,
                  background: "white",
                  borderRadius: 8,
                  border: "1px solid #eaeaea",
                  m: 2,
                }}
              >
                <Box
                  sx={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    mb: 2,
                  }}
                >
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                    <Box
                      sx={{
                        width: 40,
                        height: 40,
                        borderRadius: "50%",
                        backgroundColor: "rgba(33, 150, 243, 0.1)",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        color: "#2196f3",
                        fontWeight: "bold",
                        fontSize: "1rem",
                      }}
                    >
                      {flows
                        .find((f) => f?.id === activeFlow)
                        ?.id?.substring(0, 2) || "NA"}
                    </Box>
                    <Box>
                      <Typography
                        variant="subtitle1"
                        sx={{ fontWeight: "bold", color: "#333" }}
                      >
                        Flow Details
                      </Typography>
                      <Typography variant="body2" sx={{ color: "#666" }}>
                        {flows.find((f) => f?.id === activeFlow)?.source_ip ||
                          "N/A"}
                        :
                        {flows.find((f) => f?.id === activeFlow)?.source_port ||
                          "N/A"}{" "}
                        →
                        {flows.find((f) => f?.id === activeFlow)?.dest_ip ||
                          "N/A"}
                        :
                        {flows.find((f) => f?.id === activeFlow)?.dest_port ||
                          "N/A"}
                      </Typography>
                    </Box>
                  </Box>
                  <Button
                    variant="contained"
                    color="primary"
                    disabled={isPredicting}
                    onClick={() => predictFlow(activeFlow)}
                    sx={{
                      py: 0.5,
                      px: 1.5,
                      fontWeight: "medium",
                      boxShadow: "0 2px 4px rgba(33, 150, 243, 0.2)",
                      backgroundColor: "#2196f3",
                      borderRadius: 6,
                      "&:hover": {
                        backgroundColor: "#1976d2",
                        boxShadow: "0 4px 8px rgba(33, 150, 243, 0.3)",
                      },
                      "&.Mui-disabled": {
                        backgroundColor: "#e0e0e0",
                        boxShadow: "none",
                      },
                    }}
                  >
                    {isPredicting ? (
                      <CircularProgress size={20} color="inherit" />
                    ) : flows.find((f) => f?.id === activeFlow)?.prediction ? (
                      "Re-analyze"
                    ) : (
                      "Analyze Flow"
                    )}
                  </Button>
                </Box>

                {/* Prediction result display */}
                {flows.find((f) => f?.id === activeFlow)?.prediction && (
                  <Box
                    sx={{
                      display: "flex",
                      flexDirection: "column",
                      gap: 2,
                    }}
                  >
                    <Box sx={{ display: "flex", gap: 2 }}>
                      <Paper
                        sx={{
                          p: 2,
                          background: "white",
                          borderRadius: 8,
                          border: "1px solid #eaeaea",
                          flex: 1,
                        }}
                      >
                        <Typography
                          variant="subtitle2"
                          sx={{ color: "#666", mb: 1 }}
                        >
                          Prediction Result
                        </Typography>
                        <Box
                          sx={{
                            display: "flex",
                            alignItems: "center",
                            gap: 1,
                          }}
                        >
                          {flows.find((f) => f?.id === activeFlow)
                            ?.prediction === "Genuine" ? (
                            <CheckCircle sx={{ color: "#4caf50" }} />
                          ) : (
                            <Warning sx={{ color: "#f44336" }} />
                          )}
                          <Typography
                            variant="h6"
                            sx={{
                              color:
                                flows.find((f) => f?.id === activeFlow)
                                  ?.prediction === "Genuine"
                                  ? "#4caf50"
                                  : "#f44336",
                              fontWeight: "bold",
                            }}
                          >
                            {flows.find((f) => f?.id === activeFlow)
                              ?.prediction || "Unknown"}
                          </Typography>
                        </Box>
                      </Paper>
                    </Box>

                    {/* Feature Importance Display */}
                    {flows.find((f) => f?.id === activeFlow)
                      ?.featureImportance && (
                      <Paper
                        sx={{
                          p: 2,
                          background: "white",
                          borderRadius: 8,
                          border: "1px solid #eaeaea",
                        }}
                      >
                        <Typography
                          variant="subtitle2"
                          sx={{ color: "#666", mb: 2 }}
                        >
                          Feature Importance
                        </Typography>
                        <Box
                          sx={{
                            display: "flex",
                            flexDirection: "column",
                            gap: 1,
                          }}
                        >
                          {Object.entries(
                            flows.find((f) => f?.id === activeFlow)
                              ?.featureImportance || {}
                          ).map(([feature, importance]) => (
                            <Box
                              key={feature}
                              sx={{
                                display: "flex",
                                justifyContent: "space-between",
                                alignItems: "center",
                              }}
                            >
                              <Typography
                                variant="body2"
                                sx={{ color: "#333" }}
                              >
                                {feature
                                  .replace(/_/g, " ")
                                  .replace(/\b\w/g, (l) => l.toUpperCase())}
                              </Typography>
                              <Box
                                sx={{
                                  display: "flex",
                                  alignItems: "center",
                                  gap: 1,
                                  width: "60%",
                                }}
                              >
                                <LinearProgress
                                  variant="determinate"
                                  value={importance * 100}
                                  sx={{
                                    height: 8,
                                    borderRadius: 4,
                                    backgroundColor: "rgba(0, 0, 0, 0.1)",
                                    "& .MuiLinearProgress-bar": {
                                      backgroundColor: "#2196f3",
                                    },
                                  }}
                                />
                                <Typography
                                  variant="body2"
                                  sx={{ color: "#666", minWidth: "40px" }}
                                >
                                  {(importance * 100).toFixed(1)}%
                                </Typography>
                              </Box>
                            </Box>
                          ))}
                        </Box>
                      </Paper>
                    )}
                  </Box>
                )}
              </Paper>
            )}
            <Box
              sx={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                mb: 3,
              }}
            >
              <Typography
                variant="h6"
                sx={{ fontWeight: "bold", color: "#333" }}
              >
                Network Flows
              </Typography>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <Typography variant="body2" sx={{ color: "#666" }}>
                  {flows.length} {flows.length === 1 ? "Flow" : "Flows"}{" "}
                  Detected
                </Typography>
                <Box
                  sx={{
                    width: 8,
                    height: 8,
                    borderRadius: "50%",
                    backgroundColor: isRunning ? "#4caf50" : "#f44336",
                    animation: isRunning ? "pulse 1.5s infinite" : "none",
                    "@keyframes pulse": {
                      "0%": { opacity: 1 },
                      "50%": { opacity: 0.5 },
                      "100%": { opacity: 1 },
                    },
                  }}
                />
              </Box>
            </Box>

            {flowError && (
              <Alert severity="error" sx={{ mb: 2 }}>
                {flowError}
              </Alert>
            )}

            {flows.length > 0 ? (
              <Box sx={{ display: "flex", flexDirection: "column", gap: 2 }}>
                <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap" }}>
                  {flows.map((flow) => (
                    <Paper
                      key={flow.id}
                      sx={{
                        p: 2,
                        background:
                          activeFlow === flow.id
                            ? "rgba(33, 150, 243, 0.1)"
                            : "white",
                        borderRadius: 8,
                        border:
                          activeFlow === flow.id
                            ? "1px solid rgba(33, 150, 243, 0.3)"
                            : "1px solid #eaeaea",
                        cursor: "pointer",
                        transition: "all 0.2s ease",
                        flex: "1 1 300px",
                        position: "relative",
                        overflow: "hidden",
                        "&:hover": {
                          boxShadow: "0 4px 8px rgba(0, 0, 0, 0.1)",
                          transform: "translateY(-2px)",
                        },
                        "&::before": {
                          content: '""',
                          position: "absolute",
                          top: 0,
                          left: 0,
                          width: "4px",
                          height: "100%",
                          backgroundColor:
                            flow.prediction === "Genuine"
                              ? "#4caf50"
                              : flow.prediction === "Malicious"
                              ? "#f44336"
                              : "#9e9e9e",
                          opacity: flow.prediction ? 1 : 0.5,
                        },
                      }}
                      onClick={() => handleFlowSelect(flow.id)}
                    >
                      <Box
                        sx={{
                          display: "flex",
                          justifyContent: "space-between",
                          alignItems: "center",
                          mb: 1,
                        }}
                      >
                        <Box
                          sx={{ display: "flex", alignItems: "center", gap: 1 }}
                        >
                          <Box
                            sx={{
                              width: 24,
                              height: 24,
                              borderRadius: "50%",
                              backgroundColor: "rgba(33, 150, 243, 0.1)",
                              display: "flex",
                              alignItems: "center",
                              justifyContent: "center",
                              color: "#2196f3",
                              fontWeight: "bold",
                              fontSize: "0.75rem",
                            }}
                          >
                            {flow.id.substring(0, 2)}
                          </Box>
                          <Typography
                            variant="subtitle2"
                            sx={{ fontWeight: "bold", color: "#333" }}
                          >
                            Flow {flow.id}
                          </Typography>
                        </Box>
                        {flow.prediction && (
                          <Box
                            sx={{
                              px: 1,
                              py: 0.5,
                              borderRadius: 4,
                              fontSize: "0.75rem",
                              fontWeight: "bold",
                              backgroundColor:
                                flow.prediction === "Genuine"
                                  ? "rgba(76, 175, 80, 0.1)"
                                  : "rgba(244, 67, 54, 0.1)",
                              color:
                                flow.prediction === "Genuine"
                                  ? "#2e7d32"
                                  : "#d32f2f",
                              border:
                                flow.prediction === "Genuine"
                                  ? "1px solid rgba(76, 175, 80, 0.3)"
                                  : "1px solid rgba(244, 67, 54, 0.3)",
                              display: "flex",
                              alignItems: "center",
                              gap: 0.5,
                            }}
                          >
                            {flow.prediction === "Genuine" ? (
                              <CheckCircle size={14} />
                            ) : (
                              <Warning size={14} />
                            )}
                            {flow.prediction}
                          </Box>
                        )}
                      </Box>

                      <Box
                        sx={{
                          display: "flex",
                          flexDirection: "column",
                          gap: 0.5,
                        }}
                      >
                        <Box
                          sx={{ display: "flex", alignItems: "center", gap: 1 }}
                        >
                          <Box
                            sx={{
                              width: 8,
                              height: 8,
                              borderRadius: "50%",
                              backgroundColor: "#2196f3",
                            }}
                          />
                          <Typography
                            variant="body2"
                            sx={{ color: "#666", fontSize: "0.75rem" }}
                          >
                            {flow.source_ip}:{flow.source_port}
                          </Typography>
                        </Box>

                        <Box
                          sx={{ display: "flex", alignItems: "center", gap: 1 }}
                        >
                          <Box
                            sx={{
                              width: 8,
                              height: 8,
                              borderRadius: "50%",
                              backgroundColor: "#f44336",
                            }}
                          />
                          <Typography
                            variant="body2"
                            sx={{ color: "#666", fontSize: "0.75rem" }}
                          >
                            {flow.dest_ip}:{flow.dest_port}
                          </Typography>
                        </Box>
                      </Box>

                      <Box
                        sx={{
                          display: "flex",
                          justifyContent: "space-between",
                          mt: 1.5,
                          pt: 1.5,
                          borderTop: "1px dashed #eaeaea",
                        }}
                      >
                        <Box
                          sx={{
                            display: "flex",
                            flexDirection: "column",
                            alignItems: "center",
                          }}
                        >
                          <Typography variant="caption" sx={{ color: "#666" }}>
                            Packets
                          </Typography>
                          <Typography
                            variant="body2"
                            sx={{ fontWeight: "bold" }}
                          >
                            {flow.packet_count}
                          </Typography>
                        </Box>
                        <Box
                          sx={{
                            display: "flex",
                            flexDirection: "column",
                            alignItems: "center",
                          }}
                        >
                          <Typography variant="caption" sx={{ color: "#666" }}>
                            Bytes
                          </Typography>
                          <Typography
                            variant="body2"
                            sx={{ fontWeight: "bold" }}
                          >
                            {flow.byte_count}
                          </Typography>
                        </Box>
                        <Box
                          sx={{
                            display: "flex",
                            flexDirection: "column",
                            alignItems: "center",
                          }}
                        >
                          <Typography variant="caption" sx={{ color: "#666" }}>
                            Duration
                          </Typography>
                          <Typography
                            variant="body2"
                            sx={{ fontWeight: "bold" }}
                          >
                            {flow.duration
                              ? `${Math.round(flow.duration)}ms`
                              : "N/A"}
                          </Typography>
                        </Box>
                      </Box>
                    </Paper>
                  ))}
                </Box>
              </Box>
            ) : (
              <Box
                sx={{
                  display: "flex",
                  flexDirection: "column",
                  alignItems: "center",
                  justifyContent: "center",
                  py: 4,
                  opacity: 0.5,
                }}
              >
                <BarChart
                  size={48}
                  style={{ color: "#ccc", marginBottom: "16px" }}
                />
                <Typography color="#666">
                  {isRunning
                    ? "Capturing network traffic..."
                    : "Press Start to begin capturing network traffic"}
                </Typography>
              </Box>
            )}
          </Paper>

          {/* Original API Data Display - Now hidden when flows are available */}
          {apiData && flows.length === 0 && (
            <Paper
              sx={{
                p: 3,
                background: "white",
                color: "#333",
                borderRadius: 8,
                border: "1px solid #eaeaea",
                boxShadow: "0 2px 8px rgba(0, 0, 0, 0.05)",
                flex: 1,
              }}
            >
              <Typography
                variant="h6"
                sx={{ mb: 3, fontWeight: "bold", color: "#333" }}
              >
                Analysis Results
              </Typography>

              <Box sx={{ display: "flex", flexDirection: "column", gap: 3 }}>
                <Box sx={{ display: "flex", gap: 3 }}>
                  <Paper
                    sx={{
                      p: 2,
                      background: "white",
                      borderRadius: 8,
                      border: "1px solid #eaeaea",
                      flex: 1,
                    }}
                  >
                    <Typography
                      variant="subtitle2"
                      sx={{ mb: 1, color: "#666" }}
                    >
                      Message
                    </Typography>
                    <Typography color="#333">
                      {apiData.message ? (
                        apiData.message
                      ) : (
                        <>
                          packet_count: {apiData.features?.[0] || "N/A"} <br />
                          ip_entropy: {apiData.features?.[1] || "N/A"} <br />
                          avg_pkt_size: {apiData.features?.[2] || "N/A"} <br />
                          unique_protocols: {apiData.features?.[3] ||
                            "N/A"}{" "}
                          <br />
                          pkt_iat_var: {apiData.features?.[4] || "N/A"}
                        </>
                      )}
                    </Typography>
                  </Paper>

                  {apiData && (
                    <Paper
                      sx={{
                        p: 2,
                        background: "rgba(33, 150, 243, 0.1)",
                        borderRadius: 8,
                        border: "1px solid rgba(33, 150, 243, 0.3)",
                        width: "200px",
                        display: "flex",
                        flexDirection: "column",
                        justifyContent: "center",
                      }}
                    >
                      <Typography
                        variant="subtitle2"
                        sx={{ mb: 1, color: "#666" }}
                      >
                        Prediction
                      </Typography>
                      <Typography
                        color="#1976d2"
                        sx={{ fontWeight: "bold", fontSize: "1.25rem" }}
                      >
                        {apiData.prediction}
                      </Typography>
                    </Paper>
                  )}
                </Box>

                <Paper
                  sx={{
                    p: 2,
                    background: "white",
                    borderRadius: 8,
                    border: "1px solid #eaeaea",
                  }}
                >
                  <Typography variant="subtitle2" sx={{ mb: 2, color: "#666" }}>
                    Network Statistics
                  </Typography>
                  <Box
                    sx={{
                      display: "grid",
                      gridTemplateColumns:
                        "repeat(auto-fill, minmax(200px, 1fr))",
                      gap: 2,
                    }}
                  >
                    <Box
                      sx={{ p: 1.5, background: "#f8f9fa", borderRadius: 6 }}
                    >
                      <Typography variant="caption" sx={{ color: "#666" }}>
                        Packet Count
                      </Typography>
                      <Typography variant="body1" sx={{ fontWeight: "bold" }}>
                        {apiData.features ? apiData.features[0] : "N/A"}
                      </Typography>
                    </Box>
                    <Box
                      sx={{ p: 1.5, background: "#f8f9fa", borderRadius: 6 }}
                    >
                      <Typography variant="caption" sx={{ color: "#666" }}>
                        IP Entropy
                      </Typography>
                      <Typography variant="body1" sx={{ fontWeight: "bold" }}>
                        {apiData.features ? apiData.features[1] : "N/A"}
                      </Typography>
                    </Box>
                    <Box
                      sx={{ p: 1.5, background: "#f8f9fa", borderRadius: 6 }}
                    >
                      <Typography variant="caption" sx={{ color: "#666" }}>
                        Avg Packet Size
                      </Typography>
                      <Typography variant="body1" sx={{ fontWeight: "bold" }}>
                        {apiData.features ? apiData.features[2] : "N/A"}
                      </Typography>
                    </Box>
                    <Box
                      sx={{ p: 1.5, background: "#f8f9fa", borderRadius: 6 }}
                    >
                      <Typography variant="caption" sx={{ color: "#666" }}>
                        Unique Protocols
                      </Typography>
                      <Typography variant="body1" sx={{ fontWeight: "bold" }}>
                        {apiData.features ? apiData.features[3] : "N/A"}
                      </Typography>
                    </Box>
                    <Box
                      sx={{ p: 1.5, background: "#f8f9fa", borderRadius: 6 }}
                    >
                      <Typography variant="caption" sx={{ color: "#666" }}>
                        Packet IAT Variance
                      </Typography>
                      <Typography variant="body1" sx={{ fontWeight: "bold" }}>
                        {apiData.features ? apiData.features[4] : "N/A"}
                      </Typography>
                    </Box>
                  </Box>
                </Paper>
              </Box>
            </Paper>
          )}
        </Box>
      </Box>
    </Box>
  );
};

export default App;
