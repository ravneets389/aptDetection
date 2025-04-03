import React, { useState, useEffect } from "react";
import { Play, Square, BarChart } from "lucide-react";

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

const Button = ({ children, variant, color, disabled, onClick, sx }) => {
  const getBackgroundColor = () => {
    if (disabled) return sx?.["&.Mui-disabled"]?.backgroundColor || "#e0e0e0";
    if (color === "success") return "#4caf50";
    if (color === "error") return "#f44336";
    return "#2196f3";
  };

  return (
    <button
      disabled={disabled}
      onClick={onClick}
      style={{
        backgroundColor: getBackgroundColor(),
        color: "white",
        border: "none",
        borderRadius: "4px",
        padding: `${sx?.py ? sx.py * 8 : 8}px ${sx?.px ? sx.px * 8 : 16}px`,
        fontWeight: sx?.fontWeight || "normal",
        cursor: disabled ? "not-allowed" : "pointer",
        display: "flex",
        alignItems: "center",
        gap: "8px",
        boxShadow: sx?.boxShadow === 3 ? "0 3px 5px rgba(0,0,0,0.2)" : "none",
        opacity: disabled ? 0.7 : 1,
      }}
    >
      {children}
    </button>
  );
};

const Typography = ({ children, variant, sx }) => {
  const getFontSize = () => {
    if (variant === "h6") return "1.25rem";
    if (variant === "caption") return "0.75rem";
    return "1rem";
  };

  return (
    <div
      style={{
        fontSize: getFontSize(),
        fontWeight: sx?.fontWeight || "normal",
        opacity: sx?.opacity,
        margin: sx?.mb ? `0 0 ${sx.mb * 8}px 0` : 0,
      }}
    >
      {children}
    </div>
  );
};

const Box = ({ children, sx }) => (
  <div
    style={{
      display: sx?.display || "block",
      flexDirection: sx?.flexDirection,
      alignItems: sx?.alignItems,
      justifyContent: sx?.justifyContent,
      gap: sx?.gap ? `${sx.gap * 8}px` : "0",
      padding: sx?.p
        ? `${sx.p * 8}px`
        : sx?.py
        ? `${sx.py * 8}px 0`
        : sx?.padding
        ? sx.padding
        : "0",
      margin: sx?.mb ? `0 0 ${sx.mb * 8}px 0` : "0",
      minHeight: sx?.minHeight,
      background: sx?.background,
      position: sx?.position,
      opacity: sx?.opacity,
      textAlign: sx?.textAlign,
      top: sx?.top === 0 ? "0" : sx?.top,
      left: sx?.left === 0 ? "0" : sx?.left,
      bottom: sx?.bottom === 0 ? "0" : sx?.bottom,
      right: sx?.right === 0 ? "0" : sx?.right,
    }}
  >
    {children}
  </div>
);

const CircularProgress = ({ variant, value, size, thickness, sx }) => (
  <div
    style={{ position: "relative", width: `${size}px`, height: `${size}px` }}
  >
    {/* Background circle */}
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
      <circle
        cx={size / 2}
        cy={size / 2}
        r={size / 2 - thickness}
        fill="none"
        stroke="rgba(0,0,0,0.1)"
        strokeWidth={thickness}
      />
      {/* Progress circle */}
      <circle
        cx={size / 2}
        cy={size / 2}
        r={size / 2 - thickness}
        fill="none"
        stroke={sx?.color || "#2196f3"}
        strokeWidth={thickness}
        strokeDasharray={2 * Math.PI * (size / 2 - thickness)}
        strokeDashoffset={
          2 * Math.PI * (size / 2 - thickness) * (1 - value / 100)
        }
        transform={`rotate(-90 ${size / 2} ${size / 2})`}
        style={{ transition: "stroke-dashoffset 0.3s ease, stroke 0.3s ease" }}
      />
    </svg>
  </div>
);

const Paper = ({ children, sx }) => (
  <div
    style={{
      backgroundColor: sx?.background || "white",
      padding: sx?.p ? `${sx.p * 8}px` : sx?.py ? `${sx.py * 8}px 0` : "8px",
      margin: sx?.mb ? `0 0 ${sx.mb * 8}px 0` : "0",
      borderRadius: "4px",
      color: sx?.color || "inherit",
    }}
  >
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
  const [uploadMessage, setUploadMessage] = useState('');

  const handleFileChange = (event) => {
    setSelectedFile(event.target.files[0]);
  };

  const handleUpload = async () => {
      if (!selectedFile) {
          alert("Please select a file first.");
          return;
      }

      const formData = new FormData();
      formData.append("file", selectedFile);

      try {
          const response = await fetch('http://localhost:8000/upload/', {
              method: 'POST',
              body: formData
          });

          const result = await response.json();
          setUploadMessage(result.message);
      } catch (error) {
          console.error("Error uploading file:", error);
          setUploadMessage("Failed to upload file.");
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

  // Mock API calls
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

  const handleFileUpload = async () => {
    if (!selectedFile) {
      alert("Please select a file to upload.");
      return;
    }

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
    } catch (error) {
      console.error("File upload error:", error);
      setUploadMessage("Error uploading file.");
    }
  };
  
  return ( 
    <Box
      sx={{
        minHeight: "100vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        background: "linear-gradient(135deg, #3f51b5 0%, #9c27b0 100%)",
        padding: 4,
      }}
    >
      <Card
        sx={{
          maxWidth: 500,
          background: "rgba(255, 255, 255, 0.15)",
          backdropFilter: "blur(10px)",
          boxShadow: "0 8px 32px 0 rgba(31, 38, 135, 0.37)",
          borderRadius: 4,
        }}
      >
        <CardHeader
          title="Process Controller"
          subheader="Monitor and control your process with ease"
          sx={{
            textAlign: "center",
            color: "white",
            "& .MuiCardHeader-subheader": {
              color: "rgba(255, 255, 255, 0.7)",
            },
          }}
        />

        <CardContent>
          {/* Animated Progress */}
          <Box sx={{ display: "flex", justifyContent: "center", mb: 4 }}>
            <Box sx={{ position: "relative", display: "inline-flex" }}>
              <CircularProgress
                variant="determinate"
                value={progress}
                size={120}
                thickness={4}
                sx={{
                  color: isRunning ? "#4caf50" : "#f44336",
                }}
              />
              <Box
                sx={{
                  top: 0,
                  left: 0,
                  bottom: 0,
                  right: 0,
                  position: "absolute",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                }}
              >
                <BarChart
                  size={48}
                  style={{
                    color: isRunning ? "#4caf50" : "#f44336",
                    transition: "color 0.3s ease",
                  }}
                />
              </Box>
            </Box>
          </Box>

          {/* Control Buttons */}
          <Box
            sx={{ display: "flex", justifyContent: "center", gap: 3, mb: 4 }}
          >
            <Button
              variant="contained"
              color="success"
              disabled={isRunning || isLoading}
              onClick={handleStart}
              sx={{
                py: 1.5,
                px: 3,
                fontWeight: "medium",
                boxShadow: 3,
                "&.Mui-disabled": {
                  backgroundColor: "rgba(0, 0, 0, 0.12)",
                },
              }}
            >
              <Play size={20} />
              Start
            </Button>

            {!isRunning && apiData && (
              <Button
                variant="contained"
                color="primary"
                disabled={isLoading}
                onClick={handlePredict}
                sx={{
                  py: 1.5,
                  px: 3,
                  fontWeight: "medium",
                  boxShadow: 3,
                  backgroundColor: "#ff9800",
                  "&:hover": {
                    backgroundColor: "#f57c00",
                  },
                  "&.Mui-disabled": {
                    backgroundColor: "rgba(0, 0, 0, 0.12)",
                  },
                }}
              >
                {/* <LineChart size={20} /> */}
                Predict
              </Button>
            )}

            <Button
              variant="contained"
              color="error"
              disabled={!isRunning || isLoading}
              onClick={handleStop}
              sx={{
                py: 1.5,
                px: 3,
                fontWeight: "medium",
                boxShadow: 3,
                "&.Mui-disabled": {
                  backgroundColor: "rgba(0, 0, 0, 0.12)",
                },
              }}
            >
              <Square size={20} />
              Stop
            </Button>

            <Button
              variant="contained"
              color="primary"
              disabled={isLoading}
              onClick={handleFileUpload}
              sx={{
                py: 1.5,
                px: 3,
                fontWeight: "medium",
                boxShadow: 3,
                backgroundColor: "#4caf50",
                "&:hover": {
                  backgroundColor: "#388e3c",
                },
                "&.Mui-disabled": {
                  backgroundColor: "rgba(0, 0, 0, 0.12)",
                },
              }}
            >
              Upload
            </Button>
          </Box>

          {/* File Selector */}
          <Box sx={{ display: "flex", justifyContent: "center", mb: 4 }}>
            <input
              type="file"
              onChange={handleFileChange}
              style={{
                display: "block",
                margin: "0 auto",
                padding: "8px",
                borderRadius: "4px",
                border: "1px solid #ccc",
                backgroundColor: "#f9f9f9",
              }}
            />
          </Box>

          {/* Status Indicators */}
          <Paper
            sx={{
              p: 2,
              mb: 3,
              background: "rgba(0, 0, 0, 0.2)",
              color: "white",
            }}
          >
            <Box sx={{ display: "flex", alignItems: "center", mb: 1 }}>
              <div
                style={{
                  width: "12px",
                  height: "12px",
                  borderRadius: "50%",
                  backgroundColor: isRunning ? "#4caf50" : "#f44336",
                  marginRight: "8px",
                }}
              />
              <Typography>
                Status: {isRunning ? "Running" : "Stopped"}
              </Typography>
            </Box>

            <Box sx={{ display: "flex", alignItems: "center" }}>
              <div
                style={{
                  width: "12px",
                  height: "12px",
                  borderRadius: "50%",
                  backgroundColor: isLoading ? "#ff9800" : "#2196f3",
                  marginRight: "8px",
                  animation: isLoading
                    ? "pulse 1.5s infinite ease-in-out"
                    : "none",
                }}
              />
              <Typography>{isLoading ? "Processing..." : "Ready"}</Typography>
            </Box>
          </Paper>

          {/* API Data Display */}
          <Paper
            sx={{
              p: 2,
              background: "rgba(255, 255, 255, 0.15)",
              color: "white",
            }}
          >
            <Typography variant="h6" sx={{ mb: 2, fontWeight: "bold" }}>
              Process Data
            </Typography>

            {apiData ? (
              <Box sx={{ display: "flex", flexDirection: "column", gap: 2 }}>
                <Paper sx={{ p: 1.5, background: "rgba(255, 255, 255, 0.1)" }}>
                  <Typography variant="caption" sx={{ opacity: 0.7 }}>
                    Message
                  </Typography>
                  <Typography>
                    {apiData.message ? (
                      apiData.message
                    ) : (
                      <>
                        packet_count: {apiData.features[0]} <br />
                        ip_entropy: {apiData.features[1]} <br />
                        avg_pkt_size: {apiData.features[2]} <br />
                        unique_protocols: {apiData.features[3]} <br />
                        pkt_iat_var: {apiData.features[4]}
                      </>
                    )}
                  </Typography>
                </Paper>

                {apiData && (
                  <Paper sx={{ p: 1.5, background: "rgba(25, 118, 210, 0.2)" }}>
                    <Typography variant="caption" sx={{ opacity: 0.7 }}>
                      Prediction
                    </Typography>
                    <Typography>{apiData.prediction}</Typography>
                  </Paper>
                )}
              </Box>
            ) : (
              <Box sx={{ textAlign: "center", py: 2, opacity: 0.5 }}>
                <Typography>
                  {isRunning
                    ? "Processing in progress..."
                    : "Press Stop to view process data"}
                </Typography>
              </Box>
            )}
          </Paper>
        </CardContent>
      </Card>
    </Box>
  );
};

export default App;
