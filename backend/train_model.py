import os
import numpy as np
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# Ensure 'models/' directory exists
os.makedirs("models", exist_ok=True)

# Generate synthetic dataset
np.random.seed(42)
num_samples = 1000

# Simulated network features: [Packet Count, IP Entropy, Flow Duration, Total Fwd Packets, Total Backward Packets]
X = np.random.rand(num_samples, 5) * [1000, 1, 5000, 200, 200]
y = np.random.randint(0, 2, num_samples)  # 0: Normal, 1: APT attack

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Evaluate model
y_pred = model.predict(X_test)
print("Model Accuracy:", accuracy_score(y_test, y_pred))

# Save model
joblib.dump(model, "models/mta_kdd_model.pkl")
print("Model saved as models/mta_kdd_model.pkl")
