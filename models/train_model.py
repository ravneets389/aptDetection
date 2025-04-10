import os
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
from sklearn.preprocessing import LabelEncoder
import joblib
import logging
from tqdm import tqdm

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define important features to keep
IMPORTANT_FEATURES = [
    'frame.len', 'ip.ttl', 'ip.proto', 'tcp.srcport', 'tcp.dstport',
    'tcp.window_size_value', 'tcp.window_size_scalefactor', 'label'
]

def clean_numeric_string(value):
    """Clean numeric strings by taking the first value before any comma"""
    if pd.isna(value):
        return 0
    if isinstance(value, (int, float)):
        return float(value)
    try:
        value_str = str(value).strip()
        if ',' in value_str:
            numbers = [float(x.strip()) for x in value_str.split(',')]
            return sum(numbers) / len(numbers)
        return float(value_str)
    except:
        return 0

def load_and_sample_dataset(dataset_path, sample_size=100000, chunk_size=5000):
    """Load and sample the dataset to reduce memory usage"""
    try:
        logging.info(f"Loading and sampling dataset from {dataset_path}...")
        
        # Initialize empty lists for sampled data
        sampled_data = []
        total_rows = 0
        
        # Process in smaller chunks
        for chunk in tqdm(pd.read_csv(dataset_path, chunksize=chunk_size, low_memory=False),
                         desc="Loading chunks"):
            # Keep only important features
            chunk = chunk[IMPORTANT_FEATURES]
            
            # Clean numeric columns
            for col in ['frame.len', 'ip.ttl', 'ip.proto', 'tcp.srcport', 'tcp.dstport',
                       'tcp.window_size_value', 'tcp.window_size_scalefactor']:
                chunk[col] = chunk[col].apply(clean_numeric_string)
            
            # Sample from each chunk
            if len(chunk) > 0:
                sample = chunk.sample(n=min(len(chunk), sample_size // 10), random_state=42)
                sampled_data.append(sample)
            
            total_rows += len(chunk)
        
        # Combine sampled data
        df = pd.concat(sampled_data, ignore_index=True)
        
        # Final sampling if needed
        if len(df) > sample_size:
            df = df.sample(n=sample_size, random_state=42)
        
        logging.info(f"Sampled dataset created with {len(df)} rows")
        logging.info(f"Original dataset had {total_rows} rows")
        
        return df
    
    except Exception as e:
        logging.error(f"Error loading dataset: {str(e)}")
        raise

def train_model(df):
    """Train a RandomForestClassifier on the sampled DataFrame"""
    logging.info("\nData Overview:")
    logging.info(f"Total samples: {len(df)}")
    if 'label' in df.columns:
        logging.info(f"Malicious samples: {df['label'].sum()}")
        logging.info(f"Benign samples: {len(df) - df['label'].sum()}")
    
    # Separate features and target
    X = df.drop('label', axis=1)
    y = df['label']
    
    # Split the data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    logging.info("\nTraining Random Forest Classifier...")
    
    # Initialize and train the model with reduced parameters
    model = RandomForestClassifier(
        n_estimators=50,
        max_depth=10,
        min_samples_split=20,
        min_samples_leaf=10,
        random_state=42,
        n_jobs=-1
    )
    
    model.fit(X_train, y_train)
    
    # Make predictions on test set
    y_pred = model.predict(X_test)
    
    # Print model performance
    logging.info("\nModel Performance:")
    logging.info("\nClassification Report:")
    logging.info(classification_report(y_test, y_pred))
    
    logging.info("\nConfusion Matrix:")
    logging.info(confusion_matrix(y_test, y_pred))
    
    logging.info(f"\nAccuracy: {accuracy_score(y_test, y_pred):.4f}")
    
    # Get feature importance
    feature_importance = pd.DataFrame({
        'feature': X.columns,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    logging.info("\nFeature Importance:")
    logging.info(feature_importance)
    
    return model, X.columns.tolist()

def main():
    """Main function to load dataset, train model and save it"""
    
    # Path to the dataset
    current_dir = os.path.dirname(os.path.abspath(__file__))
    dataset_path = os.path.join(current_dir, "combined_dataset.csv")
    
    # Load and sample the dataset
    df = load_and_sample_dataset(dataset_path, sample_size=100000)
    
    # Train the model
    model, feature_names = train_model(df)
    
    # Save the model
    model_path = os.path.join(current_dir, "network_traffic_model.pkl")
    joblib.dump(model, model_path)
    logging.info(f"\nModel saved to {model_path}")
    
    # Save feature names
    feature_names_path = os.path.join(current_dir, "feature_names.txt")
    with open(feature_names_path, 'w') as f:
        f.write('\n'.join(feature_names))
    logging.info(f"Feature names saved to {feature_names_path}")

if __name__ == "__main__":
    main() 