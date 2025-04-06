import os
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
from sklearn.preprocessing import LabelEncoder
import joblib

def clean_numeric_string(value):
    """Clean numeric strings by taking the first value before any comma"""
    if pd.isna(value):
        return 0
    if isinstance(value, (int, float)):
        return float(value)
    try:
        # If it's a string with commas, take the first value
        value_str = str(value).strip()
        if ',' in value_str:
            # If it's a comma-separated list, take the average
            numbers = [float(x.strip()) for x in value_str.split(',')]
            return sum(numbers) / len(numbers)
        return float(value_str)
    except:
        return 0

def load_dataset(dataset_path):
    """Load the network traffic dataset from CSV file"""
    try:
        print(f"Loading dataset from {dataset_path}...")
        # Set low_memory=False to handle mixed types
        df = pd.read_csv(dataset_path, low_memory=False)
        print(f"Dataset loaded successfully with {len(df)} rows and {len(df.columns)} columns")
        
        # Display basic information about the dataset
        print("\nDataset Overview:")
        print(f"Total samples: {len(df)}")
        print(f"Features: {', '.join(df.columns)}")
        
        # Check for missing values
        missing_values = df.isnull().sum()
        if missing_values.any():
            print("\nMissing values detected:")
            for column, count in missing_values[missing_values > 0].items():
                print(f"  {column}: {count} missing values")
        else:
            print("\nNo missing values detected in the dataset")
        
        return df
    except Exception as e:
        print(f"Error loading dataset: {str(e)}")
        raise

def preprocess_data(df):
    """Preprocess the data by handling missing values and encoding categorical features"""
    
    # Create a copy of the dataframe to avoid warnings
    df = df.copy()
    
    # Fill missing values
    # For numeric columns, clean and convert to float
    numeric_columns = ['frame.len', 'ip.ttl', 'ip.proto', 'ip.checksum', 'ip.tos',
                      'tcp.srcport', 'tcp.dstport', 'tcp.flags', 'tcp.window_size_value',
                      'tcp.window_size_scalefactor', 'tcp.checksum', 'udp.srcport', 'udp.dstport',
                      'tcp.pdu.size']
    
    print("\nProcessing numeric columns...")
    for col in numeric_columns:
        if col in df.columns:
            print(f"Processing {col}...")
            # Clean numeric strings and convert to float
            df[col] = df[col].apply(clean_numeric_string)
            # Print some statistics
            print(f"  Range: {df[col].min()} to {df[col].max()}")
            print(f"  Mean: {df[col].mean():.2f}")
    
    # For categorical columns, fill with 'unknown'
    categorical_columns = ['frame.protocols', 'eth.src', 'eth.dst', 'ip.src', 'ip.dst',
                         'ip.flags', 'tcp.options']
    
    print("\nProcessing categorical columns...")
    for col in categorical_columns:
        if col in df.columns:
            print(f"Processing {col}...")
            df[col] = df[col].fillna('unknown')
            # Print value counts
            print(f"  Unique values: {df[col].nunique()}")
    
    # Convert frame.time to numeric (seconds since epoch)
    if 'frame.time' in df.columns:
        print("\nProcessing frame.time...")
        df['frame.time'] = df['frame.time'].apply(clean_numeric_string)
        print(f"  Range: {df['frame.time'].min()} to {df['frame.time'].max()}")
    
    # Handle categorical features with label encoding
    label_encoders = {}
    for col in categorical_columns:
        if col in df.columns:
            print(f"\nEncoding {col}...")
            label_encoders[col] = LabelEncoder()
            df[col] = label_encoders[col].fit_transform(df[col].astype(str))
            print(f"  Encoded range: {df[col].min()} to {df[col].max()}")
    
    return df, label_encoders

def train_model(df):
    """Train a RandomForestClassifier on the provided DataFrame"""
    
    print("\nData Overview:")
    print(f"Total samples: {len(df)}")
    if 'label' in df.columns:
        print(f"Malicious samples: {df['label'].sum()}")
        print(f"Benign samples: {len(df) - df['label'].sum()}")
    
    # Preprocess the data
    df_processed, label_encoders = preprocess_data(df)
    
    # Separate features and target
    if 'label' in df_processed.columns:
        X = df_processed.drop('label', axis=1)
        y = df_processed['label']
    else:
        X = df_processed
        y = None
    
    print(f"\nFinal feature count: {X.shape[1]}")
    
    if y is not None:
        # Split the data with stratification to maintain class distribution
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
        
        print("\nTraining Random Forest Classifier...")
        
        # Calculate class weights to penalize false positives more heavily
        n_samples = len(y_train)
        n_benign = (y_train == 0).sum()
        n_malicious = (y_train == 1).sum()
        
        # Higher weight for benign class to reduce false positives
        class_weight = {
            0: n_samples / (2 * n_benign),  # Benign class
            1: n_samples / (2 * n_malicious)  # Malicious class
        }
        
        # Initialize and train the model with better parameters
        model = RandomForestClassifier(
            n_estimators=100,  # Increased number of trees
            max_depth=8,       # Reduced depth to prevent overfitting
            min_samples_split=50,  # Increased to require more samples for splits
            min_samples_leaf=20,   # Increased to require more samples in leaves
            class_weight=class_weight,  # Added class weights
            random_state=42,
            n_jobs=-1
        )
        
        model.fit(X_train, y_train)
        
        # Make predictions on test set
        y_pred = model.predict(X_test)
        
        # Print model performance
        print("\nModel Performance:")
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred))
        
        print("\nConfusion Matrix:")
        print(confusion_matrix(y_test, y_pred))
        
        print(f"\nAccuracy: {accuracy_score(y_test, y_pred):.4f}")
        
        # Get feature importance
        feature_importance = pd.DataFrame({
            'feature': X.columns,
            'importance': model.feature_importances_
        }).sort_values('importance', ascending=False)
        
        print("\nTop 10 Most Important Features:")
        print(feature_importance.head(10))
        
        return model, X.columns.tolist(), label_encoders
    else:
        return None, X.columns.tolist(), label_encoders

def main():
    """Main function to load dataset, train model and save it"""
    
    # Path to the dataset - using absolute path
    current_dir = os.path.dirname(os.path.abspath(__file__))
    dataset_path = os.path.join(current_dir, "combined_dataset.csv")
    
    # Load the dataset
    df = load_dataset(dataset_path)
    
    # Train the model
    model, feature_names, label_encoders = train_model(df)
    
    # Create models directory if it doesn't exist
    os.makedirs("models", exist_ok=True)
    
    # Save the model if we have one
    if model:
        model_path = os.path.join(current_dir, "network_traffic_model.pkl")
        joblib.dump(model, model_path)
        print(f"\nModel saved to {model_path}")
        
        # Save label encoders
        encoders_path = os.path.join(current_dir, "label_encoders.pkl")
        joblib.dump(label_encoders, encoders_path)
        print(f"Label encoders saved to {encoders_path}")
    
    # Save feature names
    feature_names_path = os.path.join(current_dir, "feature_names.txt")
    with open(feature_names_path, 'w') as f:
        f.write('\n'.join(feature_names))
    print(f"Feature names saved to {feature_names_path}")

if __name__ == "__main__":
    main() 