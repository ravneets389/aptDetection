import os
import pandas as pd
import logging
from tqdm import tqdm

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def is_malicious(label):
    """Determine if a label represents malicious traffic"""
    # Convert label to lowercase string for comparison
    label_str = str(label).lower().strip()
    
    # If the label is explicitly 'benign', return False
    if label_str == 'benign':
        return False
    
    # Everything else is considered malicious
    return True

def process_csv_file(csv_path):
    """Process a single CSV file and convert labels to binary"""
    try:
        logging.info(f"Processing {csv_path}")
        # Set low_memory=False to handle mixed types
        df = pd.read_csv(csv_path, low_memory=False)
        # Convert labels to binary (0 for benign, 1 for malicious)
        if 'label' in df.columns:
            df['label'] = df['label'].apply(lambda x: 1 if is_malicious(x) else 0)
            return df
        else:
            logging.error(f"No 'label' column found in {csv_path}")
            return None
    
    except Exception as e:
        logging.error(f"Error processing {csv_path}: {str(e)}")
        return None

def create_dataset(processed_dir, output_file):
    """Create dataset from processed CSV files"""
    all_data = []
    
    # Process all CSV files in the processed directory
    for root, _, files in os.walk(processed_dir):
        for file in tqdm(files, desc="Processing files"):
            if file.endswith('.csv'):
                csv_path = os.path.join(root, file)
                df = process_csv_file(csv_path)
                if df is not None:
                    all_data.append(df)
    
    if not all_data:
        logging.error("No valid CSV files found!")
        return
    
    # Combine all dataframes
    combined_df = pd.concat(all_data, ignore_index=True)
    
    # Save to CSV
    combined_df.to_csv(output_file, index=False)
    logging.info(f"Dataset saved to {output_file}")
    logging.info(f"Total flows: {len(combined_df)}")
    logging.info(f"Malicious flows: {combined_df['label'].sum()}")
    logging.info(f"Benign flows: {len(combined_df) - combined_df['label'].sum()}")

if __name__ == "__main__":
    # Define directories
    current_dir = os.path.dirname(os.path.abspath(__file__))
    processed_dir = os.path.join(current_dir, "processed")
    output_file = os.path.join(current_dir, "combined_dataset.csv")
    
    # Create dataset
    create_dataset(processed_dir, output_file) 