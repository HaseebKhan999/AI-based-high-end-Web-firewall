"""
Data Preprocessing Module for AI-WAF
Person 3 (ML Engineer)
This module handles data loading, cleaning, and feature extraction for TRAINING
IMPORTANT: Uses the SAME feature extraction as Person 1's waf_interceptor.py
"""

import pandas as pd
import numpy as np
import re
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import joblib
import os
import sys

# Import the SAME feature extractor that Person 1 uses
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.feature_extraction import FeatureExtractor


class DataPreprocessor:
    """
    Handles all data preprocessing for ML model training
    Uses EXACT SAME features as real-time WAF (Person 1's feature extractor)
    """
    
    def __init__(self):
        self.scaler = StandardScaler()
        self.feature_extractor = FeatureExtractor()  # Same as Person 1 uses!
        self.feature_names = [
            'request_length', 'url_length', 'num_parameters', 'special_char_count',
            'entropy', 'has_sql_keywords', 'sql_keyword_count', 'has_xss_patterns',
            'xss_keyword_count', 'has_path_traversal', 'has_command_injection_chars',
            'method_encoded', 'num_dots', 'num_slashes', 'has_digits', 'digit_count',
            'upper_case_ratio', 'lower_case_ratio', 'hex_char_count', 'query_string_length'
        ]
        
    def load_data(self, filepath):
        """
        Load the CSIC 2010 dataset
        
        Args:
            filepath: Path to the CSV file (csic_database.csv)
            
        Returns:
            pandas DataFrame
        """
        try:
            # Load CSV, handle different encodings
            df = pd.read_csv(filepath, encoding='utf-8', low_memory=False)
            print(f"✅ Data loaded successfully: {df.shape[0]} rows, {df.shape[1]} columns")
            return df
        except UnicodeDecodeError:
            df = pd.read_csv(filepath, encoding='latin-1', low_memory=False)
            print(f"✅ Data loaded with latin-1 encoding: {df.shape[0]} rows, {df.shape[1]} columns")
            return df
        except Exception as e:
            print(f"❌ Error loading data: {e}")
            return None
    
    def clean_data(self, df):
        """
        Clean the dataset by handling missing values and duplicates
        
        Args:
            df: pandas DataFrame
            
        Returns:
            Cleaned DataFrame
        """
        print("\n🧹 Cleaning data...")
        
        # Drop unnamed columns (index columns)
        df = df.loc[:, ~df.columns.str.contains('^Unnamed')]
        
        # Fill missing values with empty string
        df = df.fillna('')
        
        # Remove duplicates
        initial_rows = len(df)
        df = df.drop_duplicates()
        removed_rows = initial_rows - len(df)
        
        print(f"   • Removed {removed_rows} duplicate rows")
        print(f"   • Final dataset: {len(df)} rows")
        
        return df
    
    def convert_to_request_format(self, row):
        """
        Convert CSV row to request_data format (same as Flask request)
        This matches the format that Person 1's feature extractor expects
        
        Args:
            row: DataFrame row from CSIC dataset
            
        Returns:
            dict: Request data in the format expected by FeatureExtractor
        """
        # Build the request data dictionary to match Flask request format
        request_data = {
            'ip_address': '127.0.0.1',  # Dummy IP for training
            'method': str(row.get('Method', 'GET')).strip().upper(),
            'url': str(row.get('URL', '')),
            'path': str(row.get('URL', '')).split('?')[0] if '?' in str(row.get('URL', '')) else str(row.get('URL', '')),
            'query_string': str(row.get('URL', '')).split('?')[1] if '?' in str(row.get('URL', '')) else '',
            'headers': {
                'User-Agent': str(row.get('User-Agent', '')),
                'Content-Type': str(row.get('content-type', '')),
                'Accept': str(row.get('Accept', '')),
                'Cookie': str(row.get('cookie', ''))
            },
            'body': str(row.get('content', '')),
            'content_type': str(row.get('content-type', '')),
            'user_agent': str(row.get('User-Agent', '')),
            'timestamp': '2024-01-01T00:00:00'  # Dummy timestamp
        }
        
        return request_data
    
    def extract_features_from_dataset(self, df):
        """
        Extract features from the entire dataset using Person 1's FeatureExtractor
        This ensures training uses EXACT SAME features as real-time detection
        
        Args:
            df: pandas DataFrame (CSIC dataset)
            
        Returns:
            X (features), y (labels)
        """
        print("\n🔧 Extracting features using FeatureExtractor (same as Person 1)...")
        
        features_list = []
        labels_list = []
        errors = 0
        
        for idx, row in df.iterrows():
            if idx % 5000 == 0:
                print(f"   • Processing row {idx}/{len(df)}...")
            
            try:
                # Convert row to request format
                request_data = self.convert_to_request_format(row)
                
                # Extract features using Person 1's SAME feature extractor
                features = self.feature_extractor.extract_features(request_data)
                
                # Get label (0 = Normal, 1 = Anomalous)
                label = 0 if str(row.get('classification', 'Normal')).strip() == 'Normal' else 1
                
                features_list.append(features)
                labels_list.append(label)
                
            except Exception as e:
                errors += 1
                if errors < 5:  # Only print first 5 errors
                    print(f"   ⚠️ Error processing row {idx}: {e}")
                continue
        
        # Convert to numpy arrays
        X = np.array(features_list)
        y = np.array(labels_list)
        
        print(f"\n✅ Feature extraction complete!")
        print(f"   • Successfully processed: {len(X)} rows")
        print(f"   • Errors encountered: {errors} rows")
        print(f"   • Feature matrix shape: {X.shape}")
        print(f"   • Expected features: 20")
        print(f"   • Actual features extracted: {X.shape[1] if len(X) > 0 else 0}")
        print(f"   • Normal requests: {(y == 0).sum()}")
        print(f"   • Anomalous requests: {(y == 1).sum()}")
        
        return X, y
    
    def split_data(self, X, y, test_size=0.2, random_state=42):
        """
        Split data into training and testing sets
        
        Args:
            X: Feature matrix
            y: Labels
            test_size: Proportion of test data (default: 0.2 = 20%)
            random_state: Random seed for reproducibility
            
        Returns:
            X_train, X_test, y_train, y_test
        """
        print(f"\n✂️ Splitting data (train: {int((1-test_size)*100)}%, test: {int(test_size*100)}%)...")
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y
        )
        
        print(f"   • Training set: {X_train.shape[0]} samples")
        print(f"   • Test set: {X_test.shape[0]} samples")
        
        return X_train, X_test, y_train, y_test
    
    def scale_features(self, X_train, X_test=None):
        """
        Scale features using StandardScaler
        IMPORTANT: Fit on training data only, then transform both train and test
        
        Args:
            X_train: Training features
            X_test: Test features (optional)
            
        Returns:
            Scaled features
        """
        print("\n📏 Scaling features...")
        
        # Fit scaler on training data ONLY
        X_train_scaled = self.scaler.fit_transform(X_train)
        print(f"   • Scaler fitted on training data")
        print(f"   • Feature means: {self.scaler.mean_[:5]}... (first 5)")
        print(f"   • Feature stds: {self.scaler.scale_[:5]}... (first 5)")
        
        if X_test is not None:
            # Transform test data using the fitted scaler
            X_test_scaled = self.scaler.transform(X_test)
            return X_train_scaled, X_test_scaled
        
        return X_train_scaled
    
    def save_scaler(self, filepath='data/trained_models/scaler.pkl'):
        """
        Save the fitted scaler for use during prediction
        Person 1 will load this scaler for real-time predictions
        """
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        joblib.dump(self.scaler, filepath)
        print(f"✅ Scaler saved to {filepath}")
    
    def load_scaler(self, filepath='data/trained_models/scaler.pkl'):
        """Load a saved scaler"""
        self.scaler = joblib.load(filepath)
        print(f"✅ Scaler loaded from {filepath}")
        return self.scaler
    
    def prepare_training_data(self, filepath, test_size=0.2):
        """
        Complete data preparation pipeline for training
        
        Args:
            filepath: Path to CSIC CSV file
            test_size: Proportion for test set
            
        Returns:
            X_train_scaled, X_test_scaled, y_train, y_test
        """
        print("=" * 70)
        print("🚀 STARTING DATA PREPARATION PIPELINE")
        print("=" * 70)
        
        # Step 1: Load data
        df = self.load_data(filepath)
        if df is None:
            return None, None, None, None
        
        # Step 2: Clean data
        df = self.clean_data(df)
        
        # Step 3: Extract features (using Person 1's feature extractor)
        X, y = self.extract_features_from_dataset(df)
        
        if len(X) == 0:
            print("❌ No features extracted! Check data format.")
            return None, None, None, None
        
        # Step 4: Split data
        X_train, X_test, y_train, y_test = self.split_data(X, y, test_size=test_size)
        
        # Step 5: Scale features
        X_train_scaled, X_test_scaled = self.scale_features(X_train, X_test)
        
        # Step 6: Save scaler
        self.save_scaler()
        
        print("\n" + "=" * 70)
        print("✅ DATA PREPARATION COMPLETE!")
        print("=" * 70)
        print(f"Training set: {X_train_scaled.shape}")
        print(f"Test set: {X_test_scaled.shape}")
        print(f"Features: {X_train_scaled.shape[1]}")
        print(f"Classes: Normal={sum(y_train==0)}, Anomalous={sum(y_train==1)}")
        print("=" * 70)
        
        return X_train_scaled, X_test_scaled, y_train, y_test
    
    def get_feature_names(self):
        """Return the list of feature names"""
        return self.feature_names


# Example usage (for testing)
if __name__ == "__main__":
    print("=" * 70)
    print("TESTING DATA PREPROCESSOR")
    print("=" * 70)
    
    # Initialize preprocessor
    preprocessor = DataPreprocessor()
    
    # Prepare training data
    X_train, X_test, y_train, y_test = preprocessor.prepare_training_data(
        'data/datasets/csic_database.csv',
        test_size=0.2
    )
    
    if X_train is not None:
        print("\n✅ Preprocessing test successful!")
        print(f"Ready for training with {X_train.shape[0]} training samples!")
    else:
        print("\n❌ Preprocessing failed!")