"""
Anomaly Detection Module
Author: Person 3 (ML Engineer)
Purpose: Detect anomalous/unusual patterns using Isolation Forest

This module complements the Random Forest classifier by detecting
zero-day attacks and unusual patterns that weren't in the training data.
"""

import joblib
import numpy as np
import json
import os
import sys
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.feature_extraction import FeatureExtractor
from utils.preprocessing import DataPreprocessor


class AnomalyDetector:
    """
    Handles anomaly detection using Isolation Forest
    """
    
    def __init__(self, model_path='data/trained_models/isolation_forest_model.pkl',
                 scaler_path='data/trained_models/scaler.pkl'):
        """
        Initialize anomaly detector
        
        Args:
            model_path: Path to save/load Isolation Forest model
            scaler_path: Path to feature scaler
        """
        self.model = None
        self.scaler = None
        self.feature_extractor = FeatureExtractor()
        self.model_path = model_path
        self.scaler_path = scaler_path
        self.is_loaded = False
        self.metadata = {}
        
        # Anomaly score thresholds
        self.anomaly_thresholds = {
            'normal': -0.1,      # Above this = normal
            'suspicious': -0.3,  # Between -0.3 and -0.1 = suspicious
            'anomalous': -1.0    # Below -0.3 = anomalous
        }
    
    def train_isolation_forest(self, X_train, contamination=0.1, **params):
        """
        Train Isolation Forest model on normal traffic
        
        Args:
            X_train: Training features (should be mostly normal traffic)
            contamination: Expected proportion of anomalies (default 0.1 = 10%)
            **params: Additional model parameters
            
        Returns:
            Trained Isolation Forest model
        """
        print("\n" + "="*70)
        print("🌳 TRAINING ISOLATION FOREST (ANOMALY DETECTOR)")
        print("="*70)
        
        # Default parameters
        default_params = {
            'n_estimators': 100,
            'max_samples': 'auto',
            'contamination': contamination,
            'random_state': 42,
            'n_jobs': -1,
            'verbose': 1
        }
        
        # Override with user params
        default_params.update(params)
        
        print(f"\n📋 Model Parameters:")
        for key, value in default_params.items():
            print(f"   {key}: {value}")
        
        # Initialize and train
        print(f"\n🏋️ Training on {len(X_train)} samples...")
        self.model = IsolationForest(**default_params)
        
        start_time = datetime.now()
        self.model.fit(X_train)
        training_time = (datetime.now() - start_time).total_seconds()
        
        print(f"✅ Training completed in {training_time:.2f} seconds!")
        
        # Store metadata
        self.metadata['training_time'] = training_time
        self.metadata['n_samples'] = len(X_train)
        self.metadata['model_params'] = default_params
        self.metadata['trained_at'] = datetime.now().isoformat()
        
        self.is_loaded = True
        return self.model
    
    def evaluate_on_test_set(self, X_test, y_test):
        """
        Evaluate Isolation Forest on test set
        
        Args:
            X_test: Test features
            y_test: Test labels (0=normal, 1=attack)
            
        Returns:
            dict: Evaluation metrics
        """
        print("\n" + "="*70)
        print("📊 EVALUATING ANOMALY DETECTOR")
        print("="*70)
        
        # Predict (-1 = anomaly, 1 = normal)
        predictions = self.model.predict(X_test)
        
        # Convert to binary (0 = normal, 1 = anomaly)
        predictions_binary = np.where(predictions == -1, 1, 0)
        
        # Calculate metrics
        cm = confusion_matrix(y_test, predictions_binary)
        tn, fp, fn, tp = cm.ravel()
        
        accuracy = (tp + tn) / (tp + tn + fp + fn)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
        
        print(f"\n🎯 ANOMALY DETECTION METRICS:")
        print(f"   Accuracy:  {accuracy*100:.2f}%")
        print(f"   Precision: {precision*100:.2f}%")
        print(f"   Recall:    {recall*100:.2f}%")
        print(f"   F1-Score:  {f1*100:.2f}%")
        
        print(f"\n📉 ERROR RATES:")
        print(f"   False Positive Rate: {fpr*100:.2f}%")
        print(f"   False Negative Rate: {fnr*100:.2f}%")
        
        print(f"\n🔢 CONFUSION MATRIX:")
        print(f"                    Predicted")
        print(f"                Normal  Anomaly")
        print(f"   Actual Normal  {tn:6d}  {fp:6d}")
        print(f"   Actual Attack  {fn:6d}  {tp:6d}")
        
        print(f"\n📋 CLASSIFICATION REPORT:")
        print(classification_report(y_test, predictions_binary,
                                   target_names=['Normal', 'Anomaly'],
                                   digits=4))
        
        # Store metrics
        metrics = {
            'accuracy': float(accuracy),
            'precision': float(precision),
            'recall': float(recall),
            'f1_score': float(f1),
            'false_positive_rate': float(fpr),
            'false_negative_rate': float(fnr),
            'confusion_matrix': {
                'true_negative': int(tn),
                'false_positive': int(fp),
                'false_negative': int(fn),
                'true_positive': int(tp)
            }
        }
        
        self.metadata['evaluation_metrics'] = metrics
        return metrics
    
    def save_model(self):
        """Save trained Isolation Forest model"""
        print("\n" + "="*70)
        print("💾 SAVING ANOMALY DETECTOR")
        print("="*70)
        
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        
        # Save model
        joblib.dump(self.model, self.model_path)
        print(f"✅ Model saved to: {self.model_path}")
        
        # Save metadata
        metadata_path = self.model_path.replace('.pkl', '_metadata.json')
        with open(metadata_path, 'w') as f:
            json.dump(self.metadata, f, indent=4)
        print(f"✅ Metadata saved to: {metadata_path}")
        
        model_size = os.path.getsize(self.model_path) / (1024 * 1024)
        print(f"📦 Model size: {model_size:.2f} MB")
    
    def load_model(self):
        """Load trained Isolation Forest model"""
        try:
            print(f"🔄 Loading Isolation Forest from {self.model_path}...")
            
            if not os.path.exists(self.model_path):
                print(f"❌ Model not found: {self.model_path}")
                return False
            
            # Load model
            self.model = joblib.load(self.model_path)
            print(f"✅ Isolation Forest loaded successfully")
            
            # Load scaler
            if os.path.exists(self.scaler_path):
                self.scaler = joblib.load(self.scaler_path)
                print(f"✅ Scaler loaded successfully")
            
            # Load metadata
            metadata_path = self.model_path.replace('.pkl', '_metadata.json')
            if os.path.exists(metadata_path):
                with open(metadata_path, 'r') as f:
                    self.metadata = json.load(f)
                print(f"✅ Metadata loaded")
            
            self.is_loaded = True
            return True
            
        except Exception as e:
            print(f"❌ Error loading model: {e}")
            return False
    
    def predict_anomaly(self, request_data):
        """
        Detect if a request is anomalous
        
        Args:
            request_data: Dictionary containing request information
            
        Returns:
            dict: Anomaly detection results
        """
        if not self.is_loaded:
            success = self.load_model()
            if not success:
                return {
                    'error': 'Model not loaded',
                    'is_anomaly': False,
                    'anomaly_score': 0.0
                }
        
        try:
            # Extract features
            features = self.feature_extractor.extract_features(request_data)
            features_array = np.array(features).reshape(1, -1)
            
            # Scale if scaler available
            if self.scaler:
                features_array = self.scaler.transform(features_array)
            
            # Predict (-1 = anomaly, 1 = normal)
            prediction = self.model.predict(features_array)[0]
            
            # Get anomaly score (lower = more anomalous)
            anomaly_score = float(self.model.score_samples(features_array)[0])
            
            # Determine severity
            if anomaly_score > self.anomaly_thresholds['normal']:
                severity = 'normal'
            elif anomaly_score > self.anomaly_thresholds['suspicious']:
                severity = 'suspicious'
            else:
                severity = 'anomalous'
            
            result = {
                'is_anomaly': bool(prediction == -1),
                'anomaly_score': anomaly_score,
                'severity': severity,
                'prediction': 'Anomaly' if prediction == -1 else 'Normal',
                'timestamp': datetime.now().isoformat()
            }
            
            return result
            
        except Exception as e:
            print(f"❌ Prediction error: {e}")
            return {
                'error': str(e),
                'is_anomaly': False,
                'anomaly_score': 0.0
            }
    
    def predict_batch(self, requests_data):
        """Predict multiple requests"""
        results = []
        for request_data in requests_data:
            result = self.predict_anomaly(request_data)
            results.append(result)
        return results


def train_anomaly_detector():
    """Main function to train Isolation Forest"""
    
    print("\n" + "="*70)
    print("🚀 ANOMALY DETECTOR TRAINING PIPELINE")
    print("="*70)
    
    # Initialize
    detector = AnomalyDetector()
    preprocessor = DataPreprocessor()
    
    # Prepare data
    print("\n[STEP 1] Preparing data...")
    X_train, X_test, y_train, y_test = preprocessor.prepare_training_data(
        filepath='data/datasets/csic_database.csv',
        test_size=0.2
    )
    
    if X_train is None:
        print("❌ Data preparation failed!")
        return
    
    # Train on normal traffic only (for better anomaly detection)
    # Filter to get mostly normal traffic
    normal_indices = np.where(y_train == 0)[0]
    X_train_normal = X_train[normal_indices]
    
    print(f"\n[STEP 2] Training on {len(X_train_normal)} normal samples...")
    detector.train_isolation_forest(X_train_normal, contamination=0.1)
    
    # Evaluate
    print("\n[STEP 3] Evaluating detector...")
    metrics = detector.evaluate_on_test_set(X_test, y_test)
    
    # Save
    print("\n[STEP 4] Saving model...")
    detector.save_model()
    
    print("\n" + "="*70)
    print("🎉 ANOMALY DETECTOR TRAINING COMPLETE!")
    print("="*70)
    print(f"✅ Accuracy: {metrics['accuracy']*100:.2f}%")
    print(f"✅ F1-Score: {metrics['f1_score']*100:.2f}%")
    print("\n📁 Generated Files:")
    print("   • data/trained_models/isolation_forest_model.pkl")
    print("   • data/trained_models/isolation_forest_model_metadata.json")
    print("="*70)


if __name__ == "__main__":
    try:
        train_anomaly_detector()
    except KeyboardInterrupt:
        print("\n\n⚠️ Training interrupted by user")
    except Exception as e:
        print(f"\n\n❌ Training failed: {e}")
        import traceback
        traceback.print_exc()