"""
ML Model Inference Module
Author: Person 3 (ML Engineer)
Purpose: Load trained models and make predictions on incoming requests

This module provides the interface for Person 1 to use the trained ML models
for real-time threat detection.
"""

import joblib
import numpy as np
import json
import os
import sys
from datetime import datetime

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.feature_extraction import FeatureExtractor


class MLModel:
    """
    Handles ML model loading and predictions for WAF
    """
    
    def __init__(self, model_path='data/trained_models/random_forest_model.pkl',
                 scaler_path='data/trained_models/scaler.pkl'):
        """
        Initialize ML model
        
        Args:
            model_path: Path to trained Random Forest model
            scaler_path: Path to fitted scaler
        """
        self.model = None
        self.scaler = None
        self.feature_extractor = FeatureExtractor()
        self.model_path = model_path
        self.scaler_path = scaler_path
        self.metadata = None
        self.is_loaded = False
        
        # Attack type mapping
        self.attack_types = {
            0: 'Normal',
            1: 'Attack'
        }
        
        # Threat severity thresholds
        self.severity_thresholds = {
            'low': 0.3,      # 0.0 - 0.3
            'medium': 0.6,   # 0.3 - 0.6
            'high': 0.85,    # 0.6 - 0.85
            'critical': 1.0  # 0.85 - 1.0
        }
    
    def load_model(self):
        """
        Load trained model and scaler from disk
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            print(f"🔄 Loading ML model from {self.model_path}...")
            
            # Check if files exist
            if not os.path.exists(self.model_path):
                print(f"❌ Model file not found: {self.model_path}")
                return False
            
            if not os.path.exists(self.scaler_path):
                print(f"❌ Scaler file not found: {self.scaler_path}")
                return False
            
            # Load model
            self.model = joblib.load(self.model_path)
            print(f"✅ Random Forest model loaded successfully")
            
            # Load scaler
            self.scaler = joblib.load(self.scaler_path)
            print(f"✅ Feature scaler loaded successfully")
            
            # Load metadata
            metadata_path = self.model_path.replace('.pkl', '_metadata.json')
            if os.path.exists(metadata_path):
                with open(metadata_path, 'r') as f:
                    self.metadata = json.load(f)
                print(f"✅ Model metadata loaded")
                
                # Print model info
                if 'evaluation_metrics' in self.metadata:
                    metrics = self.metadata['evaluation_metrics']
                    print(f"\n📊 Model Performance:")
                    print(f"   Accuracy: {metrics.get('accuracy', 0)*100:.2f}%")
                    print(f"   F1-Score: {metrics.get('f1_score', 0)*100:.2f}%")
                    print(f"   False Positive Rate: {metrics.get('false_positive_rate', 0)*100:.2f}%")
            
            self.is_loaded = True
            return True
            
        except Exception as e:
            print(f"❌ Error loading model: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def extract_and_scale_features(self, request_data):
        """
        Extract features from request and scale them
        
        Args:
            request_data: Dictionary containing request information
            
        Returns:
            numpy array: Scaled features ready for prediction
        """
        # Extract features using Person 1's feature extractor
        features = self.feature_extractor.extract_features(request_data)
        
        # Convert to numpy array and reshape for single prediction
        features_array = np.array(features).reshape(1, -1)
        
        # Scale features
        features_scaled = self.scaler.transform(features_array)
        
        return features_scaled
    
    def predict(self, request_data):
        """
        Predict if request is malicious or benign
        
        Args:
            request_data: Dictionary containing request information
            
        Returns:
            dict: Prediction results with threat level and confidence
        """
        if not self.is_loaded:
            success = self.load_model()
            if not success:
                return {
                    'error': 'Model not loaded',
                    'is_attack': False,
                    'confidence': 0.0,
                    'threat_level': 'unknown'
                }
        
        try:
            # Extract and scale features
            features_scaled = self.extract_and_scale_features(request_data)
            
            # Make prediction
            prediction = self.model.predict(features_scaled)[0]
            probabilities = self.model.predict_proba(features_scaled)[0]
            
            # Get confidence (probability of predicted class)
            confidence = float(probabilities[prediction])
            attack_probability = float(probabilities[1])  # Probability of attack
            
            # Determine threat level based on attack probability
            threat_level = self.calculate_threat_level(attack_probability)
            
            # Prepare result
            result = {
                'is_attack': bool(prediction == 1),
                'prediction': self.attack_types[prediction],
                'confidence': confidence,
                'attack_probability': attack_probability,
                'threat_level': threat_level,
                'probabilities': {
                    'normal': float(probabilities[0]),
                    'attack': float(probabilities[1])
                },
                'timestamp': datetime.now().isoformat()
            }
            
            return result
            
        except Exception as e:
            print(f"❌ Prediction error: {e}")
            import traceback
            traceback.print_exc()
            return {
                'error': str(e),
                'is_attack': False,
                'confidence': 0.0,
                'threat_level': 'unknown'
            }
    
    def predict_batch(self, requests_data):
        """
        Predict multiple requests at once (for efficiency)
        
        Args:
            requests_data: List of request dictionaries
            
        Returns:
            list: List of prediction results
        """
        if not self.is_loaded:
            self.load_model()
        
        results = []
        for request_data in requests_data:
            result = self.predict(request_data)
            results.append(result)
        
        return results
    
    def calculate_threat_level(self, attack_probability):
        """
        Calculate threat severity level based on attack probability
        
        Args:
            attack_probability: Probability that request is an attack (0-1)
            
        Returns:
            str: Threat level (low, medium, high, critical)
        """
        if attack_probability < self.severity_thresholds['low']:
            return 'low'
        elif attack_probability < self.severity_thresholds['medium']:
            return 'medium'
        elif attack_probability < self.severity_thresholds['high']:
            return 'high'
        else:
            return 'critical'
    
    def get_feature_importance(self, top_n=10):
        """
        Get top N most important features from the model
        
        Args:
            top_n: Number of top features to return
            
        Returns:
            list: Feature names and importance scores
        """
        if not self.is_loaded:
            return []
        
        feature_names = self.feature_extractor.get_feature_names()
        importance_scores = self.model.feature_importances_
        
        # Create list of (feature, importance) tuples
        features_with_importance = list(zip(feature_names, importance_scores))
        
        # Sort by importance (descending)
        features_with_importance.sort(key=lambda x: x[1], reverse=True)
        
        # Return top N
        return features_with_importance[:top_n]
    
    def get_model_info(self):
        """
        Get information about the loaded model
        
        Returns:
            dict: Model information
        """
        if not self.is_loaded:
            return {'error': 'Model not loaded'}
        
        info = {
            'model_type': 'Random Forest Classifier',
            'model_loaded': self.is_loaded,
            'model_path': self.model_path,
            'n_features': len(self.feature_extractor.get_feature_names()),
            'feature_names': self.feature_extractor.get_feature_names()
        }
        
        # Add metadata if available
        if self.metadata:
            info['metadata'] = self.metadata
        
        return info


# Standalone testing
if __name__ == "__main__":
    """
    Test the ML model with sample requests
    Run: python ml_model.py
    """
    print("="*70)
    print("ML MODEL INFERENCE TESTING")
    print("="*70)
    
    # Initialize model
    ml_model = MLModel()
    
    # Load model
    if not ml_model.load_model():
        print("\n❌ Failed to load model. Make sure you've trained the model first!")
        print("Run: python models/train_model.py")
        exit(1)
    
    print("\n" + "="*70)
    print("TESTING PREDICTIONS")
    print("="*70)
    
    # Test 1: Normal Request
    print("\n[TEST 1] Normal Request:")
    normal_request = {
        'url': 'http://localhost:8080/products?category=electronics',
        'path': '/products',
        'query_string': 'category=electronics',
        'body': '',
        'method': 'GET'
    }
    result = ml_model.predict(normal_request)
    print(f"Prediction: {result['prediction']}")
    print(f"Confidence: {result['confidence']*100:.2f}%")
    print(f"Threat Level: {result['threat_level']}")
    print(f"Attack Probability: {result['attack_probability']*100:.2f}%")
    
    # Test 2: SQL Injection
    print("\n[TEST 2] SQL Injection Attack:")
    sql_injection = {
        'url': "http://localhost:8080/login?user=admin' OR '1'='1&pass=x",
        'path': '/login',
        'query_string': "user=admin' OR '1'='1&pass=x",
        'body': '',
        'method': 'POST'
    }
    result = ml_model.predict(sql_injection)
    print(f"Prediction: {result['prediction']}")
    print(f"Confidence: {result['confidence']*100:.2f}%")
    print(f"Threat Level: {result['threat_level']}")
    print(f"Attack Probability: {result['attack_probability']*100:.2f}%")
    
    # Test 3: XSS Attack
    print("\n[TEST 3] XSS Attack:")
    xss_attack = {
        'url': 'http://localhost:8080/comment?text=<script>alert(document.cookie)</script>',
        'path': '/comment',
        'query_string': 'text=<script>alert(document.cookie)</script>',
        'body': '',
        'method': 'POST'
    }
    result = ml_model.predict(xss_attack)
    print(f"Prediction: {result['prediction']}")
    print(f"Confidence: {result['confidence']*100:.2f}%")
    print(f"Threat Level: {result['threat_level']}")
    print(f"Attack Probability: {result['attack_probability']*100:.2f}%")
    
    # Show feature importance
    print("\n[FEATURE IMPORTANCE] Top 10 Features:")
    top_features = ml_model.get_feature_importance(top_n=10)
    for feature, importance in top_features:
        print(f"   {feature:25s}: {importance:.4f}")
    
    print("\n" + "="*70)
    print("TESTING COMPLETE")
    print("="*70)