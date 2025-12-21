"""
ML Model Inference Module
Author: Person 3 (ML Engineer)
Purpose: Load trained models and make predictions on incoming requests

This module provides the interface for Person 1 to use the trained ML models
for real-time threat detection.
"""

import os
import sys
import joblib
import numpy as np
import json

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
        self.model_path = model_path
        self.scaler_path = scaler_path
        self.feature_extractor = FeatureExtractor()
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
            # Convert relative paths to absolute paths
            if not os.path.isabs(self.model_path):
                self.model_path = os.path.join(
                    os.path.dirname(os.path.abspath(__file__)),
                    '..', self.model_path
                )
            if not os.path.isabs(self.scaler_path):
                self.scaler_path = os.path.join(
                    os.path.dirname(os.path.abspath(__file__)),
                    '..', self.scaler_path
                )
            
            # Normalize paths
            self.model_path = os.path.normpath(self.model_path)
            self.scaler_path = os.path.normpath(self.scaler_path)
            
            # Load model
            self.model = joblib.load(self.model_path)
            # Load scaler
            self.scaler = joblib.load(self.scaler_path)
            # Load metadata if exists
            metadata_path = os.path.join(
                os.path.dirname(self.model_path),
                'random_forest_model_metadata.json'
            )
            if os.path.exists(metadata_path):
                with open(metadata_path, 'r') as f:
                    self.metadata = json.load(f)
            self.is_loaded = True
            print(f"✅ Model loaded from {self.model_path}")
            print(f"✅ Scaler loaded from {self.scaler_path}")
            return True
        except Exception as e:
            print(f"❌ Error loading model or scaler: {e}")
            self.is_loaded = False
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
        Predict if a request is normal or attack
        
        Args:
            request_data: dict with request info
            
        Returns:
            dict: prediction, confidence, threat_level, attack_probability, is_attack
        """
        if not self.is_loaded:
            raise RuntimeError("Model not loaded. Call load_model() first.")
        
        try:
            features_scaled = self.extract_and_scale_features(request_data)
            pred = self.model.predict(features_scaled)[0]
            proba = self.model.predict_proba(features_scaled)[0][1] if self.model.n_classes_ > 1 else 1.0
            threat_level = self.calculate_threat_level(proba)
            prediction_label = self.attack_types.get(pred, "Unknown")
            
            return {
                "prediction": prediction_label,
                "confidence": proba,
                "threat_level": threat_level,
                "attack_probability": proba,
                "is_attack": prediction_label == "Attack"
            }
        except Exception as e:
            return {
                "prediction": "Unknown",
                "confidence": 0.0,
                "threat_level": "low",
                "attack_probability": 0.0,
                "is_attack": False,
                "error": str(e)
            }
    
    def predict_batch(self, requests_data):
        """
        Predict on a batch of requests
        
        Args:
            requests_data: list of dicts
            
        Returns:
            list of dicts with predictions
        """
        results = []
        for req in requests_data:
            results.append(self.predict(req))
        return results
    
    def calculate_threat_level(self, attack_probability):
        """
        Map attack probability to threat level
        
        Args:
            attack_probability: Probability that request is an attack (0-1)
            
        Returns:
            str: Threat level (low, medium, high, critical)
        """
        for level, threshold in self.severity_thresholds.items():
            if attack_probability <= threshold:
                return level
        return "critical"
    
    def get_feature_importance(self, top_n=10):
        """
        Return top_n features by importance
        
        Args:
            top_n: Number of top features to return
            
        Returns:
            list: Feature names and importance scores
        """
        if not self.is_loaded or not hasattr(self.model, "feature_importances_"):
            return []
        importances = self.model.feature_importances_
        feature_names = getattr(self.feature_extractor, "feature_names", [f"f{i}" for i in range(len(importances))])
        sorted_idx = np.argsort(importances)[::-1][:top_n]
        return [(feature_names[i], importances[i]) for i in sorted_idx]
    
    def get_model_info(self):
        """
        Return model metadata
        
        Returns:
            dict: Model information
        """
        return self.metadata if self.metadata else {}


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