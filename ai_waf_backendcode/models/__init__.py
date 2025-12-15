"""
Models Package
Author: Person 3 (ML Engineer)

This package contains ML models and training scripts for the AI-WAF system.

Modules:
    - train_model: Train Random Forest classifier
    - ml_model: Load model and make predictions
    - anomaly_detector: Isolation Forest for anomaly detection
"""

from .ml_model import MLModel
from .anomaly_detector import AnomalyDetector

__all__ = ['MLModel', 'AnomalyDetector']
__version__ = '1.0.0'
__author__ = 'Person 3 (ML Engineer)'