"""
Model Training Module
Author: Person 3 (ML Engineer)
Purpose: Train Random Forest classifier to detect web attacks

This script:
1. Loads and preprocesses CSIC 2010 dataset
2. Trains Random Forest model
3. Evaluates model performance
4. Saves trained model for production use
"""

import sys
import os
import numpy as np
import pandas as pd
from datetime import datetime
import json

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.preprocessing import DataPreprocessor
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score
)
import joblib


class ModelTrainer:
    """Handles Random Forest model training and evaluation"""
    
    def __init__(self):
        self.model = None
        self.preprocessor = DataPreprocessor()
        self.feature_names = self.preprocessor.get_feature_names()
        self.training_metadata = {}
    
    def train_random_forest(self, X_train, y_train, **params):
        """
        Train Random Forest classifier
        
        Args:
            X_train: Training features
            y_train: Training labels
            **params: Model hyperparameters
            
        Returns:
            Trained model
        """
        print("\n" + "="*70)
        print("🌲 TRAINING RANDOM FOREST CLASSIFIER")
        print("="*70)
        
        # Default hyperparameters (optimized for WAF detection)
        default_params = {
            'n_estimators': 100,        # Number of trees
            'max_depth': 20,             # Maximum tree depth
            'min_samples_split': 5,      # Minimum samples to split node
            'min_samples_leaf': 2,       # Minimum samples in leaf
            'max_features': 'sqrt',      # Features to consider for split
            'random_state': 42,          # Reproducibility
            'n_jobs': -1,                # Use all CPU cores
            'class_weight': 'balanced',  # Handle imbalanced data
            'verbose': 1                 # Show progress
        }
        
        # Override with user params
        default_params.update(params)
        
        print(f"\n📋 Model Parameters:")
        for key, value in default_params.items():
            print(f"   {key}: {value}")
        
        # Initialize and train model
        print(f"\n🏋️ Training on {len(X_train)} samples...")
        self.model = RandomForestClassifier(**default_params)
        
        start_time = datetime.now()
        self.model.fit(X_train, y_train)
        training_time = (datetime.now() - start_time).total_seconds()
        
        print(f"✅ Training completed in {training_time:.2f} seconds!")
        
        # Store metadata
        self.training_metadata['training_time'] = training_time
        self.training_metadata['n_samples'] = len(X_train)
        self.training_metadata['model_params'] = default_params
        
        return self.model
    
    def evaluate_model(self, X_test, y_test):
        """
        Evaluate model performance on test set
        
        Args:
            X_test: Test features
            y_test: Test labels
            
        Returns:
            Dictionary of evaluation metrics
        """
        print("\n" + "="*70)
        print("📊 EVALUATING MODEL PERFORMANCE")
        print("="*70)
        
        # Make predictions
        y_pred = self.model.predict(X_test)
        y_pred_proba = self.model.predict_proba(X_test)[:, 1]
        
        # Calculate metrics
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred, zero_division=0)
        recall = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        roc_auc = roc_auc_score(y_test, y_pred_proba)
        
        # Confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        tn, fp, fn, tp = cm.ravel()
        
        # False positive rate and False negative rate
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
        
        print(f"\n🎯 OVERALL METRICS:")
        print(f"   Accuracy:  {accuracy*100:.2f}%")
        print(f"   Precision: {precision*100:.2f}%")
        print(f"   Recall:    {recall*100:.2f}%")
        print(f"   F1-Score:  {f1*100:.2f}%")
        print(f"   ROC-AUC:   {roc_auc*100:.2f}%")
        
        print(f"\n📉 ERROR RATES:")
        print(f"   False Positive Rate: {fpr*100:.2f}% (Normal flagged as Attack)")
        print(f"   False Negative Rate: {fnr*100:.2f}% (Attack missed)")
        
        print(f"\n🔢 CONFUSION MATRIX:")
        print(f"                    Predicted")
        print(f"                Normal  Attack")
        print(f"   Actual Normal  {tn:6d}  {fp:6d}")
        print(f"   Actual Attack  {fn:6d}  {tp:6d}")
        
        print(f"\n📋 DETAILED CLASSIFICATION REPORT:")
        print(classification_report(y_test, y_pred, 
                                   target_names=['Normal', 'Attack'],
                                   digits=4))
        
        # Feature importance
        print(f"\n🔝 TOP 10 MOST IMPORTANT FEATURES:")
        feature_importance = pd.DataFrame({
            'feature': self.feature_names,
            'importance': self.model.feature_importances_
        }).sort_values('importance', ascending=False)
        
        for idx, row in feature_importance.head(10).iterrows():
            print(f"   {row['feature']:25s}: {row['importance']:.4f}")
        
        # Store metrics
        metrics = {
            'accuracy': float(accuracy),
            'precision': float(precision),
            'recall': float(recall),
            'f1_score': float(f1),
            'roc_auc': float(roc_auc),
            'false_positive_rate': float(fpr),
            'false_negative_rate': float(fnr),
            'confusion_matrix': {
                'true_negative': int(tn),
                'false_positive': int(fp),
                'false_negative': int(fn),
                'true_positive': int(tp)
            },
            'feature_importance': feature_importance.to_dict('records')
        }
        
        self.training_metadata['evaluation_metrics'] = metrics
        
        return metrics
    
    def save_model(self, model_path='data/trained_models/random_forest_model.pkl'):
        """
        Save trained model to disk
        
        Args:
            model_path: Path to save model
        """
        print("\n" + "="*70)
        print("💾 SAVING MODEL")
        print("="*70)
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        
        # Save model
        joblib.dump(self.model, model_path)
        print(f"✅ Model saved to: {model_path}")
        
        # Save metadata
        metadata_path = model_path.replace('.pkl', '_metadata.json')
        self.training_metadata['trained_at'] = datetime.now().isoformat()
        self.training_metadata['model_path'] = model_path
        self.training_metadata['feature_names'] = self.feature_names
        
        with open(metadata_path, 'w') as f:
            json.dump(self.training_metadata, f, indent=4)
        print(f"✅ Metadata saved to: {metadata_path}")
        
        # Calculate model size
        model_size = os.path.getsize(model_path) / (1024 * 1024)  # MB
        print(f"📦 Model size: {model_size:.2f} MB")
    
    def load_model(self, model_path='data/trained_models/random_forest_model.pkl'):
        """
        Load trained model from disk
        
        Args:
            model_path: Path to model file
            
        Returns:
            Loaded model
        """
        self.model = joblib.load(model_path)
        print(f"✅ Model loaded from: {model_path}")
        return self.model


def main():
    """Main training pipeline"""
    
    print("\n" + "="*70)
    print("🚀 AI-WAF MODEL TRAINING PIPELINE")
    print("="*70)
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Initialize trainer
    trainer = ModelTrainer()
    
    # Step 1: Prepare data
    print("\n[STEP 1] Preparing training data...")
    X_train, X_test, y_train, y_test = trainer.preprocessor.prepare_training_data(
        filepath='data/datasets/csic_database.csv',
        test_size=0.2
    )
    
    if X_train is None:
        print("❌ Data preparation failed! Exiting...")
        return
    
    # Step 2: Train model
    print("\n[STEP 2] Training Random Forest model...")
    trainer.train_random_forest(X_train, y_train)
    
    # Step 3: Evaluate model
    print("\n[STEP 3] Evaluating model...")
    metrics = trainer.evaluate_model(X_test, y_test)
    
    # Step 4: Save model
    print("\n[STEP 4] Saving model...")
    trainer.save_model()
    
    # Summary
    print("\n" + "="*70)
    print("🎉 TRAINING COMPLETE!")
    print("="*70)
    print(f"✅ Model Accuracy: {metrics['accuracy']*100:.2f}%")
    print(f"✅ Model F1-Score: {metrics['f1_score']*100:.2f}%")
    print(f"✅ False Positive Rate: {metrics['false_positive_rate']*100:.2f}%")
    print(f"✅ False Negative Rate: {metrics['false_negative_rate']*100:.2f}%")
    print("\n📁 Generated Files:")
    print("   • data/trained_models/random_forest_model.pkl")
    print("   • data/trained_models/random_forest_model_metadata.json")
    print("   • data/trained_models/scaler.pkl")
    print("\n🎯 NEXT STEPS:")
    print("   1. Review model performance metrics above")
    print("   2. Create ml_model.py for predictions")
    print("   3. Integrate with Person 1's WAF interceptor")
    print("="*70)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️ Training interrupted by user")
    except Exception as e:
        print(f"\n\n❌ Training failed with error: {e}")
        import traceback
        traceback.print_exc()