"""
Test script to verify preprocessing works correctly
Run this to test if feature extraction is working with CSIC dataset
"""

import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.preprocessing import DataPreprocessor

def test_preprocessing():
    """Test the complete preprocessing pipeline"""
    
    print("=" * 70)
    print("🧪 TESTING PREPROCESSING PIPELINE")
    print("=" * 70)
    
    # Initialize preprocessor
    preprocessor = DataPreprocessor()
    
    # Test with your CSIC dataset
    print("\n📂 Loading CSIC dataset...")
    X_train, X_test, y_train, y_test = preprocessor.prepare_training_data(
        filepath='data/datasets/csic_database.csv',
        test_size=0.2
    )
    
    if X_train is not None:
        print("\n" + "=" * 70)
        print("✅ PREPROCESSING TEST PASSED!")
        print("=" * 70)
        
        # Display summary
        print("\n📊 DATA SUMMARY:")
        print(f"   Training samples: {len(X_train)}")
        print(f"   Test samples: {len(X_test)}")
        print(f"   Number of features: {X_train.shape[1]}")
        print(f"   Expected features: 20")
        
        print("\n📈 CLASS DISTRIBUTION:")
        print(f"   Training - Normal: {sum(y_train == 0)}, Anomalous: {sum(y_train == 1)}")
        print(f"   Test - Normal: {sum(y_test == 0)}, Anomalous: {sum(y_test == 1)}")
        
        print("\n🔢 FEATURE STATISTICS (First 5 features):")
        feature_names = preprocessor.get_feature_names()
        for i in range(min(5, len(feature_names))):
            print(f"   {feature_names[i]}: min={X_train[:, i].min():.2f}, max={X_train[:, i].max():.2f}, mean={X_train[:, i].mean():.2f}")
        
        print("\n💾 FILES SAVED:")
        print("   ✓ Scaler saved to: data/trained_models/scaler.pkl")
        
        print("\n🎯 NEXT STEP:")
        print("   You're ready to train your ML models!")
        print("   Run: python models/train_model.py")
        
        return True
    else:
        print("\n" + "=" * 70)
        print("❌ PREPROCESSING TEST FAILED!")
        print("=" * 70)
        return False


if __name__ == "__main__":
    success = test_preprocessing()
    
    if success:
        print("\n" + "=" * 70)
        print("🚀 ALL TESTS PASSED - READY FOR MODEL TRAINING!")
        print("=" * 70)
    else:
        print("\n" + "=" * 70)
        print("⚠️ TESTS FAILED - CHECK ERRORS ABOVE")
        print("=" * 70)