"""
Train anomaly detection model using Isolation Forest.
The model learns normal user behavior patterns from session logs.
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import os

# Features to use for training
FEATURES = [
    'login_attempts',
    'request_rate',
    'ip_changed',
    'device_changed',
    'transaction_amount',
    'session_duration',
    'hour_of_day',
    'day_of_week'
]

def load_training_data(filepath='data/training_data.csv'):
    """Load and prepare training data"""
    print(f"Loading training data from {filepath}...")
    df = pd.read_csv(filepath)
    
    print(f"Loaded {len(df)} sessions")
    print(f"Features: {', '.join(FEATURES)}")
    
    return df

def train_isolation_forest(X_train, contamination=0.05):
    """
    Train Isolation Forest model.
    
    Args:
        X_train: Training features
        contamination: Expected proportion of anomalies (default 5%)
    
    Returns:
        Trained model
    """
    print(f"\nTraining Isolation Forest...")
    print(f"Contamination rate: {contamination}")
    
    # Isolation Forest parameters
    model = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=42,
        max_samples='auto',
        bootstrap=False,
        n_jobs=-1,
        verbose=1
    )
    
    model.fit(X_train)
    
    print("Training completed!")
    
    return model

def evaluate_model(model, scaler, X_test, y_test):
    """Evaluate model performance"""
    print("\n" + "="*60)
    print("MODEL EVALUATION")
    print("="*60)
    
    # Scale test data
    X_test_scaled = scaler.transform(X_test)
    
    # Predict (-1 for anomaly, 1 for normal)
    predictions = model.predict(X_test_scaled)
    
    # Convert to binary (1 for anomaly, 0 for normal)
    predictions_binary = np.where(predictions == -1, 1, 0)
    
    # Get anomaly scores
    scores = model.score_samples(X_test_scaled)
    
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, predictions_binary))
    
    print("\nClassification Report:")
    print(classification_report(y_test, predictions_binary, 
                                target_names=['Normal', 'Anomaly']))
    
    # Show some example scores
    print("\nExample Anomaly Scores (more negative = more anomalous):")
    for i in range(min(10, len(scores))):
        label = "Anomaly" if y_test.iloc[i] == 1 else "Normal"
        print(f"  Score: {scores[i]:.4f} | True Label: {label}")
    
    return predictions_binary, scores

def convert_score_to_risk(anomaly_score):
    """
    Convert anomaly score to 0-100 risk score.
    More negative scores = higher risk
    """
    # Anomaly scores typically range from -0.5 to 0.5
    # Normalize to 0-100 scale
    risk_score = (1 - (anomaly_score + 0.5)) * 100
    risk_score = max(0, min(100, risk_score))  # Clip to 0-100
    return risk_score

def classify_risk_level(risk_score):
    """Classify risk score into low/medium/high"""
    if risk_score < 30:
        return 'low'
    elif risk_score < 70:
        return 'medium'
    else:
        return 'high'

def main():
    # Create necessary directories
    os.makedirs('models', exist_ok=True)
    os.makedirs('data', exist_ok=True)
    
    # Load data
    df = load_training_data()
    
    # Prepare features and labels
    X = df[FEATURES]
    y = df['is_anomaly']
    
    print(f"\nFeature statistics:")
    print(X.describe())
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"\nTraining set: {len(X_train)} samples")
    print(f"Test set: {len(X_test)} samples")
    
    # Scale features (important for Isolation Forest)
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    
    # Train model (contamination based on actual anomaly rate in training data)
    contamination_rate = y_train.sum() / len(y_train)
    print(f"\nActual anomaly rate in training: {contamination_rate:.2%}")
    
    model = train_isolation_forest(X_train_scaled, contamination=contamination_rate)
    
    # Evaluate model
    predictions, scores = evaluate_model(model, scaler, X_test, y_test)
    
    # Test risk score conversion
    print("\n" + "="*60)
    print("RISK SCORE CONVERSION TEST")
    print("="*60)
    test_scores = [-0.4, -0.2, 0.0, 0.2, 0.4]
    for score in test_scores:
        risk = convert_score_to_risk(score)
        level = classify_risk_level(risk)
        print(f"Anomaly Score: {score:6.2f} → Risk Score: {risk:5.1f} → Level: {level}")
    
    # Save model and scaler
    model_path = 'models/risk_model.pkl'
    scaler_path = 'models/scaler.pkl'
    
    joblib.dump(model, model_path)
    joblib.dump(scaler, scaler_path)
    
    print(f"\n" + "="*60)
    print("MODEL SAVED")
    print("="*60)
    print(f"Model saved to: {model_path}")
    print(f"Scaler saved to: {scaler_path}")
    
    # Save feature names for reference
    feature_info = {
        'features': FEATURES,
        'contamination': float(contamination_rate)
    }
    
    import json
    with open('models/feature_info.json', 'w') as f:
        json.dump(feature_info, f, indent=2)
    
    print(f"Feature info saved to: models/feature_info.json")
    print("\nTraining complete! Model ready for deployment.")

if __name__ == "__main__":
    main()
