"""
Generate synthetic training data for anomaly detection model.
This simulates normal user behavior patterns.
"""

import pandas as pd
import numpy as np
import json
from datetime import datetime, timedelta

np.random.seed(42)

def generate_normal_sessions(n_sessions=1000):
    """Generate normal user behavior sessions"""
    sessions = []
    
    for i in range(n_sessions):
        # Normal user behavior characteristics
        login_attempts = np.random.choice([1, 2], p=[0.85, 0.15])  # Usually successful on first try
        request_rate = np.random.normal(5, 2)  # 5 requests per minute average
        request_rate = max(1, min(15, request_rate))  # Clip between 1-15
        
        ip_changed = np.random.choice([0, 1], p=[0.95, 0.05])  # Rarely changes IP
        device_changed = np.random.choice([0, 1], p=[0.98, 0.02])  # Very rarely changes device
        
        # Normal transaction amounts (small to medium)
        transaction_amount = np.random.lognormal(6, 1.5)  # Mean around $403
        transaction_amount = min(transaction_amount, 5000)  # Cap at $5000 for normal
        
        # Normal session duration (5-30 minutes)
        session_duration = np.random.normal(15, 5)  
        session_duration = max(2, min(40, session_duration))
        
        # Time-based features (normal business hours)
        hour_of_day = np.random.choice(range(24), p=get_hour_distribution())
        day_of_week = np.random.choice(range(7), p=get_day_distribution())
        
        sessions.append({
            'login_attempts': login_attempts,
            'request_rate': round(request_rate, 2),
            'ip_changed': ip_changed,
            'device_changed': device_changed,
            'transaction_amount': round(transaction_amount, 2),
            'session_duration': round(session_duration, 2),
            'hour_of_day': hour_of_day,
            'day_of_week': day_of_week,
            'is_anomaly': 0  # Label as normal
        })
    
    return sessions

def generate_anomalous_sessions(n_sessions=50):
    """Generate anomalous/suspicious behavior sessions"""
    sessions = []
    
    for i in range(n_sessions):
        # Anomalous behavior characteristics
        login_attempts = np.random.choice([3, 4, 5, 6], p=[0.3, 0.3, 0.2, 0.2])
        request_rate = np.random.normal(25, 10)  # High request rate
        request_rate = max(15, min(100, request_rate))
        
        ip_changed = np.random.choice([0, 1], p=[0.3, 0.7])  # Often changes IP
        device_changed = np.random.choice([0, 1], p=[0.4, 0.6])  # Often changes device
        
        # Unusual transaction amounts
        transaction_amount = np.random.choice([
            np.random.uniform(10000, 50000),  # Very large
            np.random.uniform(0.01, 1)  # Very small (testing)
        ])
        
        # Unusual session duration
        session_duration = np.random.choice([
            np.random.uniform(0.5, 2),  # Very short
            np.random.uniform(60, 180)  # Very long
        ])
        
        # Time-based features (odd hours)
        hour_of_day = np.random.choice(range(24), p=get_anomalous_hour_distribution())
        day_of_week = np.random.randint(0, 7)
        
        sessions.append({
            'login_attempts': login_attempts,
            'request_rate': round(request_rate, 2),
            'ip_changed': ip_changed,
            'device_changed': device_changed,
            'transaction_amount': round(transaction_amount, 2),
            'session_duration': round(session_duration, 2),
            'hour_of_day': hour_of_day,
            'day_of_week': day_of_week,
            'is_anomaly': 1  # Label as anomalous
        })
    
    return sessions

def get_hour_distribution():
    """Normal users prefer business hours"""
    dist = np.ones(24) * 0.01  # Base probability
    # Higher probability during business hours (9 AM - 6 PM)
    dist[9:18] = 0.08
    # Moderate probability morning and evening
    dist[6:9] = 0.04
    dist[18:22] = 0.04
    return dist / dist.sum()

def get_anomalous_hour_distribution():
    """Anomalous activity at odd hours"""
    dist = np.ones(24) * 0.03
    # Higher probability at night
    dist[0:6] = 0.08
    dist[22:24] = 0.08
    return dist / dist.sum()

def get_day_distribution():
    """Normal users prefer weekdays"""
    # Mon-Fri higher probability
    dist = np.array([0.18, 0.18, 0.18, 0.18, 0.18, 0.05, 0.05])
    return dist

if __name__ == "__main__":
    print("Generating synthetic training data...")
    
    # Generate sessions
    normal_sessions = generate_normal_sessions(1000)
    anomalous_sessions = generate_anomalous_sessions(50)
    
    # Combine and shuffle
    all_sessions = normal_sessions + anomalous_sessions
    np.random.shuffle(all_sessions)
    
    # Create DataFrame
    df = pd.DataFrame(all_sessions)
    
    # Save to CSV
    df.to_csv('data/training_data.csv', index=False)
    
    print(f"Generated {len(df)} sessions:")
    print(f"  Normal sessions: {len(normal_sessions)}")
    print(f"  Anomalous sessions: {len(anomalous_sessions)}")
    print(f"\nData saved to data/training_data.csv")
    print(f"\nFeature statistics:")
    print(df.describe())
    print(f"\nClass distribution:")
    print(df['is_anomaly'].value_counts())
