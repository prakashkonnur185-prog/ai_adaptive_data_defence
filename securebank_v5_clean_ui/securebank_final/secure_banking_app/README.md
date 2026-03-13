# SecureBank: AI-Powered Banking Security System

A comprehensive end-to-end banking web application with real-time cybersecurity anomaly detection using machine learning. This project demonstrates a defense-first architecture where security logic resides entirely in the backend.

## 🏗️ Architecture Overview

### Frontend (Thin Client)
- **Login Page** (`index.html`): Credential submission only
- **Dashboard** (`dashboard.html`): Display-only interface
- **No Security Logic**: All authentication and risk assessment happens server-side

### Backend (Flask)
- **Authentication**: Secure password hashing and session management
- **Risk Scoring**: Real-time ML-based anomaly detection
- **Session Tracking**: Behavioral feature extraction
- **Honeypot Activation**: Automatic fake data generation for high-risk sessions
- **Security Logging**: Comprehensive activity monitoring

### Machine Learning
- **Algorithm**: Isolation Forest (unsupervised anomaly detection)
- **Training Data**: Behavioral patterns (not attack signatures)
- **Features**: Login attempts, request rate, IP changes, device changes, transaction amounts, session duration, time-based patterns

## 📁 Project Structure

```
secure_banking_app/
├── app.py                          # Flask backend (main application)
├── train_model.py                  # ML model training script
├── generate_training_data.py       # Synthetic data generator
├── honeypot.py                     # Fake data generator
├── requirements.txt                # Python dependencies
├── templates/
│   ├── index.html                 # Login page
│   └── dashboard.html             # Account dashboard
├── models/
│   ├── risk_model.pkl             # Trained Isolation Forest model
│   ├── scaler.pkl                 # Feature scaler
│   └── feature_info.json          # Feature metadata
├── logs/
│   ├── security.log               # All activity logs
│   └── high_risk_alerts.log       # High-risk session alerts
└── data/
    └── training_data.csv           # Generated training dataset
```

## 🎯 Key Features

### 1. Behavioral Anomaly Detection
The system learns **normal user behavior** rather than attack patterns:

- **Login Attempts**: Usually 1-2 for legitimate users
- **Request Rate**: 5 requests/minute average for normal sessions
- **IP Stability**: Legitimate users rarely change IPs mid-session
- **Device Consistency**: Real users don't frequently switch devices
- **Transaction Patterns**: Normal amounts vs. unusual large/small transactions
- **Session Duration**: Typical 5-30 minutes for normal banking
- **Time-Based Patterns**: Business hours vs. unusual late-night access

### 2. Risk Scoring System

**Risk Score Calculation:**
```
Anomaly Score (from Isolation Forest) → 0-100 Risk Score
```

**Risk Levels:**
- **Low (0-29)**: Show real account data
- **Medium (30-69)**: Log and monitor
- **High (70-100)**: Activate honeypot

### 3. Honeypot System

When high-risk activity is detected:
- Generate realistic but **fake** account data
- Create **fake** transaction history
- Display to attacker while logging activity
- Alert security team without tipping off attacker

### 4. Defense-First Architecture

**Security Principles:**
✅ All authentication in backend
✅ No credentials in frontend code
✅ Session-based security
✅ Comprehensive logging
✅ Real-time risk assessment
✅ Automatic threat response

## 🚀 Setup Instructions

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Installation

1. **Navigate to project directory:**
```bash
cd secure_banking_app
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Generate training data:**
```bash
python generate_training_data.py
```

Expected output:
```
Generated 1050 sessions:
  Normal sessions: 1000
  Anomalous sessions: 50
Data saved to data/training_data.csv
```

4. **Train the ML model:**
```bash
python train_model.py
```

Expected output:
```
Training Isolation Forest...
Training completed!
Model saved to: models/risk_model.pkl
```

5. **Run the application:**
```bash
python app.py
```

The server will start at `http://localhost:5000`

## 🔐 Demo Credentials

### User 1 (Normal Profile)
- **Customer ID**: `customer001`
- **Password**: `SecurePass123!`
- **Account**: Alice Johnson - Checking Account
- **Balance**: $12,450.75

### User 2 (Normal Profile)
- **Customer ID**: `customer002`
- **Password**: `BankDemo456!`
- **Account**: Bob Martinez - Savings Account
- **Balance**: $25,300.50

## 🧪 Testing the System

### Test 1: Normal Login (Low Risk)
1. Use `customer001` with correct credentials
2. Access during business hours
3. Expected: Risk score < 30, real account data shown

### Test 2: Suspicious Behavior (High Risk)
Simulate suspicious activity by:
1. Multiple rapid login attempts (modify session data)
2. Access during odd hours (3 AM)
3. Rapid page requests
4. Expected: Risk score > 70, honeypot activated

### Test 3: Failed Login
1. Use incorrect password
2. Check `logs/security.log` for failed attempt
3. Expected: Login attempts increment

## 📊 Understanding the ML Model

### Isolation Forest Algorithm
- **Type**: Unsupervised anomaly detection
- **Principle**: Anomalies are easier to isolate (fewer splits in tree)
- **Output**: Anomaly score (negative = more anomalous)

### Training Process
1. Generate 1,000 normal + 50 anomalous sessions
2. Extract 8 behavioral features
3. Standardize features using StandardScaler
4. Train Isolation Forest with contamination=5%
5. Save model and scaler for deployment

### Feature Engineering

**Numeric Features:**
- `login_attempts`: Count of attempts before success
- `request_rate`: Requests per minute
- `ip_changed`: Binary (0/1) - IP address changed mid-session
- `device_changed`: Binary (0/1) - Device fingerprint changed
- `transaction_amount`: Dollar amount of transactions
- `session_duration`: Minutes from login to current request
- `hour_of_day`: 0-23 (time-based pattern)
- `day_of_week`: 0-6 (weekday pattern)

## 🔍 Security Logging

### Log Files

**`logs/security.log`** - All activity:
```json
{
  "timestamp": "2026-02-05T10:30:45",
  "customer_id": "customer001",
  "action": "login",
  "risk_score": 15.3,
  "risk_level": "low",
  "ip_address": "192.168.1.100",
  "features": {...}
}
```

**`logs/high_risk_alerts.log`** - Critical alerts only:
```json
{
  "timestamp": "2026-02-05T03:15:22",
  "customer_id": "customer002",
  "action": "honeypot_activated",
  "risk_score": 87.5,
  "risk_level": "high",
  "features": {
    "login_attempts": 5,
    "request_rate": 45.2,
    "ip_changed": 1,
    "hour_of_day": 3
  }
}
```

## 🎓 Educational Value

This project demonstrates:

### Cybersecurity Concepts
- **Defense in Depth**: Multiple security layers
- **Behavioral Analysis**: Learning normal vs. anomalous patterns
- **Honeypots**: Deception-based security
- **Zero Trust**: Continuous verification
- **Incident Response**: Automated threat handling

### Machine Learning Concepts
- **Unsupervised Learning**: No labeled attack data needed
- **Anomaly Detection**: Finding outliers in behavior
- **Feature Engineering**: Creating meaningful behavioral metrics
- **Model Deployment**: Integrating ML into production systems

### Software Engineering
- **Separation of Concerns**: Security logic in backend only
- **Session Management**: Secure user state tracking
- **API Design**: Clean backend endpoints
- **Logging & Monitoring**: Comprehensive audit trails

## 🔒 Security Best Practices Implemented

1. ✅ **Password Hashing**: Using Werkzeug's secure hash functions
2. ✅ **Session Management**: Flask secure sessions with random keys
3. ✅ **No Frontend Secrets**: All sensitive logic server-side
4. ✅ **Input Validation**: Sanitizing user inputs
5. ✅ **HTTPS Ready**: Prepared for SSL/TLS deployment
6. ✅ **Activity Logging**: Complete audit trail
7. ✅ **Risk-Based Authentication**: Adaptive security responses

## 📈 Performance Metrics

Expected model performance:
- **Precision**: ~85-90% (high-risk alerts are accurate)
- **Recall**: ~75-80% (catches most anomalies)
- **False Positive Rate**: ~5-10% (acceptable for banking security)

## 🚨 Important Notes

⚠️ **This is a demonstration system for educational purposes**

**For Production Use:**
- Use a proper database (PostgreSQL, MySQL)
- Implement rate limiting
- Add CAPTCHA for failed login attempts
- Use environment variables for secrets
- Deploy with HTTPS/TLS
- Implement proper key management
- Add multi-factor authentication
- Use professional logging (e.g., ELK stack)
- Implement proper backup and recovery
- Add compliance features (GDPR, PCI DSS)

## 🛠️ Extending the System

### Add More Features
```python
# In app.py, add to extract_session_features():
'failed_login_count': count_failed_logins(customer_id),
'unusual_location': is_location_unusual(ip_address),
'velocity_check': check_transaction_velocity(customer_id)
```

### Improve Model
```python
# In train_model.py, try different algorithms:
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import OneClassSVM
```

### Add More Security Layers
- CAPTCHA after 3 failed attempts
- Email/SMS verification for high-risk sessions
- Biometric authentication
- Device fingerprinting
- Geolocation verification

## 📚 Further Learning

**Recommended Resources:**
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Scikit-learn Anomaly Detection](https://scikit-learn.org/stable/modules/outlier_detection.html)
- [Flask Security Best Practices](https://flask.palletsprojects.com/en/2.3.x/security/)
- [PCI DSS Compliance](https://www.pcisecuritystandards.org/)

## 🤝 Contributing

This is an educational project. Feel free to:
- Add more behavioral features
- Improve the ML model
- Enhance the honeypot generator
- Add visualization dashboards
- Implement additional security measures

## 📄 License

This project is for educational purposes. Use responsibly and ethically.

## 🙋 Support

For questions or improvements, refer to the comprehensive inline code comments and documentation throughout the codebase.

---

**Built with:** Flask, Scikit-learn, Python 3.8+
**Purpose:** Cybersecurity & Machine Learning Education
**Status:** ✅ Fully Functional Demo System
