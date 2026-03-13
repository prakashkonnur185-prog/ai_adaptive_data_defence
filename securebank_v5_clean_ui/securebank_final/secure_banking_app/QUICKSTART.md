# 🚀 Quick Start Guide - SecureBank

## Get Started in 5 Minutes

### Step 1: Navigate to Project
```bash
cd secure_banking_app
```

### Step 2: Install Dependencies
```bash
pip install -r requirements.txt --break-system-packages
```

### Step 3: Generate Training Data
```bash
python3 generate_training_data.py
```
Expected output: `Generated 1050 sessions`

### Step 4: Train the ML Model
```bash
python3 train_model.py
```
Expected output: `Model saved to: models/risk_model.pkl`

### Step 5: Start the Application
```bash
python3 app.py
```

### Step 6: Open Browser
Navigate to: **http://localhost:5000**

### Step 7: Login
Use demo credentials:
- **Customer ID:** `customer001`
- **Password:** `SecurePass123!`

---

## What You'll See

### Login Page
- Clean, professional banking interface
- Demo credentials displayed for convenience
- Secure password entry

### Dashboard (Low Risk Session)
- **Green Risk Indicator** (Score: 0-30)
- Real account information:
  - Name: Alice Johnson
  - Account: 1234-5678
  - Balance: $12,450.75
- Real transaction history

### Dashboard (High Risk Session)
- **Red Risk Indicator** (Score: 70-100)
- Honeypot activated!
- Fake account data displayed
- Security team alerted

---

## Testing Scenarios

### Test 1: Normal User (Low Risk)
1. Login with correct credentials on first try
2. Access during business hours
3. Navigate normally
4. Expected: Green indicator, real data

### Test 2: Suspicious Activity (High Risk)
Simulate an attack by modifying features in `app.py`:
```python
# In extract_session_features(), temporarily add:
features = {
    'login_attempts': 5,
    'request_rate': 35.0,
    'ip_changed': 1,
    'device_changed': 1,
    'transaction_amount': 25000.0,
    'session_duration': 1.5,
    'hour_of_day': 3,
    'day_of_week': 6
}
```
Then login and see honeypot activation!

---

## Check the Logs

### View All Activity
```bash
cat logs/security.log
```

### View High-Risk Alerts Only
```bash
cat logs/high_risk_alerts.log
```

### Count Sessions
```bash
grep "login" logs/security.log | wc -l
```

---

## Understanding Risk Scores

| Risk Score | Level | Color | Response |
|------------|-------|-------|----------|
| 0-29 | Low | Green | Show real data |
| 30-69 | Medium | Yellow | Show real data + monitor |
| 70-100 | High | Red | Activate honeypot |

---

## Project Files

```
secure_banking_app/
├── app.py                    # Main Flask backend
├── train_model.py            # ML model training
├── generate_training_data.py # Synthetic data generator
├── honeypot.py              # Fake data generator
├── templates/
│   ├── index.html           # Login page
│   └── dashboard.html       # Dashboard page
├── models/
│   ├── risk_model.pkl       # Trained model
│   └── scaler.pkl           # Feature scaler
├── logs/
│   ├── security.log         # All activity
│   └── high_risk_alerts.log # High-risk only
└── data/
    └── training_data.csv    # Training dataset
```

---

## Key Features

✅ **Real-time Anomaly Detection** - ML-powered risk scoring
✅ **Behavioral Analysis** - Learns normal user patterns
✅ **Honeypot System** - Automatic fake data for attackers
✅ **Defense-First Architecture** - All security in backend
✅ **Comprehensive Logging** - Full audit trail
✅ **Zero Trust** - Continuous verification

---

## Learning Objectives

This project teaches:
1. **Cybersecurity**: Anomaly detection, honeypots, defense-in-depth
2. **Machine Learning**: Isolation Forest, unsupervised learning
3. **Web Security**: Session management, authentication, secure design
4. **Full-Stack Development**: Flask backend, HTML frontend

---

## Need Help?

- **Full Documentation**: See `README.md`
- **Testing Guide**: See `TESTING_GUIDE.md`
- **Architecture Details**: See `ARCHITECTURE.md`

---

## Demo Credentials

### User 1
- **ID**: customer001
- **Password**: SecurePass123!
- **Account**: Alice Johnson - $12,450.75

### User 2
- **ID**: customer002
- **Password**: BankDemo456!
- **Account**: Bob Martinez - $25,300.50

---

**Built for Education** | **Cybersecurity & ML Learning** | **Production-Ready Architecture**
