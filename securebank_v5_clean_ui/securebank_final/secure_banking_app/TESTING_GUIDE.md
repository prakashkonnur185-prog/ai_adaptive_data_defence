# Testing Guide for SecureBank Anomaly Detection System

## Overview
This guide helps you understand and test the various security features of the SecureBank application.

## Test Scenarios

### Scenario 1: Normal User Behavior (Low Risk)

**Objective:** Verify that legitimate users receive low risk scores and see real data.

**Steps:**
1. Open browser to `http://localhost:5000`
2. Login with:
   - Customer ID: `customer001`
   - Password: `SecurePass123!`
3. Access during normal business hours (9 AM - 6 PM)
4. Navigate normally between pages

**Expected Results:**
- Risk score: 0-30 (Low)
- Green risk indicator
- Real account data displayed:
  - Name: Alice Johnson
  - Account: 1234-5678
  - Balance: $12,450.75
- Real transaction history showing actual purchases

**What the System Detects:**
- Single login attempt
- Normal request rate (~5 req/min)
- No IP or device changes
- Normal transaction amounts
- Business hours access

---

### Scenario 2: Multiple Failed Login Attempts (Medium Risk)

**Objective:** Verify that repeated failed logins increase risk score.

**Steps:**
1. Try logging in with wrong password 3-4 times
2. Then login successfully with correct credentials
3. Check the risk indicator on dashboard

**Expected Results:**
- Risk score: 30-70 (Medium)
- Yellow/orange risk indicator
- Real data still shown (monitoring mode)
- Activity logged in `logs/security.log`

**What the System Detects:**
- Multiple login attempts (feature: login_attempts > 2)
- Unusual authentication pattern
- Possible brute force attempt

---

### Scenario 3: Simulated Attack (High Risk)

**Objective:** Trigger honeypot activation through suspicious behavior.

**Simulation Methods:**

#### Method A: Modify Session to Simulate Attack
Edit the feature extraction in `app.py` temporarily:

```python
# In extract_session_features(), add these lines for testing:
features = {
    'login_attempts': 5,  # Multiple failed attempts
    'request_rate': 35.0,  # Very high request rate
    'ip_changed': 1,  # IP changed mid-session
    'device_changed': 1,  # Device changed mid-session
    'transaction_amount': 25000.0,  # Unusually large amount
    'session_duration': 1.5,  # Very short session
    'hour_of_day': 3,  # 3 AM access
    'day_of_week': 6  # Sunday
}
```

#### Method B: Use Request Rate Testing
Create a script `test_attack.py`:

```python
import requests
import time

# Login once
session = requests.Session()
response = session.post('http://localhost:5000/login', data={
    'customer_id': 'customer001',
    'password': 'SecurePass123!'
})

# Make rapid requests
for i in range(50):
    session.get('http://localhost:5000/dashboard')
    time.sleep(0.1)  # Very fast requests
```

**Expected Results:**
- Risk score: 70-100 (High)
- Red risk indicator
- **Honeypot activated** - fake data displayed:
  - Random fake name
  - Fake account number
  - Fake balance
  - Fake transaction history
- Security alert logged in `logs/high_risk_alerts.log`
- Info message: "Suspicious activity detected. Enhanced security active."

**What the System Detects:**
- Abnormal login patterns
- Excessive request rate
- IP/device changes
- Unusual transaction amounts
- Off-hours access
- Very short or very long sessions

---

### Scenario 4: Log Analysis

**Objective:** Understand security logging and monitoring.

**Steps:**
1. Perform various test scenarios
2. Examine log files:

```bash
# View all activity
cat logs/security.log

# View high-risk alerts only
cat logs/high_risk_alerts.log

# Count total sessions
grep "login" logs/security.log | wc -l

# Find honeypot activations
grep "honeypot_activated" logs/security.log
```

**Log Entry Format:**
```json
{
  "timestamp": "2026-02-05T10:30:45",
  "customer_id": "customer001",
  "action": "login",
  "risk_score": 15.3,
  "risk_level": "low",
  "ip_address": "127.0.0.1",
  "features": {
    "login_attempts": 1,
    "request_rate": 5.2,
    "ip_changed": 0,
    "device_changed": 0,
    "transaction_amount": 100.0,
    "session_duration": 2.5,
    "hour_of_day": 10,
    "day_of_week": 3
  }
}
```

---

### Scenario 5: Feature Impact Testing

**Objective:** Understand how individual features affect risk scores.

**Test Matrix:**

| Feature | Normal Value | Anomalous Value | Impact |
|---------|--------------|-----------------|---------|
| login_attempts | 1-2 | 4-6 | High |
| request_rate | 3-8 | 25-50 | High |
| ip_changed | 0 | 1 | Medium |
| device_changed | 0 | 1 | Medium |
| transaction_amount | 10-500 | 10000+ or <1 | High |
| session_duration | 5-30 min | <2 or >60 min | Medium |
| hour_of_day | 9-17 | 0-5, 22-23 | Low |
| day_of_week | 0-4 (Mon-Fri) | 5-6 (Sat-Sun) | Low |

**Testing Approach:**
1. Modify one feature at a time
2. Keep others normal
3. Observe risk score changes
4. Document the relationship

---

### Scenario 6: Model Retraining

**Objective:** Test model improvement with new data.

**Steps:**
1. Collect real usage logs:
```bash
python3 -c "
import pandas as pd
import json

# Parse security logs
logs = []
with open('logs/security.log') as f:
    for line in f:
        logs.append(json.loads(line))

# Convert to DataFrame
df = pd.DataFrame([log['features'] for log in logs])
df['is_anomaly'] = [1 if log['risk_level']=='high' else 0 for log in logs]

# Save as training data
df.to_csv('data/new_training_data.csv', index=False)
print(f'Saved {len(df)} sessions for retraining')
"
```

2. Retrain model:
```bash
python3 train_model.py
```

3. Restart application:
```bash
python3 app.py
```

---

## Understanding Risk Scores

### Risk Score Calculation

```
Isolation Forest Anomaly Score → Risk Score (0-100)

Anomaly Score Range: -0.5 to +0.5
- More negative = more anomalous
- More positive = more normal

Conversion Formula:
risk_score = (1 - (anomaly_score + 0.5)) * 100

Example Conversions:
  -0.40 → 90 (High Risk)
  -0.20 → 70 (High Risk)
   0.00 → 50 (Medium Risk)
   0.20 → 30 (Medium Risk)
   0.40 → 10 (Low Risk)
```

### Risk Level Thresholds

- **Low (0-29)**: Normal behavior, show real data
- **Medium (30-69)**: Slightly unusual, log and monitor
- **High (70-100)**: Highly suspicious, activate honeypot

---

## Performance Metrics

### Model Evaluation

Check model performance after training:

```bash
python3 train_model.py | grep -A 10 "Classification Report"
```

**Target Metrics:**
- Precision (Anomaly class): >85%
- Recall (Anomaly class): >75%
- F1-Score: >80%

### System Performance

Monitor application performance:

```bash
# Count sessions per hour
grep "login" logs/security.log | cut -d'T' -f2 | cut -d':' -f1 | sort | uniq -c

# Average risk score
grep "risk_score" logs/security.log | python3 -c "
import sys, json
scores = [json.loads(line)['risk_score'] for line in sys.stdin]
print(f'Average Risk Score: {sum(scores)/len(scores):.2f}')
"

# False positive rate (legitimate users flagged as high-risk)
# Manually review high_risk_alerts.log
```

---

## Troubleshooting

### Issue: Model not loading
**Solution:**
```bash
# Retrain the model
python3 train_model.py

# Verify files exist
ls -lh models/
```

### Issue: Risk scores always 50
**Solution:** Model may not be loaded. Check console for errors:
```
✗ Error loading model: [Errno 2] No such file or directory: 'models/risk_model.pkl'
```

### Issue: Logs not being created
**Solution:**
```bash
# Create logs directory
mkdir -p logs

# Check permissions
chmod 755 logs
```

### Issue: All sessions showing as high-risk
**Solution:** Check if anomaly detection is too sensitive:
```python
# In train_model.py, adjust contamination parameter:
contamination=0.10  # Increase from 0.05
```

---

## Advanced Testing

### Load Testing
Test system under high load:

```python
# load_test.py
import threading
import requests
import time

def simulate_user(user_id, password):
    session = requests.Session()
    
    # Login
    session.post('http://localhost:5000/login', data={
        'customer_id': user_id,
        'password': password
    })
    
    # Make requests
    for _ in range(10):
        session.get('http://localhost:5000/dashboard')
        time.sleep(1)
    
    # Logout
    session.get('http://localhost:5000/logout')

# Simulate 10 concurrent users
threads = []
for i in range(10):
    t = threading.Thread(target=simulate_user, 
                        args=('customer001', 'SecurePass123!'))
    threads.append(t)
    t.start()

for t in threads:
    t.join()

print("Load test complete!")
```

### A/B Testing Different Models

Compare Isolation Forest vs. One-Class SVM:

```python
# In train_model.py, add:
from sklearn.svm import OneClassSVM

model_svm = OneClassSVM(kernel='rbf', nu=0.05)
model_svm.fit(X_train_scaled)

# Compare performance
```

---

## Security Checklist

Before considering production deployment:

- [ ] Replace demo credentials with database
- [ ] Implement rate limiting
- [ ] Add CAPTCHA
- [ ] Enable HTTPS/TLS
- [ ] Use environment variables for secrets
- [ ] Implement MFA (Multi-Factor Authentication)
- [ ] Add email alerts for high-risk sessions
- [ ] Set up proper logging infrastructure (ELK, Splunk)
- [ ] Implement session timeout
- [ ] Add IP whitelisting option
- [ ] Regular model retraining schedule
- [ ] Security audit and penetration testing
- [ ] Compliance review (PCI DSS, GDPR)

---

## Conclusion

This testing guide covers comprehensive scenarios for validating the SecureBank anomaly detection system. Use it to:
1. Understand system behavior
2. Verify security features
3. Troubleshoot issues
4. Optimize performance
5. Learn cybersecurity concepts

For questions or improvements, refer to the inline code documentation.
