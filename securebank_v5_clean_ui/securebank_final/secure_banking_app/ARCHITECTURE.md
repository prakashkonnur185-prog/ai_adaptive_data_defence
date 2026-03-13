# SecureBank System Architecture

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         USER BROWSER                             │
│  ┌────────────────┐              ┌─────────────────┐            │
│  │  Login Page    │              │   Dashboard     │            │
│  │  (index.html)  │──────────────▶│ (dashboard.html)│            │
│  └────────────────┘              └─────────────────┘            │
│         │                                  ▲                     │
│         │ POST /login                      │ Risk-based          │
│         │                                  │ Data Display        │
└─────────┼──────────────────────────────────┼──────────────────────┘
          │                                  │
          │                                  │
          ▼                                  │
┌─────────────────────────────────────────────────────────────────┐
│                      FLASK BACKEND (app.py)                      │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │              SECURITY CONTROLLER                             ││
│  │  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐││
│  │  │ Authentication │  │ Session Manager│  │ Risk Evaluator │││
│  │  │   - Verify     │  │  - Track IP    │  │ - Extract      │││
│  │  │   - Hash Check │  │  - Device FP   │  │   Features     │││
│  │  │   - Create     │  │  - Request     │  │ - Calculate    │││
│  │  │     Session    │  │    Counting    │  │   Risk Score   │││
│  │  └────────────────┘  └────────────────┘  └────────────────┘││
│  │         │                     │                    │         ││
│  │         └─────────────────────┼────────────────────┘         ││
│  │                               │                              ││
│  │                               ▼                              ││
│  │                    ┌──────────────────────┐                 ││
│  │                    │  Risk Score Decision │                 ││
│  │                    │   if risk < 30:      │                 ││
│  │                    │     → Real Data      │                 ││
│  │                    │   elif risk < 70:    │                 ││
│  │                    │     → Real Data      │                 ││
│  │                    │   else:              │                 ││
│  │                    │     → Honeypot       │                 ││
│  │                    └──────────────────────┘                 ││
│  │                               │                              ││
│  │              ┌────────────────┴────────────────┐            ││
│  │              ▼                                  ▼            ││
│  │   ┌──────────────────┐              ┌──────────────────┐   ││
│  │   │   Real Data      │              │  Honeypot Data   │   ││
│  │   │   - DEMO_USERS   │              │  (honeypot.py)   │   ││
│  │   │   - Real Trans   │              │  - Fake Account  │   ││
│  │   └──────────────────┘              │  - Fake Trans    │   ││
│  │                                     └──────────────────┘   ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                    SECURITY LOGGING                          ││
│  │  ┌─────────────────────────────────────────────────────────┐││
│  │  │  logs/security.log         logs/high_risk_alerts.log    │││
│  │  │  - All activity             - High-risk only            │││
│  │  │  - Timestamps               - Immediate attention       │││
│  │  │  - Features logged          - Alert format              │││
│  │  └─────────────────────────────────────────────────────────┘││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ Uses
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                  MACHINE LEARNING PIPELINE                       │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                   TRAINING PHASE                             ││
│  │  ┌──────────────────────────────────────────────────────┐  ││
│  │  │  1. generate_training_data.py                        │  ││
│  │  │     - Create 1000 normal sessions                    │  ││
│  │  │     - Create 50 anomalous sessions                   │  ││
│  │  │     - Behavioral features                            │  ││
│  │  │     → data/training_data.csv                         │  ││
│  │  └──────────────────────────────────────────────────────┘  ││
│  │                           │                                  ││
│  │                           ▼                                  ││
│  │  ┌──────────────────────────────────────────────────────┐  ││
│  │  │  2. train_model.py                                   │  ││
│  │  │     - Load training data                             │  ││
│  │  │     - Extract 8 features                             │  ││
│  │  │     - StandardScaler normalization                   │  ││
│  │  │     - Train Isolation Forest                         │  ││
│  │  │     - Contamination = 5%                             │  ││
│  │  │     - Save model & scaler                            │  ││
│  │  │     → models/risk_model.pkl                          │  ││
│  │  │     → models/scaler.pkl                              │  ││
│  │  └──────────────────────────────────────────────────────┘  ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                   INFERENCE PHASE                            ││
│  │  ┌──────────────────────────────────────────────────────┐  ││
│  │  │  Real-time Risk Scoring                              │  ││
│  │  │  ┌────────────────────────────────────────────────┐  │  ││
│  │  │  │ 1. Session Features Extraction                 │  │  ││
│  │  │  │    - login_attempts                            │  │  ││
│  │  │  │    - request_rate                              │  │  ││
│  │  │  │    - ip_changed                                │  │  ││
│  │  │  │    - device_changed                            │  │  ││
│  │  │  │    - transaction_amount                        │  │  ││
│  │  │  │    - session_duration                          │  │  ││
│  │  │  │    - hour_of_day                               │  │  ││
│  │  │  │    - day_of_week                               │  │  ││
│  │  │  └────────────────────────────────────────────────┘  │  ││
│  │  │                        │                               │  ││
│  │  │                        ▼                               │  ││
│  │  │  ┌────────────────────────────────────────────────┐  │  ││
│  │  │  │ 2. Feature Scaling (StandardScaler)            │  │  ││
│  │  │  └────────────────────────────────────────────────┘  │  ││
│  │  │                        │                               │  ││
│  │  │                        ▼                               │  ││
│  │  │  ┌────────────────────────────────────────────────┐  │  ││
│  │  │  │ 3. Isolation Forest Prediction                 │  │  ││
│  │  │  │    model.score_samples()                       │  │  ││
│  │  │  │    → Anomaly Score (-0.5 to +0.5)             │  │  ││
│  │  │  └────────────────────────────────────────────────┘  │  ││
│  │  │                        │                               │  ││
│  │  │                        ▼                               │  ││
│  │  │  ┌────────────────────────────────────────────────┐  │  ││
│  │  │  │ 4. Risk Score Conversion                       │  │  ││
│  │  │  │    risk = (1 - (score + 0.5)) * 100           │  │  ││
│  │  │  │    → Risk Score (0-100)                        │  │  ││
│  │  │  └────────────────────────────────────────────────┘  │  ││
│  │  │                        │                               │  ││
│  │  │                        ▼                               │  ││
│  │  │  ┌────────────────────────────────────────────────┐  │  ││
│  │  │  │ 5. Risk Classification                         │  │  ││
│  │  │  │    < 30: Low                                   │  │  ││
│  │  │  │    30-69: Medium                               │  │  ││
│  │  │  │    >= 70: High                                 │  │  ││
│  │  │  └────────────────────────────────────────────────┘  │  ││
│  │  └──────────────────────────────────────────────────────┘  ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

## Data Flow Diagram

```
┌──────────┐
│  User    │
│ Attempts │
│  Login   │
└────┬─────┘
     │
     │ 1. POST credentials
     ▼
┌────────────────────┐
│ Authentication     │
│ - Check password   │──────────┐
│ - Create session   │          │ If invalid
└────────┬───────────┘          │
         │                      │
         │ 2. Valid login       │
         ▼                      ▼
┌────────────────────┐    ┌────────────┐
│ Session Tracking   │    │   Reject   │
│ - Track IP/device  │    │  + Log     │
│ - Count requests   │    └────────────┘
│ - Measure duration │
└────────┬───────────┘
         │
         │ 3. Extract features
         ▼
┌────────────────────┐
│ Feature Vector     │
│ [1, 5.2, 0, 0,    │
│  100, 2.5, 10, 3] │
└────────┬───────────┘
         │
         │ 4. Predict
         ▼
┌────────────────────┐
│ ML Model          │
│ (Isolation Forest) │
│ → Anomaly Score    │
└────────┬───────────┘
         │
         │ 5. Convert
         ▼
┌────────────────────┐
│ Risk Score: 15.3   │
│ Level: LOW         │
└────────┬───────────┘
         │
         │ 6. Decision
         ▼
    ┌────┴────┐
    │   Risk  │
    │  Level? │
    └────┬────┘
         │
    ┌────┴─────────────────────┐
    │                          │
    ▼                          ▼
┌─────────┐              ┌──────────┐
│  LOW /  │              │   HIGH   │
│ MEDIUM  │              │          │
└────┬────┘              └────┬─────┘
     │                        │
     │ 7a. Real data          │ 7b. Honeypot
     ▼                        ▼
┌─────────────────┐    ┌──────────────────┐
│ Show Real       │    │ Show Fake Data   │
│ - Alice Johnson │    │ - Random Name    │
│ - $12,450.75    │    │ - Random Balance │
│ - Real Trans    │    │ - Fake Trans     │
└─────────────────┘    └──────────────────┘
     │                        │
     │                        │ 8. Alert
     │                        ▼
     │                  ┌──────────────────┐
     │                  │ Security Alert   │
     │                  │ → high_risk.log  │
     │                  └──────────────────┘
     │
     │ 9. Log activity
     ▼
┌──────────────────┐
│ security.log     │
│ - Timestamp      │
│ - Customer ID    │
│ - Risk score     │
│ - Features       │
└──────────────────┘
```

## Feature Engineering Pipeline

```
┌─────────────────────────────────────────────────────────────┐
│                   RAW SESSION DATA                          │
│  - HTTP Request                                             │
│  - IP Address                                               │
│  - User-Agent                                               │
│  - Timestamp                                                │
│  - Login attempts                                           │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│              FEATURE EXTRACTION FUNCTIONS                   │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  login_attempts:                                            │
│    ├─ Track: session['login_attempts']                     │
│    └─ Type: Integer (1-6)                                  │
│                                                             │
│  request_rate:                                              │
│    ├─ Calculate: request_count / session_duration_minutes  │
│    └─ Type: Float (1-50 req/min)                           │
│                                                             │
│  ip_changed:                                                │
│    ├─ Compare: current_ip != initial_ip                    │
│    └─ Type: Binary (0/1)                                   │
│                                                             │
│  device_changed:                                            │
│    ├─ Compare: MD5(user_agent) != initial_fingerprint      │
│    └─ Type: Binary (0/1)                                   │
│                                                             │
│  transaction_amount:                                        │
│    ├─ Get: session.get('last_transaction_amount', 100)     │
│    └─ Type: Float (0-50000)                                │
│                                                             │
│  session_duration:                                          │
│    ├─ Calculate: (now - start_time).seconds / 60           │
│    └─ Type: Float (0-180 minutes)                          │
│                                                             │
│  hour_of_day:                                               │
│    ├─ Extract: datetime.now().hour                         │
│    └─ Type: Integer (0-23)                                 │
│                                                             │
│  day_of_week:                                               │
│    ├─ Extract: datetime.now().weekday()                    │
│    └─ Type: Integer (0-6, Mon-Sun)                         │
│                                                             │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                 FEATURE VECTOR OUTPUT                       │
│  [login_attempts, request_rate, ip_changed, device_changed, │
│   transaction_amount, session_duration, hour_of_day,        │
│   day_of_week]                                              │
│                                                             │
│  Example: [1, 5.2, 0, 0, 100.0, 2.5, 10, 3]               │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│              FEATURE STANDARDIZATION                        │
│  StandardScaler:                                            │
│    scaled = (value - mean) / std_dev                       │
│                                                             │
│  Scaled Vector:                                             │
│    [-0.35, 0.15, -0.22, -0.10, -0.45, -1.2, -0.55, 0.42]  │
└─────────────────────────────────────────────────────────────┘
```

## Isolation Forest Algorithm Flow

```
┌─────────────────────────────────────────────────────────────┐
│              ISOLATION FOREST TRAINING                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Input: Training data (1000 normal + 50 anomalous)         │
│                                                             │
│  Step 1: Build 100 isolation trees                         │
│  ┌────────────────────────────────────────────────────┐   │
│  │  For each tree:                                     │   │
│  │    1. Randomly sample data                          │   │
│  │    2. Randomly select feature                       │   │
│  │    3. Randomly select split value                   │   │
│  │    4. Partition data recursively                    │   │
│  │    5. Stop at max_depth or single point             │   │
│  └────────────────────────────────────────────────────┘   │
│                                                             │
│  Principle: Anomalies require fewer splits to isolate      │
│                                                             │
│  Example Tree:                                              │
│       [All Data]                                            │
│          │                                                  │
│    request_rate < 15?                                       │
│      ┌──┴────┐                                             │
│     Yes      No (Anomaly - high rate)                      │
│      │                                                      │
│  ip_changed = 0?                                            │
│   ┌──┴─┐                                                   │
│  Yes   No (Anomaly - IP changed)                           │
│   │                                                         │
│ Normal                                                      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│              ISOLATION FOREST INFERENCE                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Input: New session feature vector                         │
│                                                             │
│  Step 1: Pass through all 100 trees                        │
│  ┌────────────────────────────────────────────────────┐   │
│  │  For each tree:                                     │   │
│  │    - Count splits needed to isolate point           │   │
│  │    - Record path length                             │   │
│  └────────────────────────────────────────────────────┘   │
│                                                             │
│  Step 2: Calculate average path length                     │
│    avg_path_length = mean([tree_1_path, ..., tree_100])   │
│                                                             │
│  Step 3: Compute anomaly score                             │
│    score = 2^(-avg_path_length / c(n))                    │
│    where c(n) = normalization factor                       │
│                                                             │
│  Score interpretation:                                      │
│    - Shorter paths → Higher anomaly score                  │
│    - Longer paths → Lower anomaly score                    │
│                                                             │
│  Output: Anomaly score (-0.5 to +0.5)                     │
│    Negative = anomalous                                     │
│    Positive = normal                                        │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Security Response Decision Tree

```
                    [New Session]
                         │
                         ▼
              ┌──────────────────────┐
              │  Extract Features    │
              └──────────┬───────────┘
                         │
                         ▼
              ┌──────────────────────┐
              │  Calculate Risk Score│
              └──────────┬───────────┘
                         │
                    Risk Score?
                         │
        ┌────────────────┼────────────────┐
        │                │                │
   Risk < 30        30 ≤ Risk < 70    Risk ≥ 70
        │                │                │
        ▼                ▼                ▼
┌───────────────┐ ┌───────────────┐ ┌───────────────┐
│   LOW RISK    │ │  MEDIUM RISK  │ │   HIGH RISK   │
└───────┬───────┘ └───────┬───────┘ └───────┬───────┘
        │                 │                 │
        ▼                 ▼                 ▼
┌───────────────┐ ┌───────────────┐ ┌───────────────┐
│ Show Real     │ │ Show Real     │ │ Activate      │
│ Account Data  │ │ Account Data  │ │ Honeypot      │
└───────┬───────┘ └───────┬───────┘ └───────┬───────┘
        │                 │                 │
        │                 │                 ▼
        │                 │         ┌───────────────┐
        │                 │         │ Generate Fake │
        │                 │         │ Account Data  │
        │                 │         └───────┬───────┘
        │                 │                 │
        │                 │                 ▼
        │                 │         ┌───────────────┐
        │                 ▼         │ Alert Security│
        │         ┌───────────────┐ │ Team          │
        │         │ Log Activity  │ └───────┬───────┘
        │         │ + Monitor     │         │
        │         └───────┬───────┘         │
        │                 │                 │
        ▼                 ▼                 ▼
┌─────────────────────────────────────────────────┐
│           Log to security.log                   │
│  - Timestamp, Customer ID, Risk Score           │
│  - Action, IP, Features                         │
└─────────────────────────────────────────────────┘
                         │
                    Risk ≥ 70?
                         │
                    ┌────┴────┐
                   No        Yes
                    │          │
                    ▼          ▼
            [Continue]  ┌─────────────────┐
                        │ Log to           │
                        │ high_risk.log    │
                        └─────────────────┘
```

## System Components Interaction

```
┌─────────────────────────────────────────────────────────────┐
│                    SESSION LIFECYCLE                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. LOGIN (t=0)                                             │
│     ├─ User submits credentials                            │
│     ├─ Backend validates password                          │
│     ├─ Create session ID                                   │
│     ├─ Initialize session tracking                         │
│     └─ Extract initial features                            │
│                                                             │
│  2. RISK ASSESSMENT (t=0+)                                  │
│     ├─ Calculate risk score                                │
│     ├─ Classify risk level                                 │
│     ├─ Log authentication event                            │
│     └─ Decide data source (real vs honeypot)               │
│                                                             │
│  3. DASHBOARD ACCESS (t=0+)                                 │
│     ├─ User navigates to dashboard                         │
│     ├─ Update session metrics                              │
│     ├─ Recalculate risk (dynamic)                          │
│     ├─ Serve appropriate data                              │
│     └─ Log dashboard access                                │
│                                                             │
│  4. ONGOING MONITORING (t=0+ to t=logout)                   │
│     ├─ Track every request                                 │
│     ├─ Monitor request rate                                │
│     ├─ Detect IP/device changes                            │
│     ├─ Update risk score continuously                      │
│     └─ Switch to honeypot if risk increases                │
│                                                             │
│  5. LOGOUT (t=logout)                                       │
│     ├─ Log logout event                                    │
│     ├─ Calculate final session metrics                     │
│     ├─ Clear session data                                  │
│     └─ Generate session report                             │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

This architecture ensures:
- ✅ Security-first design
- ✅ Real-time threat detection
- ✅ Minimal false positives
- ✅ Comprehensive logging
- ✅ Automated response
- ✅ Scalable ML pipeline
