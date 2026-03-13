from flask import Flask, render_template, request, session, redirect, url_for
import hashlib
import secrets
import random
import re
from datetime import datetime
from honeypot import get_honeypot_data

# -------------------------------------------------
# SQL INJECTION DETECTION
# -------------------------------------------------

SQL_INJECTION_PATTERNS = [
    r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|EXEC|EXECUTE)\b)",
    r"(--|#|/\*|\*/)",
    r"(\bOR\b.{0,10}\d+\s*=+\s*\d+)",
    r"(\bAND\b.{0,10}\d+\s*=+\s*\d+)",
    r"('\s*(OR|AND)\s*')",
    r"(\bOR\b.{0,10}('|\").*(=+).*('|\"))",
    r"(';|\";\s*--|'--)",
    r"(\bxp_\w+)",
    r"(\bWAITFOR\b|\bSLEEP\b)",
    r"(\bINFORMATION_SCHEMA\b)",
    r"(CHAR\s*\(|ASCII\s*\(|CONCAT\s*\()",
    r"(\b0x[0-9a-fA-F]+\b)",
    r"(\d+\s*=+\s*\d+)",
    r"('.*')",
]

def detect_sql_injection(value: str) -> bool:
    """Returns True if the input matches known SQL injection patterns."""
    if not value:
        return False
    value_upper = value.upper()
    for pattern in SQL_INJECTION_PATTERNS:
        if re.search(pattern, value_upper, re.IGNORECASE):
            return True
    return False


app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# ------------------------------------------------
# DEMO USER
# FIX #2 : password stored as plain string under key "password"
# FIX #4 : added missing "available_balance" key
# ------------------------------------------------

DEMO_USERS = {
    "customer001": {
        "password":          "SecurePass123!",  # plain string — compared directly
        "name":              "Alice Johnson",
        "account_number":    "1234-5678",
        "account_type":      "Checking",
        "balance":           12450.75,
        "available_balance": 12450.75,          # was missing → caused KeyError
    }
}

# ------------------------------------------------
# REAL TRANSACTIONS
# ------------------------------------------------

REAL_TRANSACTIONS = {
    "customer001": [
        {"date": "2026-02-04", "description": "Salary Deposit",      "amount": 4500,    "type": "Credit", "status": "Completed"},
        {"date": "2026-02-03", "description": "Whole Foods",          "amount": -125.43, "type": "Debit",  "status": "Completed"},
        {"date": "2026-02-02", "description": "Netflix Subscription", "amount": -15.99,  "type": "Online", "status": "Completed"},
    ]
}

# ------------------------------------------------
# LOCATION DATA
# India & USA = trusted (grant countries) → penalty 0
# ------------------------------------------------

COUNTRY_DATA = {
    # Trusted
    "India":          {"ip": "103.21.58.1",    "flag": "🇮🇳", "region": "South Asia",      "penalty": 0,  "trusted": True},
    "United States":  {"ip": "72.21.215.1",    "flag": "🇺🇸", "region": "North America",   "penalty": 0,  "trusted": True},
    # Low risk
    "United Kingdom": {"ip": "81.2.69.142",    "flag": "🇬🇧", "region": "Europe",          "penalty": 8,  "trusted": False},
    "Germany":        {"ip": "85.214.132.117", "flag": "🇩🇪", "region": "Europe",          "penalty": 8,  "trusted": False},
    "Canada":         {"ip": "99.234.54.1",    "flag": "🇨🇦", "region": "North America",   "penalty": 8,  "trusted": False},
    "Australia":      {"ip": "203.2.218.1",    "flag": "🇦🇺", "region": "Oceania",         "penalty": 8,  "trusted": False},
    "France":         {"ip": "92.222.14.1",    "flag": "🇫🇷", "region": "Europe",          "penalty": 10, "trusted": False},
    "Japan":          {"ip": "133.242.0.1",    "flag": "🇯🇵", "region": "East Asia",       "penalty": 10, "trusted": False},
    "Singapore":      {"ip": "175.41.128.1",   "flag": "🇸🇬", "region": "South-East Asia", "penalty": 10, "trusted": False},
    "UAE":            {"ip": "185.93.1.1",     "flag": "🇦🇪", "region": "Middle East",     "penalty": 12, "trusted": False},
    # Medium risk
    "Brazil":         {"ip": "186.192.0.1",    "flag": "🇧🇷", "region": "South America",   "penalty": 18, "trusted": False},
    "Mexico":         {"ip": "189.240.0.1",    "flag": "🇲🇽", "region": "North America",   "penalty": 18, "trusted": False},
    "Turkey":         {"ip": "212.252.0.1",    "flag": "🇹🇷", "region": "Europe/Asia",     "penalty": 20, "trusted": False},
    "Indonesia":      {"ip": "114.121.0.1",    "flag": "🇮🇩", "region": "South-East Asia", "penalty": 18, "trusted": False},
    "Pakistan":       {"ip": "202.163.0.1",    "flag": "🇵🇰", "region": "South Asia",      "penalty": 22, "trusted": False},
    "Ukraine":        {"ip": "91.232.160.1",   "flag": "🇺🇦", "region": "Eastern Europe",  "penalty": 22, "trusted": False},
    "Vietnam":        {"ip": "103.28.248.1",   "flag": "🇻🇳", "region": "South-East Asia", "penalty": 20, "trusted": False},
    # High risk
    "Russia":         {"ip": "95.213.0.1",     "flag": "🇷🇺", "region": "Eastern Europe",  "penalty": 35, "trusted": False},
    "China":          {"ip": "111.206.0.1",    "flag": "🇨🇳", "region": "East Asia",       "penalty": 35, "trusted": False},
    "Nigeria":        {"ip": "41.184.0.1",     "flag": "🇳🇬", "region": "West Africa",     "penalty": 40, "trusted": False},
    "Iran":           {"ip": "5.200.0.1",      "flag": "🇮🇷", "region": "Middle East",     "penalty": 45, "trusted": False},
    "North Korea":    {"ip": "175.45.176.1",   "flag": "🇰🇵", "region": "East Asia",       "penalty": 60, "trusted": False},
}

# ------------------------------------------------
# TIME SLOTS
# ------------------------------------------------

TIME_SLOTS = [
    {"label": "09:00 AM – 12:00 PM (Morning Business)",   "hour": 9,  "risk_label": "Normal",     "penalty": 0},
    {"label": "12:00 PM – 03:00 PM (Afternoon Business)", "hour": 12, "risk_label": "Normal",     "penalty": 0},
    {"label": "03:00 PM – 06:00 PM (Late Afternoon)",     "hour": 15, "risk_label": "Normal",     "penalty": 0},
    {"label": "06:00 PM – 09:00 PM (Evening)",            "hour": 18, "risk_label": "Low Risk",   "penalty": 5},
    {"label": "09:00 PM – 12:00 AM (Late Night)",         "hour": 21, "risk_label": "Suspicious", "penalty": 15},
    {"label": "12:00 AM – 03:00 AM (Midnight)",           "hour": 0,  "risk_label": "High Risk",  "penalty": 25},
    {"label": "03:00 AM – 06:00 AM (Dead of Night)",      "hour": 3,  "risk_label": "High Risk",  "penalty": 30},
    {"label": "06:00 AM – 09:00 AM (Early Morning)",      "hour": 6,  "risk_label": "Low Risk",   "penalty": 5},
]

# ------------------------------------------------
# GLOBAL TRACKERS
# ------------------------------------------------

session_data     = {}
USER_DEVICES     = {}
FAILED_LOGINS    = {}
USER_RISK        = {}
PRE_LOGIN_FAILED = {}

# ------------------------------------------------
# HELPERS
# ------------------------------------------------

def get_device():
    agent = request.headers.get("User-Agent", "")
    return hashlib.md5(agent.encode()).hexdigest()

def get_ip():
    if request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For").split(",")[0]
    return request.remote_addr

def get_country_info(name):
    return COUNTRY_DATA.get(name, {
        "ip": "0.0.0.0", "flag": "🌐", "region": "Unknown",
        "penalty": 30, "trusted": False
    })

def get_time_penalty(hour):
    """Return (penalty, risk_label) for the given hour."""
    matched = TIME_SLOTS[0]
    for slot in TIME_SLOTS:
        if slot["hour"] <= hour:
            matched = slot
    return matched["penalty"], matched["risk_label"]

# ------------------------------------------------
# TRANSACTION GENERATORS
# ------------------------------------------------

def randomized_transactions():
    merchants = ["Amazon", "Uber", "Starbucks", "Walmart", "Netflix"]
    return [{
        "date":        datetime.now().strftime("%Y-%m-%d"),
        "description": random.choice(merchants),
        "amount":      -random.randint(10, 300),
        "type":        "Debit",
        "status":      "Completed",
    } for _ in range(5)]

def honeypot_data():
    merchants = ["Amazon", "Target", "Shell", "Uber"]
    tx = [{
        "date":        datetime.now().strftime("%Y-%m-%d"),
        "description": random.choice(merchants),
        "amount":      -random.randint(5, 120),
        "type":        "Debit",
        "status":      "Completed",
    } for _ in range(5)]
    return random.randint(200, 400), tx

# ------------------------------------------------
# RISK ENGINE
# is_login=True  → one-time login penalties (location, time, failed logins, device)
# is_login=False → ongoing dashboard checks only (device swap, IP hop, rapid requests)
# Location & time are NEVER re-added after login
# ------------------------------------------------

def calculate_risk(previous_risk, activity):
    risk     = previous_risk
    is_login = activity.get("is_login", False)

    if is_login:
        # ── One-time penalties at login ──
        if activity.get("new_device"):
            risk += 6
        fl = activity.get("failed_logins", 0)
        if fl > 0:  risk += 3
        if fl > 2:  risk += 5
        if fl > 5:  risk += 10
        if fl > 10: risk += 15
        if fl > 15: risk += 25
        risk += activity.get("location_penalty", 0)   # location — once only
        risk += activity.get("time_penalty", 0)        # time     — once only
        # Extra spike: suspicious country AND late-night
        if activity.get("location_penalty", 0) > 0 and activity.get("time_penalty", 0) >= 15:
            risk += 10
    else:
        # ── Ongoing dashboard checks ──
        if activity.get("new_device"):   risk += 6   # device changed mid-session
        if activity.get("new_location"): risk += 4   # IP changed mid-session
        # Rapid requests — tiered, triggers at 6+
        rq = activity.get("request_count", 0)
        if rq > 6:  risk += 3
        if rq > 10: risk += 5
        if rq > 15: risk += 8
        if rq > 20: risk += 12
        if rq > 30: risk += 20

    return min(risk, 100)

# ------------------------------------------------
# SECURITY LOG  (backend only — never shown to user)
# ------------------------------------------------

def security_log(user, risk, activity):
    print("\n🚨========== AI SECURITY MONITOR ==========")
    print(f"USER           : {user}")
    print(f"RISK SCORE     : {risk}")
    print(f"COUNTRY        : {activity.get('country','?')}  TRUSTED: {activity.get('trusted_country',False)}  PENALTY: +{activity.get('location_penalty',0)}")
    print(f"LOGIN HOUR     : {activity.get('login_hour','?')}h  LABEL: {activity.get('time_risk_label','?')}  PENALTY: +{activity.get('time_penalty',0)}")
    status = "✅ SAFE" if risk <= 40 else ("⚠️  SUSPICIOUS" if risk <= 75 else "🚨 HIGH RISK")
    print(f"STATUS         : {status}")
    print("\nFLAGS")
    for k, v in activity.items():
        print(f"  {k}: {v}")
    print("===========================================\n")

# ------------------------------------------------
# ROUTES
# FIX #1: removed duplicate @app.route decorators on /login and /dashboard
# ------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html", countries=COUNTRY_DATA, time_slots=TIME_SLOTS)


@app.route("/login", methods=["POST"])          # FIX #1 — single decorator only
def login():
    customer_id = request.form.get("customer_id", "").strip()
    password    = request.form.get("password", "")
    trap_field  = request.form.get("trap_field", "")

    # ── Bot trap (honeypot hidden field filled by bots) ──
    if trap_field:
        print("\n🤖 BOT DETECTED via honeypot trap field")
        session["customer_id"]   = "attacker"
        session["session_id"]    = secrets.token_hex(16)
        session["risk_score"]    = 95
        session["sql_injection"] = True
        return redirect(url_for("dashboard"))

    # ── SQL Injection check ──
    if detect_sql_injection(customer_id) or detect_sql_injection(password):
        print("\n🚨 SQL INJECTION ATTEMPT DETECTED 🚨")
        print(f"  customer_id : {customer_id!r}")
        print(f"  password    : {password!r}")
        session["customer_id"]   = "attacker"
        session["session_id"]    = secrets.token_hex(16)
        session["risk_score"]    = 75
        session["sql_injection"] = True
        return redirect(url_for("dashboard"))

    # Initialise failed-login counter
    if customer_id not in FAILED_LOGINS:
        FAILED_LOGINS[customer_id] = 0

    # ── Validate credentials ──
    # FIX #2 : plain string comparison, removed check_password_hash + password_hash key
    if customer_id in DEMO_USERS and password == DEMO_USERS[customer_id]["password"]:
        user   = DEMO_USERS[customer_id]
        device = get_device()

        selected_country = request.form.get("country", "India")
        selected_hour    = int(request.form.get("login_hour", 9))

        country_info     = get_country_info(selected_country)
        location_penalty = country_info["penalty"]
        trusted_country  = country_info["trusted"]
        simulated_ip     = country_info["ip"]
        time_penalty, time_risk_label = get_time_penalty(selected_hour)

        base_risk = USER_RISK.get(customer_id, 15)

        # FIX #3 : removed undefined extract_session_features / calculate_risk_score
        #          replaced with calculate_risk() using activity dict
        activity = {
            "is_login":         True,
            "new_device":       device != USER_DEVICES.get(customer_id, device),
            "new_location":     False,
            "failed_logins":    PRE_LOGIN_FAILED.get(customer_id, 0),
            "request_count":    0,
            "unusual_time":     selected_hour < 6 or selected_hour >= 21,
            "country":          selected_country,
            "trusted_country":  trusted_country,
            "location_penalty": location_penalty,
            "login_hour":       selected_hour,
            "time_risk_label":  time_risk_label,
            "time_penalty":     time_penalty,
            "simulated_ip":     simulated_ip,
        }

        risk_score = calculate_risk(base_risk, activity)
        USER_RISK[customer_id]        = risk_score
        USER_DEVICES[customer_id]     = device
        PRE_LOGIN_FAILED[customer_id] = FAILED_LOGINS[customer_id]
        FAILED_LOGINS[customer_id]    = 0   # reset on successful login

        sid = secrets.token_hex(16)
        session["customer_id"]     = customer_id
        session["session_id"]      = sid
        session["country"]         = selected_country
        session["country_flag"]    = country_info["flag"]
        session["trusted_country"] = trusted_country
        session["login_hour"]      = selected_hour
        session["time_risk_label"] = time_risk_label
        session["simulated_ip"]    = simulated_ip
        session["risk_score"]      = risk_score

        session_data[sid] = {
            "ip":               get_ip(),
            "requests":         0,
            "location_penalty": location_penalty,
            "time_penalty":     time_penalty,
        }

        security_log(customer_id, risk_score, activity)
        return redirect(url_for("dashboard"))

    # ── Failed login ──
    FAILED_LOGINS[customer_id] = FAILED_LOGINS.get(customer_id, 0) + 1

    selected_country = request.form.get("country", "India")
    selected_hour    = int(request.form.get("login_hour", 9))
    country_info     = get_country_info(selected_country)
    location_penalty = country_info["penalty"]
    time_penalty, time_risk_label = get_time_penalty(selected_hour)

    base_risk = USER_RISK.get(customer_id, 15)
    count     = FAILED_LOGINS[customer_id]

    if count <= 3:    base_risk += 2
    elif count <= 6:  base_risk += 5
    elif count <= 10: base_risk += 8
    else:             base_risk += 12

    USER_RISK[customer_id] = min(base_risk + location_penalty + time_penalty, 100)

    activity = {
        "is_login":         True,
        "new_device":       False,
        "new_location":     False,
        "failed_logins":    FAILED_LOGINS[customer_id],
        "request_count":    0,
        "unusual_time":     selected_hour < 6 or selected_hour >= 21,
        "country":          selected_country,
        "trusted_country":  country_info["trusted"],
        "location_penalty": location_penalty,
        "login_hour":       selected_hour,
        "time_risk_label":  time_risk_label,
        "time_penalty":     time_penalty,
        "simulated_ip":     country_info["ip"],
    }
    security_log(customer_id, USER_RISK[customer_id], activity)

    return render_template("index.html", error="Invalid Customer ID or Password",
                           countries=COUNTRY_DATA, time_slots=TIME_SLOTS)


@app.route("/dashboard")                        # FIX #1 — single decorator only
def dashboard():
    if "customer_id" not in session:
        return redirect(url_for("index"))

    cid = session["customer_id"]

    # ── SQL injection / bot → serve honeypot data ──
    if session.get("sql_injection"):
        print("⚠️  SQL INJECTION / BOT — HONEYPOT ACTIVATED")
        try:
            data         = get_honeypot_data()
            account_data = data["account"]
            transactions = data["transactions"]
        except Exception:
            # Fallback if honeypot.py doesn't return expected format
            fake_balance, transactions = honeypot_data()
            account_data = {
                "customer_name":     "John Doe",
                "account_number":    "0000-0000",
                "account_type":      "Checking",
                "balance":           fake_balance,
                "available_balance": fake_balance,
            }
        return render_template("dashboard.html", account=account_data, transactions=transactions)

    # ── Normal authenticated flow ──
    sid  = session.get("session_id", "")
    data = session_data.get(sid, {
        "ip": get_ip(), "requests": 0,
        "location_penalty": 0, "time_penalty": 0
    })
    data["requests"] = data.get("requests", 0) + 1
    session_data[sid] = data

    # FIX #3 : use calculate_risk() — extract_session_features / calculate_risk_score removed
    activity = {
        "is_login":         False,
        "new_device":       get_device() != USER_DEVICES.get(cid, get_device()),
        "new_location":     get_ip() != data.get("ip", get_ip()),
        "failed_logins":    PRE_LOGIN_FAILED.get(cid, 0),
        "request_count":    data["requests"],
        "unusual_time":     datetime.now().hour < 6,
        "country":          session.get("country", "Unknown"),
        "trusted_country":  session.get("trusted_country", False),
        "location_penalty": data.get("location_penalty", 0),
        "login_hour":       session.get("login_hour", 9),
        "time_risk_label":  session.get("time_risk_label", "Normal"),
        "time_penalty":     data.get("time_penalty", 0),
        "simulated_ip":     session.get("simulated_ip", get_ip()),
    }

    new_risk   = calculate_risk(USER_RISK.get(cid, 15), activity)
    risk_score = max(USER_RISK.get(cid, 15), new_risk)
    USER_RISK[cid]        = risk_score
    session["risk_score"] = risk_score

    security_log(cid, risk_score, activity)

    user     = DEMO_USERS[cid]
    real_bal = user["balance"]

    if risk_score <= 40:
        account_data = {
            "customer_name":     user["name"],
            "account_number":    user["account_number"],
            "account_type":      user["account_type"],
            "balance":           real_bal,
            "available_balance": user["available_balance"],  # FIX #4 — key now exists
        }
        transactions = REAL_TRANSACTIONS.get(cid, [])

    elif risk_score <= 75:
        account_data = {
            "customer_name":     user["name"],
            "account_number":    user["account_number"],
            "account_type":      user["account_type"],
            "balance":           real_bal,
            "available_balance": user["available_balance"],  # FIX #4
        }
        transactions = randomized_transactions()

    else:
        fake_balance, transactions = honeypot_data()
        account_data = {
            "customer_name":     user["name"],
            "account_number":    user["account_number"],
            "account_type":      user["account_type"],
            "balance":           fake_balance,
            "available_balance": fake_balance,
        }

    return render_template("dashboard.html", account=account_data, transactions=transactions)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


if __name__ == "__main__":
    print("\n🔐 SecureBank AI Fraud Detection System Started")
    print("   Login: customer001 / SecurePass123!\n")
    print("Risk Rules:")
    print("  India / USA        → Trusted (penalty: 0)")
    print("  UK / Germany / CA  → Low risk (+8)")
    print("  Russia / Nigeria   → High risk (+35–60)")
    print("  Business hours     → Safe (penalty: 0)")
    print("  Midnight – 3 AM    → High risk (+25–30)")
    print("  Suspicious loc + late night → Extra +10 spike\n")
    app.run(debug=True)