#!/bin/bash

# SecureBank Quick Setup Script
# This script automates the setup process

echo "============================================================"
echo "SecureBank - AI-Powered Banking Security System"
echo "Quick Setup Script"
echo "============================================================"
echo ""

# Check Python version
echo "Checking Python version..."
python3 --version

# Install dependencies
echo ""
echo "Installing dependencies..."
pip install -r requirements.txt --break-system-packages

# Create necessary directories
echo ""
echo "Creating directories..."
mkdir -p data logs models

# Generate training data
echo ""
echo "Generating training data..."
python3 generate_training_data.py

# Train ML model
echo ""
echo "Training anomaly detection model..."
python3 train_model.py

# Test honeypot
echo ""
echo "Testing honeypot generator..."
python3 honeypot.py

echo ""
echo "============================================================"
echo "Setup Complete!"
echo "============================================================"
echo ""
echo "To start the application, run:"
echo "  python3 app.py"
echo ""
echo "Then access: http://localhost:5000"
echo ""
echo "Demo Credentials:"
echo "  customer001 / SecurePass123!"
echo "  customer002 / BankDemo456!"
echo ""
echo "============================================================"
