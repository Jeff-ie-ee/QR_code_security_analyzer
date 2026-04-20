QR Code Security Analyzer
Overview

QR Code Security Analyzer is a security-focused application that inspects QR code content and identifies potential threats before user interaction. Unlike traditional QR scanners, this system performs multi-layered security analysis to detect phishing attempts, malicious URLs, payment fraud, and unsafe configurations embedded within QR codes.

The application supports multiple QR formats including URLs, UPI payments, WiFi credentials, and cryptocurrency addresses, and provides an explainable risk assessment through a structured threat scoring engine.

Key Features
Multi-Format QR Support
URL analysis
UPI payment QR validation
WiFi credential inspection
Cryptocurrency address analysis
Email, SMS, and contact QR parsing
Advanced Security Analysis
Google Safe Browsing integration
VirusTotal reputation checks
WHOIS-based domain age analysis
SSL certificate validation
Redirect chain inspection
URL shortener detection
Phishing & Spoof Detection
Typosquatting detection using string similarity
Unicode homograph attack detection
Brand impersonation checks
Suspicious keyword identification
Payment & Financial Fraud Detection
Fake payment gateway detection (Paytm, PhonePe, PayPal, etc.)
UPI parameter validation
Suspicious transaction pattern analysis
WiFi Security Analysis
Encryption strength evaluation (WEP/WPA/WPA2/WPA3)
Password strength and pattern detection
Detection of insecure or open networks
Cryptocurrency Risk Analysis
Address format validation
Scam pattern detection
Suspicious transaction metadata analysis
Risk classification for crypto transactions
Threat Scoring System
Weighted scoring model (0–100)
Risk classification:
SAFE
LOW RISK
SUSPICIOUS
MALICIOUS
Detailed breakdown of contributing factors
Architecture
QR Input (Image / Webcam / Manual)
        │
        ▼
QR Parsing Engine
        │
        ▼
Security Analyzer
        │
        ▼
Threat Scoring Engine
        │
        ▼
Result Visualization
Tech Stack
Backend: Python, Flask
Database: SQLite, SQLAlchemy
Image Processing: OpenCV, Pyzbar, Pillow
APIs: Google Safe Browsing API, VirusTotal API
Installation
1. Clone the Repository
git clone https://github.com/your-username/qr-security-analyzer.git
cd qr-security-analyzer
2. Create Virtual Environment
python3 -m venv venv
source venv/bin/activate
3. Install Dependencies
pip install -r requirements.txt
4. Configure Environment Variables

Create a .env file in the root directory:

SECRET_KEY=your_secret_key
DATABASE_URL=sqlite:///qr_scans.db
GOOGLE_SAFE_BROWSING_API_KEY=your_google_api_key
VIRUSTOTAL_API_KEY=your_virustotal_api_key
Usage
Run the Application
python app.py

Access the application at:

http://127.0.0.1:5000
API Endpoint
Scan QR Content
POST /api/scan
Request Body
{
  "qr_content": "https://example.com"
}
Response
{
  "total_score": 35,
  "threat_level": "SUSPICIOUS",
  "breakdown": {...},
  "warnings": [...]
}
Project Structure
.
├── app.py
├── config.py
├── models/
│   └── database.py
├── utils/
│   ├── qr_scanner.py
│   ├── security_analyzer.py
│   ├── threat_scorer.py
│   └── advanced_analyzer.py
├── templates/
├── static/
├── uploads/
└── requirements.txt
Security Considerations
API keys must be stored securely using environment variables
File uploads are restricted by type and size
External API calls include timeout handling
Input validation is applied across QR parsing and analysis stages
Limitations
Dependent on external APIs for threat intelligence
Synchronous processing may impact performance under load
Basic blacklist implementation (can be extended with real-time threat feeds)
Future Improvements
Asynchronous processing using task queues
Integration with real-time threat intelligence feeds
Machine learning-based phishing detection
Caching layer for repeated scans
Rate limiting and API protection
Docker-based deployment

