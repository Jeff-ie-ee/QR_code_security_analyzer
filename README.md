QR Code Security Analyzer

A security-focused QR code analysis platform that detects potential threats embedded in QR codes. The system supports multiple QR formats including URLs, UPI payments, WiFi credentials, and cryptocurrency addresses, and performs layered security checks to identify phishing, fraud, and malicious activity.

Features
Multi-format QR support (URL, UPI, WiFi, Crypto, Email, SMS)
URL security analysis using Safe Browsing and VirusTotal
Domain intelligence (WHOIS, SSL validation, redirects)
Phishing detection (typosquatting, homograph attacks, keyword analysis)
Payment fraud detection and UPI validation
WiFi security analysis (encryption and password strength)
Cryptocurrency address validation and scam detection
Threat scoring system with risk classification
Tech Stack
Python
Flask
SQLAlchemy
OpenCV
Pyzbar
External APIs: Google Safe Browsing, VirusTotal
