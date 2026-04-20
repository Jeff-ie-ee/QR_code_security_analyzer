import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-here-change-in-production'
    
    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///qr_scans.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # File upload
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    UPLOAD_FOLDER = 'uploads'
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp'}
    
    # API Keys (set in .env)
    GOOGLE_SAFE_BROWSING_API_KEY = os.environ.get('GOOGLE_SAFE_BROWSING_API_KEY')
    VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')
    
    # Security thresholds
    DOMAIN_AGE_THRESHOLD = 90  # days
    THREAT_SCORE_MALICIOUS = 40
    THREAT_SCORE_SUSPICIOUS = 20
    
    # Timeouts
    REQUEST_TIMEOUT = 10
