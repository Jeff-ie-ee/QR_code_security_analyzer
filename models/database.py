from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.String(32), unique=True, nullable=False)
    qr_content = db.Column(db.Text, nullable=False)
    qr_type = db.Column(db.String(50), nullable=False)
    threat_score = db.Column(db.Float, default=0.0)
    is_malicious = db.Column(db.Boolean, default=False)
    security_report = db.Column(db.Text)  # JSON stored as text
    threat_breakdown = db.Column(db.Text)  # JSON stored as text
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_ip = db.Column(db.String(45))
    
    
    def to_dict(self):
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'qr_type': self.qr_type,
            'threat_score': self.threat_score,
            'is_malicious': self.is_malicious,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'user_ip': self.user_ip
        }
