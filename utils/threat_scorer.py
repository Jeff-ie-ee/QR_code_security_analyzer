from typing import Dict, Any
import datetime

class ThreatScorer:
    def __init__(self):
        self.weights = {
            'safe_browsing': 30,
            'virustotal': 25,
            'domain_age': 15,
            'ssl_valid': 10,
            'redirects': 5,
            'shortlink': 5,
            'spoof': 15,
            'homograph': 15,
            'phishing_keywords': 10,
            'blacklist': 20,
            'payment_fraud': 25,
            'upi_fraud': 20,
            'wifi_security': 15,
            'crypto_fraud': 20
        }
        
        self.type_descriptions = {
            'url': 'Website URL',
            'upi': 'UPI Payment',
            'whatsapp_pay': 'WhatsApp Payment',
            'crypto': 'Cryptocurrency',
            'wifi': 'WiFi Network',
            'vcard': 'Contact Card',
            'email': 'Email Address',
            'phone': 'Phone Number',
            'sms': 'Text Message',
            'text': 'Plain Text',
            'unknown': 'Unknown Type'
        }

    def calculate_score(self, qr_info: Dict[str, Any], security_report: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate threat score based ONLY on security findings"""
        breakdown = {}
        total_score = 0
        
        qr_type = qr_info.get('type', 'unknown')
        
        if qr_type == 'url' and security_report.get('checks'):
            checks = security_report['checks']
            
            # Safe Browsing
            if 'safe_browsing' in checks and not checks['safe_browsing'].get('safe', True):
                breakdown['safe_browsing'] = {
                    'score': self.weights['safe_browsing'],
                    'max': self.weights['safe_browsing'],
                    'reason': 'Flagged by Google Safe Browsing'
                }
                total_score += self.weights['safe_browsing']
            
            # VirusTotal
            if 'virustotal' in checks and checks['virustotal'].get('available'):
                positives = checks['virustotal'].get('positives', 0)
                total_engines = checks['virustotal'].get('total', 'multiple')

                if positives >= 10:
                    vt_contribution = self.weights['virustotal']
                elif positives >= 5:
                    vt_contribution = self.weights['virustotal'] * 0.75
                elif positives >= 2:
                    vt_contribution = self.weights['virustotal'] * 0.50
                elif positives >= 1:
                    vt_contribution = self.weights['virustotal'] * 0.25
                else:
                    vt_contribution = 0

                if vt_contribution > 0:
                    breakdown['virustotal'] = {
                        'score': vt_contribution,
                        'max': self.weights['virustotal'],
                        'reason': f"VirusTotal: {positives}/{total_engines} engines flagged"
                    }
                    total_score += vt_contribution
            
            # Domain Age
            if 'whois' in checks and checks['whois'].get('is_new'):
                breakdown['domain_age'] = {
                    'score': self.weights['domain_age'],
                    'max': self.weights['domain_age'],
                    'reason': f"New domain ({checks['whois'].get('age_days', 0)} days old)"
                }
                total_score += self.weights['domain_age']
            
            # SSL Certificate
            if 'ssl' in checks:
                if not checks['ssl'].get('valid', True):
                    breakdown['ssl'] = {
                        'score': self.weights['ssl_valid'],
                        'max': self.weights['ssl_valid'],
                        'reason': 'Invalid SSL certificate'
                    }
                    total_score += self.weights['ssl_valid']
                elif checks['ssl'].get('expiry_days', 0) < 7:
                    breakdown['ssl'] = {
                        'score': self.weights['ssl_valid'] * 0.5,
                        'max': self.weights['ssl_valid'],
                        'reason': 'SSL certificate expiring soon'
                    }
                    total_score += self.weights['ssl_valid'] * 0.5
            
            # Redirects
            if 'redirects' in checks and checks['redirects'].get('count', 0) > 2:
                redirect_score = min(checks['redirects'].get('count', 0) * 2, self.weights['redirects'])
                breakdown['redirects'] = {
                    'score': redirect_score,
                    'max': self.weights['redirects'],
                    'reason': f"Multiple redirects ({checks['redirects'].get('count')})"
                }
                total_score += redirect_score
            
            # Shortlink
            if 'shortlink' in checks and checks['shortlink'].get('is_shortlink'):
                breakdown['shortlink'] = {
                    'score': self.weights['shortlink'],
                    'max': self.weights['shortlink'],
                    'reason': 'Uses URL shortening service (can hide malicious links)'
                }
                total_score += self.weights['shortlink']
            
            # Spoof Detection
            if 'spoof' in checks and checks['spoof'].get('has_warnings'):
                warning_count = len(checks['spoof'].get('warnings', []))
                is_typosquatting = checks['spoof'].get('is_typosquatting', False)
                
                if is_typosquatting:
                    spoof_score = self.weights['spoof'] * 0.8
                else:
                    spoof_score = min(warning_count * 5, self.weights['spoof'] * 0.6)
                
                breakdown['spoof'] = {
                    'score': spoof_score,
                    'max': self.weights['spoof'],
                    'reason': 'Domain spoofing detected',
                    'warnings': checks['spoof'].get('warnings', [])[:2]
                }
                total_score += spoof_score
            
            # Homograph Attack
            if 'homograph' in checks and checks['homograph'].get('is_homograph'):
                breakdown['homograph'] = {
                    'score': self.weights['homograph'],
                    'max': self.weights['homograph'],
                    'reason': 'Possible homograph attack (Unicode spoofing)'
                }
                total_score += self.weights['homograph']
            
            # Phishing Keywords
            if 'phishing_keywords' in checks and checks['phishing_keywords'].get('is_suspicious'):
                keyword_score = min(checks['phishing_keywords'].get('count', 0) * 3, self.weights['phishing_keywords'])
                breakdown['phishing_keywords'] = {
                    'score': keyword_score,
                    'max': self.weights['phishing_keywords'],
                    'reason': f"Contains {checks['phishing_keywords'].get('count')} suspicious keywords"
                }
                total_score += keyword_score
            
            # Blacklist
            if 'reputation' in checks and checks['reputation'].get('blacklist_match'):
                breakdown['blacklist'] = {
                    'score': self.weights['blacklist'],
                    'max': self.weights['blacklist'],
                    'reason': 'Domain found in blacklist'
                }
                total_score += self.weights['blacklist']
            
            # Payment Fraud
            if 'payment_fraud' in checks and checks['payment_fraud'].get('has_warnings'):
                fraud_check = checks['payment_fraud']
                warning_count = fraud_check.get('warning_count', 0)
                severity = fraud_check.get('severity', 'LOW')
                
                if severity == 'HIGH':
                    fraud_score = self.weights['payment_fraud'] * 0.9
                elif severity == 'MEDIUM':
                    fraud_score = self.weights['payment_fraud'] * 0.6
                else:
                    fraud_score = min(warning_count * 5, self.weights['payment_fraud'] * 0.4)
                
                warnings = fraud_check.get('warnings', [])
                for warning in warnings:
                    if 'TYPOSQUATTING' in warning:
                        fraud_score += 15
                        break
                
                breakdown['payment_fraud'] = {
                    'score': min(fraud_score, self.weights['payment_fraud']),
                    'max': self.weights['payment_fraud'],
                    'reason': f"Payment fraud detected: {fraud_check.get('detected_gateway', 'unknown')}",
                    'warnings': warnings[:2]
                }
                total_score += min(fraud_score, self.weights['payment_fraud'])
        
        # UPI scoring
        elif qr_type == 'upi' and security_report.get('checks'):
            checks = security_report['checks']
            
            if 'upi_verification' in checks:
                upi_verification = checks['upi_verification']
                if not upi_verification.get('valid', True):
                    breakdown['upi_verification'] = {
                        'score': 10,
                        'max': 10,
                        'reason': 'Invalid UPI scheme',
                        'details': upi_verification.get('missing_params', [])
                    }
                    total_score += 10
            
            if 'upi_fraud_check' in checks and checks['upi_fraud_check'].get('has_warnings'):
                upi_warnings = checks['upi_fraud_check'].get('warnings', [])
                upi_score = min(len(upi_warnings) * 5, self.weights['upi_fraud'])
                breakdown['upi_fraud'] = {
                    'score': upi_score,
                    'max': self.weights['upi_fraud'],
                    'reason': 'UPI fraud indicators detected',
                    'warnings': upi_warnings[:3]
                }
                total_score += upi_score
        
        # WiFi scoring
        elif qr_type == 'wifi' and qr_info.get('wifi_info'):
            wifi_analysis = security_report.get('wifi_analysis', {})
        
            if wifi_analysis.get('warnings'):
                security_score = wifi_analysis.get('security_score', 100)
                threat_points = (100 - security_score) * 0.15
            
                breakdown['wifi_security'] = {
                    'score': min(threat_points, self.weights['wifi_security']),
                    'max': self.weights['wifi_security'],
                    'reason': f"WiFi {wifi_analysis.get('risk_level', 'UNKNOWN')} risk",
                    'warnings': wifi_analysis.get('warnings', [])[:3]
                }
                total_score += min(threat_points, self.weights['wifi_security'])
        
        # Crypto scoring
        elif qr_type == 'crypto' and security_report.get('crypto_analysis'):
            crypto_analysis = security_report['crypto_analysis']
        
            if crypto_analysis.get('warnings'):
                fraud_score = crypto_analysis.get('fraud_score', 0)
                risk_level = crypto_analysis.get('risk_level', 'LOW')
            
                if risk_level == 'CRITICAL':
                    crypto_threat = self.weights['crypto_fraud']
                elif risk_level == 'HIGH':
                    crypto_threat = self.weights['crypto_fraud'] * 0.75
                elif risk_level == 'MEDIUM':
                    crypto_threat = self.weights['crypto_fraud'] * 0.5
                else:
                    crypto_threat = min(self.weights['crypto_fraud'], fraud_score / 5)
            
                breakdown['crypto_fraud'] = {
                    'score': crypto_threat,
                    'max': self.weights['crypto_fraud'],
                    'reason': f"{crypto_analysis.get('crypto_type', 'Crypto')} {risk_level} risk",
                    'warnings': crypto_analysis.get('warnings', [])[:3],
                    'confidence': f"{crypto_analysis.get('confidence', 0)}%"
                }
                total_score += crypto_threat
        
        # Cap total score at 100
        total_score = min(total_score, 100)
        
        if total_score >= 20:
            threat_level = "MALICIOUS"
            color = "danger"
        elif total_score >= 10:
            threat_level = "SUSPICIOUS"
            color = "warning"
        elif total_score >= 5:
            threat_level = "LOW RISK"
            color = "info"
        else:
            threat_level = "SAFE"
            color = "success"
        
        return {
            'total_score': round(total_score, 1),
            'threat_level': threat_level,
            'color': color,
            'breakdown': breakdown,
            'qr_type': qr_type,
            'type_description': self.type_descriptions.get(qr_type, 'Unknown'),
            'max_possible': 100,
            'timestamp': datetime.datetime.utcnow().isoformat()
        }
