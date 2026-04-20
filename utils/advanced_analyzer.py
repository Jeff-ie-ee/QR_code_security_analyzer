"""
Advanced analyzers for WiFi and Cryptocurrency QR codes
"""
import re
import urllib.parse
from datetime import datetime
from typing import Dict, Any, List
import hashlib

class WiFiAnalyzer:
    """Analyze WiFi QR codes for security"""
    
    def __init__(self):
        # Common weak passwords
        self.common_passwords = [
            'password', 'password123', '12345678', 'admin',
            'welcome', 'qwerty', 'letmein', 'monkey', 'dragon',
            'baseball', 'football', 'mustang', 'master', 'hello',
            'freedom', 'whatever', 'qazwsx', 'trustno1', 'sunshine'
        ]
        
        # Sequential patterns
        self.sequential_patterns = [
            '1234', '2345', '3456', '4567', '5678', '6789', '7890',
            'abcd', 'bcde', 'cdef', 'defg', 'efgh', 'fghi', 'ghij',
            'qwer', 'wert', 'erty', 'rtyu', 'tyui', 'yuio', 'uiop'
        ]
    
    def analyze_wifi(self, wifi_info: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze WiFi security"""
        password = wifi_info.get('password', '')
        encryption = wifi_info.get('encryption', '').upper()
        ssid = wifi_info.get('ssid', '')
        
        warnings = []
        security_score = 100  # Start with perfect score
        risk_factors = []
        
        # 1. ENCRYPTION TYPE ANALYSIS
        if encryption in ['WEP', 'WPA']:
            warnings.append(f"⚠️ WEAK ENCRYPTION: {encryption} is easily crackable")
            security_score -= 40
            risk_factors.append(f"weak_encryption_{encryption}")
        elif encryption in ['NOPASS', '']:
            warnings.append("🔓 NO ENCRYPTION: Open network (anyone can listen)")
            security_score -= 60
            risk_factors.append("no_encryption")
        elif encryption == 'WPA2':
            if 'TKIP' in encryption:
                warnings.append("⚠️ WPA2-TKIP is vulnerable to attacks")
                security_score -= 20
                risk_factors.append("wpa2_tkip_vulnerable")
        elif encryption == 'WPA3':
            security_score += 10  # Bonus for WPA3
            risk_factors.append("wpa3_secure")
        
        # 2. PASSWORD STRENGTH ANALYSIS
        if password:
            # Length check
            if len(password) < 8:
                warnings.append("🔓 PASSWORD TOO SHORT: Less than 8 characters")
                security_score -= 25
                risk_factors.append("password_too_short")
            
            # Common password check
            if password.lower() in self.common_passwords:
                warnings.append("🔓 COMMON PASSWORD: Easily guessable")
                security_score -= 30
                risk_factors.append("common_password")
            
            # Pattern checks
            if password.isdigit():
                warnings.append("🔓 ONLY NUMBERS: No letters or special characters")
                security_score -= 15
                risk_factors.append("only_numbers")
            
            if password.isalpha():
                warnings.append("🔓 ONLY LETTERS: No numbers or special characters")
                security_score -= 15
                risk_factors.append("only_letters")
            
            # Sequential pattern check
            password_lower = password.lower()
            for pattern in self.sequential_patterns:
                if pattern in password_lower:
                    warnings.append(f"🔓 SEQUENTIAL PATTERN: '{pattern}' detected")
                    security_score -= 20
                    risk_factors.append("sequential_pattern")
                    break
            
            # Complexity check
            has_upper = any(c.isupper() for c in password)
            has_lower = any(c.islower() for c in password)
            has_digit = any(c.isdigit() for c in password)
            has_special = any(not c.isalnum() for c in password)
            
            complexity_score = sum([has_upper, has_lower, has_digit, has_special])
            
            if complexity_score < 3:
                warnings.append(f"🔓 LOW COMPLEXITY: Score {complexity_score}/4")
                security_score -= 20
                risk_factors.append(f"low_complexity_{complexity_score}")
            
            # Dictionary word check
            common_words = ['home', 'house', 'family', 'network', 'wifi',
                           'internet', 'secure', 'private', 'access', 'wireless']
            for word in common_words:
                if word in password_lower:
                    warnings.append(f"🔓 CONTAINS COMMON WORD: '{word}'")
                    security_score -= 10
                    risk_factors.append(f"contains_word_{word}")
                    break
        else:
            if encryption not in ['NOPASS', '']:
                warnings.append("❓ NO PASSWORD: But encryption specified")
                risk_factors.append("no_password_but_encryption")
        
        # 3. SSID ANALYSIS
        if ssid:
            suspicious_ssids = ['FreeWiFi', 'Free_WiFi', 'Public_WiFi', 
                               'Airport_WiFi', 'Hotel_WiFi', 'Guest']
            for suspicious in suspicious_ssids:
                if suspicious.lower() in ssid.lower():
                    warnings.append(f"⚠️ SUSPICIOUS SSID: '{suspicious}' in network name")
                    security_score -= 10
                    risk_factors.append(f"suspicious_ssid_{suspicious}")
                    break
        
        # 4. FINAL RISK ASSESSMENT
        risk_level = "LOW"
        if security_score <= 30:
            risk_level = "CRITICAL"
        elif security_score <= 50:
            risk_level = "HIGH"
        elif security_score <= 70:
            risk_level = "MEDIUM"
        
        recommendation = "CONNECT"
        if risk_level in ["CRITICAL", "HIGH"]:
            recommendation = "AVOID"
        elif risk_level == "MEDIUM":
            recommendation = "CONNECT WITH CAUTION"
        
        return {
            'warnings': warnings,
            'security_score': max(0, security_score),  # 0-100 scale
            'risk_level': risk_level,
            'risk_factors': risk_factors,
            'recommendation': recommendation,
            'encryption_strength': self.get_encryption_strength(encryption),
            'password_strength': self.get_password_strength(password),
            'analysis_time': datetime.now().isoformat()
        }
    
    def get_encryption_strength(self, encryption: str) -> str:
        """Get encryption strength rating"""
        strength_map = {
            'WPA3': 'VERY STRONG',
            'WPA2': 'STRONG',
            'WPA': 'WEAK',
            'WEP': 'VERY WEAK',
            'NOPASS': 'NONE',
            '': 'UNKNOWN'
        }
        return strength_map.get(encryption.upper(), 'UNKNOWN')
    
    def get_password_strength(self, password: str) -> str:
        """Get password strength rating"""
        if not password:
            return "NO PASSWORD"
        
        length = len(password)
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        
        complexity = sum([has_upper, has_lower, has_digit, has_special])
        
        if length >= 12 and complexity == 4:
            return "VERY STRONG"
        elif length >= 8 and complexity >= 3:
            return "STRONG"
        elif length >= 8 and complexity >= 2:
            return "MEDIUM"
        else:
            return "WEAK"


class CryptoAnalyzer:
    """Analyze Cryptocurrency QR codes for security"""
    
    def __init__(self):
        # Known scam address patterns (simplified - in reality would use API/database)
        self.scam_patterns = {
            'bitcoin': {
                'patterns': [
                    r'^1Fake',  # Pattern for fake addresses
                    r'^3Fake',
                    r'^bc1fake'
                ],
                'testnet_prefixes': ['tb1', 'bcrt', '2', 'n', 'm']
            },
            'ethereum': {
                'patterns': [
                    r'^0x0000',
                    r'^0xdead',
                    r'^0xfff'
                ],
                'testnet_prefixes': []
            }
        }
        
        # Common scam messages/keywords
        self.scam_keywords = [
            'urgent', 'immediate', 'investment', 'double',
            'free', 'giveaway', 'airdrop', 'reward',
            'wallet', 'recovery', 'support', 'verify',
            'prize', 'lottery', 'winner', 'bonus'
        ]
    
    def analyze_crypto(self, content: str, crypto_type: str, address: str) -> Dict[str, Any]:
        """Analyze cryptocurrency QR code"""
        warnings = []
        fraud_score = 0
        analysis_details = {
            'valid_format': True,
            'parameters': {},
            'risk_factors': []
        }
        
        # 1. ADDRESS VALIDATION
        if not self.validate_address(address, crypto_type):
            warnings.append("❌ INVALID ADDRESS FORMAT")
            fraud_score += 30
            analysis_details['valid_format'] = False
            analysis_details['risk_factors'].append("invalid_format")
        
        # 2. KNOWN SCAM PATTERNS
        scam_patterns = self.scam_patterns.get(crypto_type, {}).get('patterns', [])
        for pattern in scam_patterns:
            if re.match(pattern, address, re.IGNORECASE):
                warnings.append(f"⚠️ KNOWN SCAM PATTERN: Matches {pattern}")
                fraud_score += 25
                analysis_details['risk_factors'].append("known_scam_pattern")
                break
        
        # 3. TESTNET DETECTION
        testnet_prefixes = self.scam_patterns.get(crypto_type, {}).get('testnet_prefixes', [])
        for prefix in testnet_prefixes:
            if address.lower().startswith(prefix):
                warnings.append(f"⚠️ TESTNET ADDRESS: {address[:10]}... (NOT FOR REAL TRANSACTIONS)")
                fraud_score += 40  # Very high - sending to testnet loses funds!
                analysis_details['risk_factors'].append("testnet_address")
                break
        
        # 4. PARAMETER ANALYSIS
        try:
            parsed = urllib.parse.urlparse(content)
            query_params = urllib.parse.parse_qs(parsed.query)
            analysis_details['parameters'] = query_params
            
            # Amount parameter
            if 'amount' in query_params:
                try:
                    amount = float(query_params['amount'][0])
                    if amount <= 0:
                        warnings.append("⚠️ ZERO/NEGATIVE AMOUNT")
                        fraud_score += 15
                        analysis_details['risk_factors'].append("zero_amount")
                    elif amount > 10:  # Large crypto amount
                        warnings.append(f"⚠️ LARGE AMOUNT: {amount} {crypto_type.upper()}")
                        fraud_score += 10
                        analysis_details['risk_factors'].append("large_amount")
                except:
                    warnings.append("⚠️ INVALID AMOUNT FORMAT")
                    fraud_score += 10
            
            # Message/label analysis
            message_fields = ['message', 'label', 'memo', 'note']
            for field in message_fields:
                if field in query_params:
                    message = query_params[field][0].lower()
                    
                    # Check for scam keywords
                    found_keywords = [kw for kw in self.scam_keywords if kw in message]
                    if found_keywords:
                        warnings.append(f"⚠️ SUSPICIOUS MESSAGE: Contains {', '.join(found_keywords[:3])}")
                        fraud_score += len(found_keywords) * 5
                        analysis_details['risk_factors'].append(f"suspicious_message_{field}")
                    
                    # Check for urgency
                    if 'urgent' in message or 'immediate' in message:
                        warnings.append("🚨 URGENT LANGUAGE: Common in scams")
                        fraud_score += 20
                        analysis_details['risk_factors'].append("urgent_language")
                    
                    break  # Only check first message field
        
        except Exception as e:
            warnings.append(f"⚠️ PARAMETER PARSE ERROR: {str(e)}")
            analysis_details['risk_factors'].append("parse_error")
        
        # 5. ADDRESS REPUTATION (Simulated - would use API in production)
        address_hash = hashlib.sha256(address.encode()).hexdigest()[:8]
        
        # Simulate reputation based on hash (for demo)
        if int(address_hash, 16) % 100 < 5:  # 5% chance of "known scam"
            warnings.append("⚠️ ADDRESS IN SCAM DATABASE (Simulated)")
            fraud_score += 35
            analysis_details['risk_factors'].append("in_scam_database")
        
        # 6. FORMAT CHECKS
        if len(address) < 25:
            warnings.append("⚠️ UNUSUALLY SHORT ADDRESS")
            fraud_score += 10
            analysis_details['risk_factors'].append("short_address")
        
        if ' ' in address or '\t' in address:
            warnings.append("⚠️ ADDRESS CONTAINS WHITESPACE")
            fraud_score += 15
            analysis_details['risk_factors'].append("whitespace_in_address")
        
        # 7. FINAL RISK ASSESSMENT
        risk_level = "LOW"
        if fraud_score >= 50:
            risk_level = "CRITICAL"
        elif fraud_score >= 30:
            risk_level = "HIGH"
        elif fraud_score >= 15:
            risk_level = "MEDIUM"
        
        confidence = min(100, fraud_score * 1.5)
        
        return {
            'crypto_type': crypto_type,
            'address': address,
            'short_address': f"{address[:8]}...{address[-6:]}",
            'warnings': warnings,
            'fraud_score': fraud_score,
            'risk_level': risk_level,
            'confidence': confidence,
            'analysis_details': analysis_details,
            'recommendation': 'BLOCK' if risk_level == 'CRITICAL' else 
                            ('WARN' if risk_level in ['HIGH', 'MEDIUM'] else 'ALLOW'),
            'timestamp': datetime.now().isoformat()
        }
    
    def validate_address(self, address: str, crypto_type: str) -> bool:
        """Basic cryptocurrency address validation"""
        if not address:
            return False
        
        if crypto_type == 'bitcoin':
            return bool(re.match(r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$', address) or 
                       address.startswith('bc1'))
        elif crypto_type == 'ethereum':
            return bool(re.match(r'^0x[a-fA-F0-9]{40}$', address))
        elif crypto_type == 'litecoin':
            return bool(re.match(r'^[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}$', address))
        elif crypto_type == 'ripple':
            return bool(re.match(r'^r[0-9a-zA-Z]{24,34}$', address))
        elif crypto_type == 'doge':
            return bool(re.match(r'^D[1-9A-HJ-NP-Za-km-z]{33}$', address))
        
        return True  # Unknown crypto type
    
    def get_crypto_info(self, crypto_type: str) -> Dict[str, Any]:
        """Get information about cryptocurrency"""
        info = {
            'bitcoin': {
                'name': 'Bitcoin',
                'symbol': 'BTC',
                'security_note': 'Irreversible transactions',
                'scam_types': ['Fake exchanges', 'Giveaway scams', 'Investment fraud']
            },
            'ethereum': {
                'name': 'Ethereum',
                'symbol': 'ETH',
                'security_note': 'Smart contract risks',
                'scam_types': ['Fake token sales', 'Wallet drainers', 'NFT scams']
            },
            'litecoin': {
                'name': 'Litecoin',
                'symbol': 'LTC',
                'security_note': 'Faster transactions than Bitcoin',
                'scam_types': ['Same as Bitcoin scams']
            },
            'ripple': {
                'name': 'Ripple',
                'symbol': 'XRP',
                'security_note': 'Centralized validation',
                'scam_types': ['Fake airdrops', 'Exchange impersonation']
            },
            'doge': {
                'name': 'Dogecoin',
                'symbol': 'DOGE',
                'security_note': 'Meme coin, high volatility',
                'scam_types': ['Pump and dump', 'Social media scams']
            }
        }
        return info.get(crypto_type, {'name': crypto_type, 'symbol': '???'})
