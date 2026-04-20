import requests
import ssl
import socket
import whois
from datetime import datetime, timedelta, timezone
import urllib.parse
from urllib.parse import urlparse
import json
import time
import re
from typing import Dict, Any, List
import idna
import tldextract
from dateutil import parser as dateutil_parser
from difflib import SequenceMatcher
from utils.advanced_analyzer import WiFiAnalyzer, CryptoAnalyzer


class SecurityAnalyzer:
    def __init__(self, google_api_key=None, virustotal_api_key=None):
        self.google_api_key = google_api_key
        self.virustotal_api_key = virustotal_api_key
        self.headers = {'User-Agent': 'SecureQRScanner/1.0'}
        self.wifi_analyzer = WiFiAnalyzer()
        self.crypto_analyzer = CryptoAnalyzer()

        # Phishing keywords
        self.phishing_keywords = [
            'login', 'verify', 'secure', 'account', 'banking', 'paypal',
            'update', 'confirm', 'password', 'credential', 'urgent',
            'suspicious', 'activity', 'locked', 'restricted'
        ]

        # Common shorteners
        self.short_domains = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co',
            'is.gd', 'buff.ly', 'adf.ly', 'shorte.st', 'bc.vc'
        ]

    # ── String similarity using SequenceMatcher ─────────
    def is_similar(self, a: str, b: str, threshold: float = 0.8) -> bool:
        """
        Returns True if two strings are at least `threshold` similar.
        Uses SequenceMatcher which computes the ratio of matching
        characters between two strings.

        threshold=0.8 means 80% similar.
        This catches most typosquatting attempts while avoiding
        false positives on completely unrelated words.

        Examples:
            is_similar("paypol",   "paypal")  → 0.833 → True
            is_similar("phonepee", "phonepe") → 0.933 → True
            is_similar("paytmm",   "paytm")   → 0.909 → True
            is_similar("mypaypal", "paypal")  → 0.615 → False
        """
        return SequenceMatcher(None, a, b).ratio() >= threshold
    # ────────────────────────────────────────────────────────────

    def analyze_url(self, url: str) -> Dict[str, Any]:
        """Perform comprehensive URL security analysis"""
        result = {
            'url': url,
            'checks': {},
            'warnings': [],
            'score_components': {}
        }

        try:
            parsed = urlparse(url)
            domain = parsed.netloc

            # 1. Google Safe Browsing
            if self.google_api_key:
                result['checks']['safe_browsing'] = \
                    self.check_google_safe_browsing(url)

            # 2. VirusTotal
            if self.virustotal_api_key:
                result['checks']['virustotal'] = \
                    self.check_virustotal(url)

            # 3. WHOIS Domain Age
            result['checks']['whois'] = self.check_domain_age(domain)

            # 4. SSL Certificate Check
            if parsed.scheme == 'https':
                result['checks']['ssl'] = \
                    self.check_ssl_certificate(domain)

            # 5. Redirect Chain Analysis
            result['checks']['redirects'] = self.follow_redirects(url)

            # 6. Shortlink Detection
            result['checks']['shortlink'] = self.is_shortlink(domain)

            # 7. Domain Spoof Detection
            result['checks']['spoof'] = self.check_domain_spoofing(domain)

            # 8. Unicode Homograph Detection
            result['checks']['homograph'] = \
                self.check_homograph_attack(domain)

            # 9. Phishing Keyword Detection
            result['checks']['phishing_keywords'] = \
                self.check_phishing_keywords(url)

            # 10. Blacklist / Whitelist Reputation
            result['checks']['reputation'] = \
                self.check_domain_reputation(domain)

            # 11. Payment Fraud Detection
            result['checks']['payment_fraud'] = \
                self.check_payment_fraud(url)

            # 12. UPI Scheme Verification (if applicable)
            if 'upi' in url.lower():
                result['checks']['upi_verification'] = \
                    self.verify_upi_scheme(url)

            # Collect all warnings into one list
            result['warnings'] = self.collect_warnings(result['checks'])

        except Exception as e:
            result['error'] = str(e)

        return result

    # ────────────────────────────────────────────────────────────
    # CHECK 1 — Google Safe Browsing
    # ────────────────────────────────────────────────────────────
    def check_google_safe_browsing(self, url: str) -> Dict[str, Any]:
        """Check URL against Google Safe Browsing API"""
        try:
            api_url = \
                "https://safebrowsing.googleapis.com/v4/threatMatches:find"

            payload = {
                "client": {
                    "clientId": "secure-qr-system",
                    "clientVersion": "1.0"
                },
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE",
                        "SOCIAL_ENGINEERING",
                        "UNWANTED_SOFTWARE",
                        "POTENTIALLY_HARMFUL_APPLICATION"
                    ],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }

            params = {'key': self.google_api_key}
            response = requests.post(
                api_url, params=params, json=payload, timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                return {
                    'safe': 'matches' not in data or
                            len(data.get('matches', [])) == 0,
                    'threats': data.get('matches', []),
                    'timestamp': datetime.utcnow().isoformat()
                }

        except Exception:
            pass

        return {'safe': True, 'error': 'Check failed'}

    # ────────────────────────────────────────────────────────────
    # CHECK 2 — VirusTotal
    # ────────────────────────────────────────────────────────────
    def check_virustotal(self, url: str) -> Dict[str, Any]:
        """Check URL reputation with VirusTotal"""
        try:
            if not self.virustotal_api_key:
                return {'available': False}

            params = {'apikey': self.virustotal_api_key, 'resource': url}
            response = requests.get(
                'https://www.virustotal.com/vtapi/v2/url/report',
                params=params,
                headers=self.headers,
                timeout=15
            )

            if response.status_code == 200:
                data = response.json()

                # URL not in database — submit for future scans
                if data.get('response_code') == 0:
                    try:
                        submit_params = {
                            'apikey': self.virustotal_api_key,
                            'url': url
                        }
                        requests.post(
                            'https://www.virustotal.com/vtapi/v2/url/scan',
                            params=submit_params,
                            headers=self.headers,
                            timeout=15
                        )
                    except Exception:
                        pass
                    return {
                        'available': False,
                        'message': 'URL submitted for scanning, '
                                   'not yet in database'
                    }

                # URL queued for scanning
                if data.get('response_code') == -2:
                    return {
                        'available': False,
                        'message': 'URL is queued for scanning'
                    }

                # URL found in database
                if data.get('response_code') == 1:
                    positives = data.get('positives', 0)
                    total = data.get('total', 1)
                    score = positives / total * 100 if total > 0 else 0
                    return {
                        'available': True,
                        'positives': positives,
                        'total': total,
                        'score': score,
                        'scan_date': data.get('scan_date'),
                        'permalink': data.get('permalink')
                    }

            elif response.status_code == 204:
                return {
                    'available': False,
                    'message': 'VirusTotal rate limit exceeded'
                }

            elif response.status_code == 403:
                return {
                    'available': False,
                    'message': 'Invalid VirusTotal API key'
                }

        except Exception as e:
            return {'available': False, 'error': str(e)}

        return {'available': False}

    # ────────────────────────────────────────────────────────────
    # CHECK 3 — WHOIS Domain Age
    # ────────────────────────────────────────────────────────────
    def check_domain_age(self, domain: str) -> Dict[str, Any]:
        """Check domain registration age"""
        try:
            # Remove port if present
            domain = domain.split(':')[0]

            # Use tldextract to get root domain
            # subdomains confuse whois lookups
            extracted = tldextract.extract(domain)
            root_domain = f"{extracted.domain}.{extracted.suffix}"

            w = whois.whois(root_domain)
            creation_date = None

            if isinstance(w.creation_date, list):
                creation_date = w.creation_date[0]
            else:
                creation_date = w.creation_date

            # Handle string dates
            if isinstance(creation_date, str):
                try:
                    creation_date = dateutil_parser.parse(creation_date)
                except Exception:
                    return {
                        'age_days': None,
                        'error': 'Could not parse date'
                    }

            if creation_date:
                # Fix timezone mismatch
                if creation_date.tzinfo is not None:
                    now = datetime.now(timezone.utc)
                else:
                    now = datetime.now()

                age_days = (now - creation_date).days
                return {
                    'age_days': age_days,
                    'creation_date': creation_date.isoformat(),
                    'is_new': age_days <= 90,
                    'registrar': w.registrar,
                    'expiration_date': str(w.expiration_date)
                }

        except Exception as e:
            return {
                'age_days': None,
                'error': f'WHOIS lookup failed: {str(e)}'
            }

        return {'age_days': None, 'error': 'No creation date found'}

    # ────────────────────────────────────────────────────────────
    # CHECK 4 — SSL Certificate
    # ────────────────────────────────────────────────────────────
    def check_ssl_certificate(self, domain: str) -> Dict[str, Any]:
        """Validate SSL certificate"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443),
                                          timeout=10) as sock:
                with context.wrap_socket(
                    sock, server_hostname=domain
                ) as ssock:
                    cert = ssock.getpeercert()
                    not_after = datetime.strptime(
                        cert['notAfter'], '%b %d %H:%M:%S %Y %Z'
                    )
                    days_until_expiry = (not_after - datetime.now()).days
                    return {
                        'valid': True,
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'subject': dict(x[0] for x in cert['subject']),
                        'expiry_days': days_until_expiry,
                        'not_after': not_after.isoformat(),
                        'is_valid': days_until_expiry > 0
                    }

        except Exception as e:
            return {'valid': False, 'error': str(e)}

    # ────────────────────────────────────────────────────────────
    # CHECK 5 — Redirect Chain
    # ────────────────────────────────────────────────────────────
    def follow_redirects(self, url: str,
                         max_redirects: int = 10) -> Dict[str, Any]:
        """Follow redirect chain and analyze"""
        redirects = []
        current_url = url

        try:
            for i in range(max_redirects):
                response = requests.head(
                    current_url,
                    allow_redirects=False,
                    headers=self.headers,
                    timeout=10
                )

                redirects.append({
                    'url': current_url,
                    'status': response.status_code,
                    'headers': dict(response.headers)
                })

                if response.status_code in [301, 302, 303, 307, 308]:
                    location = response.headers.get('location')
                    if location:
                        current_url = urllib.parse.urljoin(
                            current_url, location
                        )
                    else:
                        break
                else:
                    break

                if i == max_redirects - 1:
                    redirects.append({'warning': 'Too many redirects'})

        except Exception as e:
            redirects.append({'error': str(e)})

        return {
            'chain': redirects,
            'count': len(redirects) - 1 if len(redirects) > 1 else 0,
            'final_url': redirects[-1].get('url', url) if redirects else url
        }

    # ────────────────────────────────────────────────────────────
    # CHECK 6 — Shortlink Detection
    # ────────────────────────────────────────────────────────────
    def is_shortlink(self, domain: str) -> Dict[str, Any]:
        """Check if domain is a URL shortener"""
        domain_lower = domain.lower()
        is_short = any(
            short in domain_lower for short in self.short_domains
        )
        return {
            'is_shortlink': is_short,
            'known_shortener': is_short,
            'short_domains': self.short_domains
        }

    # ────────────────────────────────────────────────────────────
    # CHECK 7 — Domain Spoof Detection (IMPROVED)
    # ────────────────────────────────────────────────────────────
    def check_domain_spoofing(self, domain: str) -> Dict[str, Any]:
        """
        Check for domain spoofing attempts using two independent passes.

        PASS 1 — Substring check:
            Brand name found as substring inside domain.
            Catches: phonepe-login.com, paytm-secure.net
            Then uses SequenceMatcher for precise TYPOSQUATTING label.

        PASS 2 — Similarity check:
            Base domain is similar to a brand even without substring match.
            Catches: paypol.com, phomepe.com, googel.com
            This was the gap in the previous implementation.

        Both passes are independent so neither can block the other.
        """
        warnings = []

        brands = {
            'paytm':    ['paytm.com', 'paytm.in'],
            'paypal':   ['paypal.com', 'paypal.me'],
            'google':   ['google.com', 'google.co.in'],
            'amazon':   ['amazon.com', 'amazon.in'],
            'phonepe':  ['phonepe.com'],
            'razorpay': ['razorpay.com'],
            'bank':     ['hdfcbank.com', 'icicibank.com', 'sbi.co.in'],
            'facebook': ['facebook.com', 'fb.com'],
            'whatsapp': ['whatsapp.com']
        }

        domain_lower = domain.lower()

        # tldextract gives us accurate base domain
        # "secure.phonepe-login.com" → base_domain = "phonepe-login"
        # "paypol.com"               → base_domain = "paypol"
        # "paytmm.in"                → base_domain = "paytmm"
        extracted = tldextract.extract(domain_lower)
        base_domain = extracted.domain

        # Track which brands have already been flagged
        # to prevent duplicate warnings across both passes
        already_flagged = set()

        # ── PASS 1: Substring check ──────────────────────────────
        # Runs when the brand name string exists inside the domain.
        # Then uses SequenceMatcher to decide if it is TYPOSQUATTING
        # or just a generic suspicious mention.
        # ─────────────────────────────────────────────────────────
        for brand, legitimate_domains in brands.items():
            if brand in domain_lower:

                is_legitimate = any(
                    domain_lower.endswith(legit_domain)
                    for legit_domain in legitimate_domains
                )

                if not is_legitimate:

                    # 1a: Direct similarity of base domain to brand
                    # "paytmm" vs "paytm" → 0.909 → TYPOSQUATTING
                    if self.is_similar(base_domain, brand):
                        warnings.append(
                            f"⚠️ TYPOSQUATTING: "
                            f"Possible fake {brand} domain"
                        )
                        already_flagged.add(brand)

                    # 1b: Similarity after splitting hyphens
                    # "phonepe-login" → ["phonepe","login"]
                    # "phonepe" vs "phonepe" → 1.0 → TYPOSQUATTING
                    elif any(
                        self.is_similar(word, brand)
                        for word in base_domain.split('-')
                    ):
                        warnings.append(
                            f"⚠️ TYPOSQUATTING: "
                            f"Possible fake {brand} domain"
                        )
                        already_flagged.add(brand)

                    # 1c: Generic fallback
                    # Brand is mentioned but not similar enough to
                    # be a deliberate typo.
                    # Example: "mypaytmlessons.com"
                    else:
                        warnings.append(
                            f"⚠️ WARNING: Contains {brand} "
                            f"but not on legitimate domain"
                        )
                        already_flagged.add(brand)

        # ── PASS 2: Similarity check (the key fix) ───────────────
        # Runs independently of Pass 1.
        # Catches domains that RESEMBLE a brand without containing
        # it as a substring — the exact gap that let paypol.com
        # slip through in the previous implementation.
        #
        # Examples caught here:
        #   "paypol.com"   → ratio("paypol","paypal")  = 0.833 ✓
        #   "phomepe.com"  → ratio("phomepe","phonepe") = 0.857 ✓
        #   "googel.com"   → ratio("googel","google")   = 0.909 ✓
        #   "amaz0n.in"    → caught by char substitution below
        # ─────────────────────────────────────────────────────────
        for brand, legitimate_domains in brands.items():

            # Skip brands already caught in Pass 1
            if brand in already_flagged:
                continue

            # Skip legitimate domains
            is_legitimate = any(
                domain_lower.endswith(legit_domain)
                for legit_domain in legitimate_domains
            )
            if is_legitimate:
                continue

            # 2a: Direct similarity of base domain to brand
            if self.is_similar(base_domain, brand):
                warnings.append(
                    f"⚠️ TYPOSQUATTING: "
                    f"Possible fake {brand} domain"
                )
                already_flagged.add(brand)
                continue

            # 2b: Similarity after splitting hyphens
            # Handles: "pay-pal.com" → ["pay","pal"]
            for word in base_domain.split('-'):
                if self.is_similar(word, brand):
                    warnings.append(
                        f"⚠️ TYPOSQUATTING: "
                        f"Possible fake {brand} domain"
                    )
                    already_flagged.add(brand)
                    break

        # ── Character substitution check ─────────────────────────
        # Catches: paypa1.com (1→l), g00gle.com (0→o), amaz0n.com
        # Works by replacing the fake character with the real one
        # and checking if a brand name then appears.
        suspicious_characters = {
            '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
            '6': 'b', '8': 'b', '9': 'g', '@': 'a'
        }

        for fake, real in suspicious_characters.items():
            if fake in domain_lower:
                for brand in brands.keys():
                    if real in brand:
                        test_domain = domain_lower.replace(fake, real)
                        if brand in test_domain:
                            warnings.append(
                                f"⚠️ CHARACTER SUBSTITUTION: "
                                f"Possible {brand} spoof"
                            )
        # ─────────────────────────────────────────────────────────

        # ── Hyphen spoofing check ─────────────────────────────────
        # Catches: paypal-secure.com, login-paytm.com
        # Checks if brand name appears with a hyphen before or after
        for brand in brands.keys():
            if (f"-{brand}" in domain_lower or
                    f"{brand}-" in domain_lower):
                if not any(
                    domain_lower.endswith(legit)
                    for legit in brands.get(brand, [])
                ):
                    warnings.append(
                        f"⚠️ HYPHEN SPOOFING: "
                        f"Suspicious {brand} domain"
                    )
        # ─────────────────────────────────────────────────────────

        return {
            'warnings': warnings,
            'has_warnings': len(warnings) > 0,
            'warning_count': len(warnings),
            'is_typosquatting': any(
                'TYPOSQUATTING' in w for w in warnings
            )
        }

    # ────────────────────────────────────────────────────────────
    # CHECK 8 — Homograph Attack
    # ────────────────────────────────────────────────────────────
    def check_homograph_attack(self, domain: str) -> Dict[str, Any]:
        """Check for homograph attacks using Unicode characters"""
        try:
            ascii_domain = idna.encode(domain).decode('ascii')

            if domain != ascii_domain:
                import unicodedata
                scripts = set()
                for char in domain:
                    try:
                        scripts.add(
                            unicodedata.name(char).split()[0]
                        )
                    except Exception:
                        pass

                if len(scripts) > 1:
                    return {
                        'is_homograph': True,
                        'original': domain,
                        'ascii': ascii_domain,
                        'scripts': list(scripts),
                        'warning': 'Possible homograph attack detected'
                    }

        except Exception:
            pass

        return {'is_homograph': False}

    # ────────────────────────────────────────────────────────────
    # CHECK 9 — Phishing Keywords
    # ────────────────────────────────────────────────────────────
    def check_phishing_keywords(self, url: str) -> Dict[str, Any]:
        """Check for phishing-related keywords in URL"""
        url_lower = url.lower()
        found_keywords = [
            keyword for keyword in self.phishing_keywords
            if keyword in url_lower
        ]
        return {
            'found_keywords': found_keywords,
            'count': len(found_keywords),
            'is_suspicious': len(found_keywords) >= 3
        }

    # ────────────────────────────────────────────────────────────
    # CHECK 10 — Domain Reputation
    # ────────────────────────────────────────────────────────────
    def check_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """Check domain against blacklists/whitelists"""
        blacklist = [
            'malicious-site.com',
            'phishing-attempt.net'
        ]

        whitelist = [
            'google.com',
            'github.com',
            'microsoft.com'
        ]

        domain_lower = domain.lower()
        blacklist_lower = [b.lower() for b in blacklist]
        whitelist_lower = [w.lower() for w in whitelist]

        return {
            'in_blacklist': domain_lower in blacklist_lower,
            'in_whitelist': domain_lower in whitelist_lower,
            'blacklist_match': domain_lower in blacklist_lower,
            'whitelist_match': domain_lower in whitelist_lower
        }

    # ────────────────────────────────────────────────────────────
    # CHECK 11 — Payment Fraud
    # ────────────────────────────────────────────────────────────
    def check_payment_fraud(self, url: str) -> Dict[str, Any]:
        """Check for payment fraud indicators"""
        warnings = []
        url_lower = url.lower()

        payment_gateways = {
            'paypal':    ['paypal.com', 'paypal.me'],
            'stripe':    ['stripe.com'],
            'razorpay':  ['razorpay.com'],
            'phonepe':   ['phonepe.com'],
            'paytm':     ['paytm.com', 'secure.paytm.in'],
            'googlepay': ['gpay.app', 'googlepay.com'],
            'amazonpay': ['amazonpay.com']
        }

        payment_typos = {
            'paypal':    ['paypai', 'paypa1', 'paypai-com',
                          'paypal-secure', 'paypal-login',
                          'paypal-verify', 'paypal-update'],
            'paytm':     ['paytmm', 'paiytm', 'paytmm-com',
                          'paytm-login', 'paytm-verify',
                          'paytm-update', 'paytm-secure'],
            'phonepe':   ['phonepee', 'fonepe', 'phonepe-login'],
            'googlepay': ['googlepai', 'gogglepay', 'googlepay-login'],
            'amazonpay': ['amazonpai', 'amazon-pay-login']
        }

        is_payment_related = False
        detected_gateway = None

        for gateway in payment_gateways.keys():
            if gateway in url_lower:
                is_payment_related = True
                detected_gateway = gateway

                legitimate_domains = payment_gateways[gateway]
                is_legitimate = any(
                    url_lower.endswith(domain) or
                    f".{domain}" in url_lower
                    for domain in legitimate_domains
                )

                if not is_legitimate:
                    # Check known typo patterns
                    if gateway in payment_typos:
                        for typo in payment_typos[gateway]:
                            if typo in url_lower:
                                warnings.append(
                                    f"⚠️ TYPOSQUATTING: "
                                    f"Fake {gateway} page detected"
                                )
                                break

                    # Check suspicious URL patterns
                    if not warnings:
                        suspicious_patterns = [
                            f"{gateway}-login",
                            f"{gateway}-verify",
                            f"{gateway}-secure",
                            f"{gateway}-update",
                            f"{gateway}-account",
                            f"login-{gateway}"
                        ]
                        for pattern in suspicious_patterns:
                            if pattern in url_lower:
                                warnings.append(
                                    f"⚠️ SUSPICIOUS: "
                                    f"Fake {gateway} login page"
                                )
                                break

                    if not warnings:
                        warnings.append(
                            f"⚠️ WARNING: Possible fake {gateway} page"
                        )

        if is_payment_related:
            # HTTPS enforcement
            if not url.startswith('https://'):
                warnings.append(
                    "🔒 INSECURE: Payment page without HTTPS"
                )

            # Suspicious query parameters
            parsed = urllib.parse.urlparse(url)
            query = urllib.parse.parse_qs(parsed.query)
            suspicious_params = [
                'login', 'verify', 'secure', 'update', 'password'
            ]
            for param in query.keys():
                if any(s in param.lower() for s in suspicious_params):
                    warnings.append(
                        f"🔍 SUSPICIOUS: Contains {param} parameter"
                    )

            # IP address instead of domain
            if re.match(
                r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url
            ):
                warnings.append(
                    "⚠️ SUSPICIOUS: Uses IP address instead of domain"
                )

        # Brand used in subdomain check
        brand_domains = [
            'paytm', 'paypal', 'google',
            'amazon', 'phonepe', 'razorpay'
        ]
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower()

        for brand in brand_domains:
            if brand in domain and not any(
                legit in domain
                for legit in payment_gateways.get(brand, [])
            ):
                parts = domain.split('.')
                if len(parts) > 2 and brand in parts[0]:
                    warnings.append(
                        f"⚠️ SUSPICIOUS: {brand} used in subdomain"
                    )

        return {
            'warnings': warnings,
            'has_warnings': len(warnings) > 0,
            'is_payment_related': is_payment_related,
            'detected_gateway': detected_gateway,
            'warning_count': len(warnings),
            'severity': 'HIGH' if len(warnings) > 2 else (
                        'MEDIUM' if len(warnings) > 0 else 'LOW')
        }

    # ────────────────────────────────────────────────────────────
    # CHECK 12 — UPI Scheme Verification
    # ────────────────────────────────────────────────────────────
    def verify_upi_scheme(self, upi_url: str) -> Dict[str, Any]:
        """Verify UPI scheme validity"""
        try:
            parsed = urllib.parse.urlparse(upi_url)
            query_params = urllib.parse.parse_qs(parsed.query)

            required = ['pa', 'pn', 'am']
            missing = [
                param for param in required
                if param not in query_params
            ]

            return {
                'valid': len(missing) == 0,
                'missing_params': missing,
                'has_amount': 'am' in query_params,
                'amount': query_params.get('am', [None])[0],
                'payee_vpa': query_params.get('pa', [None])[0],
                'payee_name': query_params.get('pn', [None])[0]
            }

        except Exception as e:
            return {'valid': False, 'error': str(e)}

    # ────────────────────────────────────────────────────────────
    # COLLECT WARNINGS
    # ────────────────────────────────────────────────────────────
    def collect_warnings(self, checks: Dict[str, Any]) -> List[str]:
        """Collect all warnings from all checks into one list"""
        warnings = []

        if 'safe_browsing' in checks and \
                not checks['safe_browsing'].get('safe', True):
            warnings.append("Google Safe Browsing flagged this URL")

        if 'virustotal' in checks and \
                checks['virustotal'].get('available'):
            if checks['virustotal'].get('score', 0) > 5:
                warnings.append(
                    f"VirusTotal detected "
                    f"{checks['virustotal'].get('positives', 0)} threats"
                )

        if 'whois' in checks and checks['whois'].get('is_new'):
            warnings.append(
                f"Domain registered recently "
                f"({checks['whois'].get('age_days', 0)} days ago)"
            )

        if 'ssl' in checks and not checks['ssl'].get('valid'):
            warnings.append("Invalid SSL certificate")
        elif 'ssl' in checks and \
                checks['ssl'].get('expiry_days', 0) < 30:
            warnings.append("SSL certificate expires soon")

        if 'redirects' in checks and \
                checks['redirects'].get('count', 0) > 3:
            warnings.append(
                f"Multiple redirects detected "
                f"({checks['redirects'].get('count')})"
            )

        if 'shortlink' in checks and \
                checks['shortlink'].get('is_shortlink'):
            warnings.append("URL uses a shortening service")

        if 'spoof' in checks and checks['spoof'].get('has_warnings'):
            warnings.extend(checks['spoof'].get('warnings', []))

        if 'homograph' in checks and \
                checks['homograph'].get('is_homograph'):
            warnings.append("Possible homograph attack detected")

        if 'phishing_keywords' in checks and \
                checks['phishing_keywords'].get('is_suspicious'):
            warnings.append("Contains suspicious keywords")

        if 'reputation' in checks and \
                checks['reputation'].get('blacklist_match'):
            warnings.append("Domain found in blacklist")

        if 'payment_fraud' in checks and \
                checks['payment_fraud'].get('has_warnings'):
            warnings.extend(
                checks['payment_fraud'].get('warnings', [])
            )

        return warnings
