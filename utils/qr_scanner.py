import cv2
import qrcode
import re
from typing import Dict, Any


class QRScanner:
    def __init__(self):
        # OpenCV QR Detector
        self.detector = cv2.QRCodeDetector()

        self.url_pattern = re.compile(
            r'^(https?://)?'
            r'(([A-Z0-9-]+\.)+[A-Z]{2,6})'
            r'(:\d+)?'
            r'(/.*)?$',
            re.IGNORECASE
        )

        self.upi_pattern = re.compile(
            r'^upi://pay\?pa=[^&]+&pn=[^&]+&am=\d+&cu=INR$',
            re.IGNORECASE
        )

        self.email_pattern = re.compile(
            r'^mailto:[^@]+@[^@]+\.[^@]+$'
        )

        self.phone_pattern = re.compile(
            r'^tel:\+\d{10,15}$'
        )

        self.sms_pattern = re.compile(
            r'^smsto:\d+:.+$'
        )

        self.vcard_pattern = re.compile(
            r'^BEGIN:VCARD.*END:VCARD$',
            re.DOTALL
        )

        self.bitcoin_pattern = re.compile(
            r'^bitcoin:[13][a-km-zA-HJ-NP-Z1-9]{25,34}$'
        )

        self.wifi_pattern = re.compile(
            r'^WIFI:'
            r'S:(?P<ssid>[^;]*);'
            r'T:(?P<type>[^;]*);'
            r'P:(?P<password>[^;]*);'
            r'(?:H:(?P<hidden>[^;]*);)?'
            r';?$',
            re.IGNORECASE
        )

        self.crypto_patterns = {
            'bitcoin': re.compile(
                r'^bitcoin:[13][a-km-zA-HJ-NP-Z1-9]{25,34}(?:\?.*)?$'
            ),
            'ethereum': re.compile(
                r'^(?:ethereum:|ETH:)?(0x[a-fA-F0-9]{40})(?:\?.*)?$'
            ),
            'litecoin': re.compile(
                r'^litecoin:[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}(?:\?.*)?$'
            ),
            'ripple': re.compile(
                r'^(?:ripple:|XRP:)?(r[0-9a-zA-Z]{24,34})(?:\?.*)?$'
            ),
            'doge': re.compile(
                r'^dogecoin:[D9][1-9A-HJ-NP-Za-km-z]{33}(?:\?.*)?$'
            )
        }

    def decode_from_image(self, image_path: str) -> str:
        """Decode QR code from image file using OpenCV"""
        try:
            image = cv2.imread(image_path)

            if image is None:
                return None

            data, points, _ = self.detector.detectAndDecode(image)

            if data:
                return data.strip()

            return None

        except Exception as e:
            print(f"Error decoding QR: {e}")
            return None

    def decode_from_webcam(self) -> str:
        """Decode QR code from webcam using OpenCV"""
        cap = cv2.VideoCapture(0)

        while True:
            ret, frame = cap.read()

            if not ret:
                break

            data, points, _ = self.detector.detectAndDecode(frame)

            if data:
                cap.release()
                cv2.destroyAllWindows()
                return data.strip()

            cv2.imshow("QR Scanner", frame)

            if cv2.waitKey(1) & 0xFF == ord("q"):
                break

        cap.release()
        cv2.destroyAllWindows()

        return None

    def parse_qr_content(self, content: str) -> Dict[str, Any]:
        """Parse QR content and identify type"""

        if not content:
            return {
                'type': 'unknown',
                'content': content
            }

        content = content.strip()

        print(f"QR_SCANNER DEBUG: Content = '{content}'")

        wifi_match = self.wifi_pattern.match(content)

        if wifi_match:
            wifi_info = wifi_match.groupdict()

            return {
                'type': 'wifi',
                'content': content,
                'wifi_info': {
                    'ssid': wifi_info.get('ssid', ''),
                    'encryption': wifi_info.get('type', ''),
                    'password': wifi_info.get('password', ''),
                    'hidden': wifi_info.get('hidden', 'false').lower() == 'true'
                }
            }

        url_match = self.url_pattern.match(content)

        print(f"QR_SCANNER DEBUG: URL pattern match = {url_match}")
        print(f"QR_SCANNER DEBUG: Starts with http/https = {content.startswith(('http://', 'https://'))}")

        if url_match or content.startswith(('http://', 'https://')):
            url = content if '://' in content else f'http://{content}'

            print(f"QR_SCANNER DEBUG: Returning URL = '{url}'")

            return {
                'type': 'url',
                'url': url,
                'content': content
            }

        if 'upi://' in content.lower() or self.upi_pattern.match(content):
            return {
                'type': 'upi',
                'content': content
            }

        for crypto_type, pattern in self.crypto_patterns.items():
            if pattern.match(content):
                return {
                    'type': 'crypto',
                    'crypto_type': crypto_type,
                    'content': content,
                    'address': self.extract_crypto_address(content, crypto_type)
                }

        if 'whatsapp://pay' in content.lower():
            return {
                'type': 'whatsapp_pay',
                'content': content
            }

        if self.bitcoin_pattern.match(content) or content.startswith(('ethereum:', 'litecoin:')):
            return {
                'type': 'crypto',
                'content': content
            }

        if self.wifi_pattern.match(content):
            return {
                'type': 'wifi',
                'content': content
            }

        if self.vcard_pattern.match(content):
            return {
                'type': 'vcard',
                'content': content
            }

        if self.email_pattern.match(content):
            return {
                'type': 'email',
                'content': content
            }

        if self.phone_pattern.match(content):
            return {
                'type': 'phone',
                'content': content
            }

        if self.sms_pattern.match(content):
            return {
                'type': 'sms',
                'content': content
            }

        if len(content) < 1000:
            return {
                'type': 'text',
                'content': content
            }

        return {
            'type': 'unknown',
            'content': content
        }

    def extract_crypto_address(self, content: str, crypto_type: str) -> str:
        """Extract cryptocurrency address from QR content"""

        try:
            if crypto_type == 'ethereum':
                match = re.search(r'(0x[a-fA-F0-9]{40})', content)
                return match.group(1) if match else content.split(':')[-1]

            elif crypto_type == 'ripple':
                match = re.search(r'(r[0-9a-zA-Z]{24,34})', content)
                return match.group(1) if match else content.split(':')[-1]

            else:
                return content.split(':')[1].split('?')[0]

        except Exception:
            return content
