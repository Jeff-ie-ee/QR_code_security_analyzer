from dotenv import load_dotenv
load_dotenv()

import os
import hashlib
from datetime import datetime
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
import json
import urllib.parse
from config import Config
from utils.qr_scanner import QRScanner
from utils.security_analyzer import SecurityAnalyzer
from utils.threat_scorer import ThreatScorer
from models.database import db, ScanResult
from flask import request

app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions
db.init_app(app)

# Create upload folder
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize scanners
qr_scanner = QRScanner()
security_analyzer = SecurityAnalyzer(
    google_api_key=app.config['GOOGLE_SAFE_BROWSING_API_KEY'],
    virustotal_api_key=app.config['VIRUSTOTAL_API_KEY']
)
threat_scorer = ThreatScorer()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def parse_upi_string(upi_string):
    """Parse UPI string and extract payment details"""
    try:
        parsed = urllib.parse.urlparse(upi_string)
        query_params = urllib.parse.parse_qs(parsed.query)
        
        return {
            'pa': query_params.get('pa', [''])[0],  # Payee UPI ID
            'pn': query_params.get('pn', [''])[0],  # Payee Name
            'am': query_params.get('am', [''])[0] if query_params.get('am') else None,  # Amount
            'cu': query_params.get('cu', ['INR'])[0],  # Currency
            'tn': query_params.get('tn', [''])[0] if query_params.get('tn') else None  # Transaction Note
        }
    except:
        return {'pa': upi_string, 'pn': 'Unknown', 'am': None, 'cu': 'INR', 'tn': None}

# Add this to your Jinja2 template context
@app.context_processor
def utility_processor():
    def parse_upi_string_func(upi_string):
        return parse_upi_string(upi_string)
    return dict(parse_upi_string=parse_upi_string_func)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['GET', 'POST'])
def scan_qr():
    if request.method == 'POST':
        scan_method = request.form.get('scan_method')
        qr_data = None
        filename = None
        
        if scan_method == 'upload' and 'file' in request.files:
            file = request.files['file']
            if file.filename == '':
                flash('No selected file')
                return redirect(request.url)
            
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                
                # Decode QR from image
                qr_data = qr_scanner.decode_from_image(filepath)
        
        elif scan_method == 'manual' and 'qr_content' in request.form:
            qr_data = request.form.get('qr_content')
        
        elif scan_method == 'webcam' and 'webcam_data' in request.form:
            qr_data = request.form['webcam_data']
        
        if qr_data:
            # Create scan hash for tracking
            scan_hash = hashlib.sha256(f"{qr_data}{datetime.utcnow().timestamp()}".encode()).hexdigest()[:16]
            session['current_scan'] = scan_hash
            
            # Start analysis in background (for production, use Celery)
            result = perform_security_analysis(qr_data, scan_hash)
            
            print(f"DEBUG result checks keys: {list(result['security_report'].get('checks', {}).keys())}")
            return render_template('result.html', result=result)
        
        flash('Failed to decode QR code')
        return redirect(url_for('scan_qr'))
    
    return render_template('scan.html')

@app.route('/api/scan', methods=['POST'])
def api_scan():
    """API endpoint for mobile apps"""
    data = request.json
    qr_content = data.get('qr_content')
    
    if not qr_content:
        return jsonify({'error': 'No QR content provided'}), 400
    
    scan_hash = hashlib.sha256(f"{qr_content}{datetime.utcnow().timestamp()}".encode()).hexdigest()[:16]
    result = perform_security_analysis(qr_content, scan_hash)
    
    return jsonify(result)

def perform_security_analysis(qr_content, scan_hash):
    """Perform complete security analysis on QR content"""
    
    # Step 1: Parse QR type
    qr_info = qr_scanner.parse_qr_content(qr_content)
    
    print(f"DEBUG: QR content = {qr_content}")
    print(f"DEBUG: QR info = {qr_info}")
    
    # Step 2: Perform security analysis based on type
    security_report = {}
    
    if qr_info['type'] == 'url' and qr_info.get('url'):
    
        print(f"DEBUG: Calling analyze_url with: {qr_info['url']}")
    
        security_report = security_analyzer.analyze_url(qr_info['url'])
    
    elif qr_info['type'] == 'upi':
        # Add UPI-specific checks
        security_report = {
            'type': 'upi',
            'checks': {
                'upi_verification': verify_upi_scheme(qr_content),
                'upi_fraud_check': check_upi_fraud(qr_content)
            },
            'warnings': []
        }
    
    elif qr_info['type'] == 'wifi' and qr_info.get('wifi_info'):
        # WiFi analysis
        wifi_analysis = security_analyzer.wifi_analyzer.analyze_wifi(qr_info['wifi_info'])
        security_report = {
            'type': 'wifi',
            'wifi_analysis': wifi_analysis,
            'warnings': wifi_analysis.get('warnings', [])
        }
    
    elif qr_info['type'] == 'crypto' and qr_info.get('crypto_type'):
        # Cryptocurrency analysis
        crypto_analysis = security_analyzer.crypto_analyzer.analyze_crypto(
            qr_content,
            qr_info.get('crypto_type', 'unknown'),
            qr_info.get('address', '')
        )
        security_report = {
            'type': 'crypto',
            'crypto_analysis': crypto_analysis,
            'warnings': crypto_analysis.get('warnings', [])
        }
    
    # Step 3: Calculate threat score
    threat_score = threat_scorer.calculate_score(qr_info, security_report)
    
    # Step 4: Determine action
    is_malicious = threat_score['total_score'] >= app.config['THREAT_SCORE_MALICIOUS']
    is_suspicious = threat_score['total_score'] >= app.config['THREAT_SCORE_SUSPICIOUS']
    
    # Step 5: Determine redirect URL based on type
    redirect_url = None
    if not is_malicious:
        if qr_info['type'] == 'url':
            redirect_url = qr_info.get('url')
        elif qr_info['type'] in ['upi', 'whatsapp_pay', 'crypto']:
            # For payment types, use our redirect endpoint
            redirect_url = url_for('safe_redirect', scan_id=scan_hash, _external=True)
    
    # Step 6: Prepare result
    result = {
        'scan_id': scan_hash,
        'timestamp': datetime.utcnow().isoformat(),
        'qr_content': qr_content,
        'qr_info': qr_info,
        'security_report': security_report,
        'threat_score': threat_score,
        'is_malicious': is_malicious,
        'is_suspicious': is_suspicious,
        'recommendation': 'BLOCK' if is_malicious else ('WARN' if is_suspicious else 'ALLOW'),
        'redirect_url': redirect_url,
        'can_redirect': redirect_url is not None
    }
    
    # Step 7: Save to database
    save_scan_result(result)
    
    return result

def verify_upi_scheme(upi_string):
    """Verify UPI scheme validity"""
    try:
        parsed = urllib.parse.urlparse(upi_string)
        query_params = urllib.parse.parse_qs(parsed.query)
        
        # Check required parameters for UPI
        required = ['pa', 'pn']
        missing = [param for param in required if param not in query_params]
        
        return {
            'valid': len(missing) == 0,
            'missing_params': missing,
            'has_amount': 'am' in query_params,
            'amount': query_params.get('am', [None])[0],
            'payee_vpa': query_params.get('pa', [None])[0],
            'payee_name': query_params.get('pn', [None])[0],
            'currency': query_params.get('cu', ['INR'])[0]
        }
    except Exception as e:
        return {'valid': False, 'error': str(e)}

def check_upi_fraud(upi_string):
    """Check for UPI fraud patterns"""
    warnings = []
    
    try:
        parsed = urllib.parse.urlparse(upi_string)
        query_params = urllib.parse.parse_qs(parsed.query)
        
        # Check for suspicious amounts
        if 'am' in query_params:
            try:
                amount = float(query_params['am'][0])
                if amount <= 0:
                    warnings.append("Suspicious: Zero or negative amount")
                elif amount > 100000:  # ₹1 lakh limit
                    warnings.append("Warning: Large transaction amount")
            except:
                warnings.append("Invalid amount format")
        
        # Check for suspicious payee names
        payee_name = query_params.get('pn', [''])[0]
        suspicious_names = ['test', 'demo', 'fake', 'example']
        if any(name in payee_name.lower() for name in suspicious_names):
            warnings.append("Suspicious payee name")
        
        # Check UPI ID format
        upi_id = query_params.get('pa', [''])[0]
        if not '@' in upi_id:
            warnings.append("Invalid UPI ID format")
        elif len(upi_id.split('@')[0]) < 3:
            warnings.append("Suspiciously short UPI ID")
        
    except Exception as e:
        warnings.append(f"Error parsing UPI: {str(e)}")
    
    return {
        'warnings': warnings,
        'has_warnings': len(warnings) > 0
    }

def save_scan_result(result):
    """Save scan result to database"""
    try:
        scan_result = ScanResult(
            scan_id=result['scan_id'],
            qr_content=result['qr_content'],
            qr_type=result['qr_info']['type'],
            threat_score=result['threat_score']['total_score'],
            is_malicious=result['is_malicious'],
            security_report=json.dumps(result['security_report']),
            threat_breakdown=json.dumps(result['threat_score']['breakdown'])
        )
        db.session.add(scan_result)
        db.session.commit()
    except Exception as e:
        app.logger.error(f"Error saving scan result: {e}")

@app.route('/history')
def history():
    """View scan history with pagination"""
    page = request.args.get('page', 1, type=int)
    per_page = 20  # Show 20 scans per page
    
    # Query with pagination
    pagination = ScanResult.query.order_by(
        ScanResult.timestamp.desc()
    ).paginate(page=page, per_page=per_page, error_out=False)
    
    scans = pagination.items
    
    return render_template('history.html', 
                         scans=scans,
                         pagination=pagination,
                         total_scans=ScanResult.query.count())

@app.route('/delete_scan/<scan_id>', methods=['POST'])
#@login_required  # Optional: add if you have user authentication
def delete_scan(scan_id):
    """Delete a single scan result"""
    try:
        scan = ScanResult.query.filter_by(scan_id=scan_id).first()
        
        if not scan:
            flash('Scan not found', 'error')
            return redirect(url_for('history'))
        
        db.session.delete(scan)
        db.session.commit()
        
        flash('Scan deleted successfully', 'success')
    except Exception as e:
        flash(f'Error deleting scan: {str(e)}', 'error')
    
    return redirect(url_for('history'))

@app.route('/delete_all_history', methods=['POST'])
#@login_required  # Optional: add if you have user authentication
def delete_all_history():
    """Delete all scan history"""
    try:
        # Delete all scan results
        num_deleted = ScanResult.query.delete()
        db.session.commit()
        
        flash(f'Successfully deleted {num_deleted} scan records', 'success')
    except Exception as e:
        flash(f'Error deleting history: {str(e)}', 'error')
    
    return redirect(url_for('history'))

@app.route('/redirect/<scan_id>')
def safe_redirect(scan_id):
    """Safe redirect endpoint for verified QR codes"""
    scan = ScanResult.query.filter_by(scan_id=scan_id).first()
    
    if not scan:
        flash('Scan result not found')
        return redirect(url_for('index'))
    
    if scan.is_malicious:
        flash('Access denied: This QR code was flagged as malicious')
        return redirect(url_for('index'))
    
    # Handle different QR types
    if scan.qr_type == 'url':
        return render_template('redirect.html', 
                             url=scan.qr_content if scan.qr_type == 'url' else None,
                             scan=scan)
    
    elif scan.qr_type == 'upi':
        return render_template('redirect_upi.html', scan=scan)
    
    elif scan.qr_type == 'whatsapp_pay':
        # Handle WhatsApp Pay
        return render_template('redirect_whatsapp.html', scan=scan)
    
    elif scan.qr_type == 'crypto':
        # Handle cryptocurrency
        return render_template('redirect_crypto.html', scan=scan)
    
    else:
        # For other types (text, email, etc.), show details
        return render_template('redirect_other.html', scan=scan)

@app.route('/api/scan/<scan_id>')
def get_scan_result(scan_id):
    """API to get scan result"""
    scan = ScanResult.query.filter_by(scan_id=scan_id).first()
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
    
    return jsonify({
        'scan_id': scan.scan_id,
        'qr_content': scan.qr_content,
        'qr_type': scan.qr_type,
        'threat_score': scan.threat_score,
        'is_malicious': scan.is_malicious,
        'timestamp': scan.timestamp.isoformat(),
        'security_report': json.loads(scan.security_report) if scan.security_report else {},
        'threat_breakdown': json.loads(scan.threat_breakdown) if scan.threat_breakdown else {}
    })

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host='0.0.0.0', port=port, 
            ssl_context=('cert.pem', 'key.pem'))
