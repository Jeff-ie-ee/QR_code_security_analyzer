// QR Scanner Webcam functionality
class QRScannerUI {
    constructor() {
        this.scanner = null;
        this.isScanning = false;
        this.init();
    }

    init() {
        this.bindEvents();
        this.initCameraSelector();
    }

    bindEvents() {
        // Start camera button
        document.getElementById('start-camera')?.addEventListener('click', () => this.startCamera());
        
        // Stop camera button
        document.getElementById('stop-camera')?.addEventListener('click', () => this.stopCamera());
        
        // Analyze button
        document.getElementById('analyze-camera')?.addEventListener('click', () => this.analyzeScan());
        
        // Tab change cleanup
        document.querySelectorAll('a[data-bs-toggle="tab"]').forEach(tab => {
            tab.addEventListener('shown.bs.tab', (e) => {
                if (e.target.getAttribute('href') !== '#camera') {
                    this.stopCamera();
                }
            });
        });
    }

    async initCameraSelector() {
        try {
            const cameras = await Instascan.Camera.getCameras();
            const select = document.getElementById('camera-select');
            
            if (cameras.length > 0) {
                cameras.forEach((camera, index) => {
                    const option = document.createElement('option');
                    option.value = index;
                    option.text = camera.name || `Camera ${index + 1}`;
                    select?.appendChild(option);
                });
            } else {
                console.warn('No cameras found.');
            }
        } catch (error) {
            console.error('Error accessing cameras:', error);
        }
    }

    async startCamera() {
        if (this.isScanning) return;

        try {
            const cameras = await Instascan.Camera.getCameras();
            const video = document.getElementById('preview');
            
            if (cameras.length > 0) {
                this.scanner = new Instascan.Scanner({
                    video: video,
                    mirror: false,
                    backgroundScan: true,
                    refractoryPeriod: 5000
                });

                this.scanner.addListener('scan', (content) => {
                    this.onQRScanned(content);
                });

                // Use back camera if available
                const backCamera = cameras.find(c => c.name.toLowerCase().includes('back')) || cameras[0];
                await this.scanner.start(backCamera);
                
                this.isScanning = true;
                this.updateUIState(true);
                
                console.log('Camera started successfully');
            } else {
                alert('No cameras found. Please check your camera permissions.');
            }
        } catch (error) {
            console.error('Error starting camera:', error);
            alert('Error accessing camera. Please ensure camera permissions are granted.');
        }
    }

    stopCamera() {
        if (this.scanner) {
            this.scanner.stop();
            this.scanner = null;
        }
        this.isScanning = false;
        this.updateUIState(false);
    }

    onQRScanned(content) {
        console.log('QR Code scanned:', content);
        
        // Display scanned content
        const scannedContent = document.getElementById('scanned-content');
        const scannedResult = document.getElementById('scanned-result');
        
        if (scannedContent && scannedResult) {
            scannedContent.textContent = content;
            scannedResult.style.display = 'block';
            
            // Add vibration feedback if on mobile
            if ('vibrate' in navigator) {
                navigator.vibrate(100);
            }
            
            // Play success sound
            this.playScanSound();
            
            // Stop camera after successful scan
            setTimeout(() => this.stopCamera(), 1000);
        }
    }

    analyzeScan() {
        const content = document.getElementById('scanned-content')?.textContent;
        if (content) {
            this.submitScan(content);
        }
    }

    submitScan(content) {
        const form = document.createElement('form');
        form.method = 'POST';
        form.action = '/scan';
        
        const methodInput = document.createElement('input');
        methodInput.type = 'hidden';
        methodInput.name = 'scan_method';
        methodInput.value = 'webcam';
        form.appendChild(methodInput);
        
        const contentInput = document.createElement('input');
        contentInput.type = 'hidden';
        contentInput.name = 'webcam_data';
        contentInput.value = content;
        form.appendChild(contentInput);
        
        document.body.appendChild(form);
        form.submit();
    }

    updateUIState(isScanning) {
        const startBtn = document.getElementById('start-camera');
        const stopBtn = document.getElementById('stop-camera');
        
        if (startBtn) startBtn.disabled = isScanning;
        if (stopBtn) stopBtn.disabled = !isScanning;
    }

    playScanSound() {
        try {
            const audioContext = new (window.AudioContext || window.webkitAudioContext)();
            const oscillator = audioContext.createOscillator();
            const gainNode = audioContext.createGain();
            
            oscillator.connect(gainNode);
            gainNode.connect(audioContext.destination);
            
            oscillator.frequency.value = 800;
            oscillator.type = 'sine';
            
            gainNode.gain.setValueAtTime(0.3, audioContext.currentTime);
            gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.5);
            
            oscillator.start(audioContext.currentTime);
            oscillator.stop(audioContext.currentTime + 0.5);
        } catch (error) {
            console.log('Could not play scan sound:', error);
        }
    }
}

// File upload preview
class FileUploadUI {
    constructor() {
        this.init();
    }

    init() {
        const fileInput = document.getElementById('file');
        const preview = document.getElementById('file-preview');
        
        if (fileInput && preview) {
            fileInput.addEventListener('change', (e) => this.handleFileSelect(e));
        }
    }

    handleFileSelect(event) {
        const file = event.target.files[0];
        const preview = document.getElementById('file-preview');
        
        if (!file || !preview) return;
        
        if (!file.type.match('image.*')) {
            preview.innerHTML = '<div class="alert alert-danger">Please select an image file</div>';
            return;
        }
        
        const reader = new FileReader();
        
        reader.onload = (e) => {
            preview.innerHTML = `
                <div class="text-center">
                    <img src="${e.target.result}" class="img-fluid rounded" style="max-height: 200px;" alt="QR Code Preview">
                    <p class="mt-2 text-muted">${file.name} (${this.formatFileSize(file.size)})</p>
                </div>
            `;
        };
        
        reader.readAsDataURL(file);
    }

    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
}

// Threat score visualization
class ThreatVisualizer {
    constructor() {
        this.init();
    }

    init() {
        this.renderThreatGauges();
        this.renderCheckStatus();
    }

    renderThreatGauges() {
        const gaugeElements = document.querySelectorAll('.threat-gauge');
        
        gaugeElements.forEach(element => {
            const score = parseFloat(element.dataset.score);
            const color = this.getScoreColor(score);
            
            // Create SVG gauge
            const svg = this.createGaugeSVG(score, color);
            element.innerHTML = '';
            element.appendChild(svg);
        });
    }

    createGaugeSVG(score, color) {
        const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        svg.setAttribute('viewBox', '0 0 100 100');
        svg.setAttribute('width', '100%');
        svg.setAttribute('height', '100');
        
        // Background circle
        const bgCircle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        bgCircle.setAttribute('cx', '50');
        bgCircle.setAttribute('cy', '50');
        bgCircle.setAttribute('r', '45');
        bgCircle.setAttribute('fill', 'none');
        bgCircle.setAttribute('stroke', '#e9ecef');
        bgCircle.setAttribute('stroke-width', '8');
        svg.appendChild(bgCircle);
        
        // Progress circle
        const progressCircle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        progressCircle.setAttribute('cx', '50');
        progressCircle.setAttribute('cy', '50');
        progressCircle.setAttribute('r', '45');
        progressCircle.setAttribute('fill', 'none');
        progressCircle.setAttribute('stroke', color);
        progressCircle.setAttribute('stroke-width', '8');
        progressCircle.setAttribute('stroke-dasharray', `${score * 2.83} 283`);
        progressCircle.setAttribute('stroke-linecap', 'round');
        progressCircle.setAttribute('transform', 'rotate(-90 50 50)');
        svg.appendChild(progressCircle);
        
        // Score text
        const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        text.setAttribute('x', '50');
        text.setAttribute('y', '55');
        text.setAttribute('text-anchor', 'middle');
        text.setAttribute('font-size', '20');
        text.setAttribute('font-weight', 'bold');
        text.setAttribute('fill', color);
        text.textContent = Math.round(score);
        svg.appendChild(text);
        
        return svg;
    }

    getScoreColor(score) {
        if (score >= 70) return '#dc3545';
        if (score >= 40) return '#ffc107';
        if (score >= 20) return '#17a2b8';
        return '#28a745';
    }

    renderCheckStatus() {
        const checkCards = document.querySelectorAll('.check-card');
        
        checkCards.forEach(card => {
            const score = parseFloat(card.dataset.score || 0);
            const icon = card.querySelector('.check-icon i');
            
            if (icon) {
                if (score >= 10) {
                    icon.className = 'fas fa-times-circle text-danger';
                } else if (score >= 5) {
                    icon.className = 'fas fa-exclamation-triangle text-warning';
                } else {
                    icon.className = 'fas fa-check-circle text-success';
                }
            }
        });
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    // Initialize QR scanner if on scan page
    if (document.getElementById('preview')) {
        window.qrScanner = new QRScannerUI();
    }
    
    // Initialize file upload preview
    if (document.getElementById('file')) {
        window.fileUploadUI = new FileUploadUI();
    }
    
    // Initialize threat visualizer if on result page
    if (document.querySelector('.threat-gauge')) {
        window.threatVisualizer = new ThreatVisualizer();
    }
    
    // Add copy functionality for scan IDs
    document.querySelectorAll('.copy-scan-id').forEach(button => {
        button.addEventListener('click', (e) => {
            const scanId = e.target.dataset.scanId;
            navigator.clipboard.writeText(scanId).then(() => {
                const originalText = e.target.innerHTML;
                e.target.innerHTML = '<i class="fas fa-check"></i> Copied!';
                setTimeout(() => {
                    e.target.innerHTML = originalText;
                }, 2000);
            });
        });
    });
    
    // Auto-expand QR content on click
    document.querySelectorAll('.expand-qr-content').forEach(button => {
        button.addEventListener('click', (e) => {
            const content = e.target.parentElement.querySelector('.qr-content');
            if (content) {
                content.classList.toggle('expanded');
                if (content.classList.contains('expanded')) {
                    e.target.innerHTML = '<i class="fas fa-minus"></i> Show Less';
                } else {
                    e.target.innerHTML = '<i class="fas fa-plus"></i> Show More';
                }
            }
        });
    });
});

// Toast notifications
class ToastNotification {
    static show(message, type = 'info') {
        const toast = document.createElement('div');
        toast.className = `toast-notification alert alert-${type} alert-dismissible fade show`;
        toast.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        
        toast.style.position = 'fixed';
        toast.style.top = '20px';
        toast.style.right = '20px';
        toast.style.zIndex = '9999';
        toast.style.minWidth = '300px';
        
        document.body.appendChild(toast);
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (toast.parentNode) {
                toast.remove();
            }
        }, 5000);
    }
}

// Export for global use
window.ToastNotification = ToastNotification;
