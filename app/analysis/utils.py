import os
import subprocess
import time
from datetime import datetime

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def analyze_firmware(filepath):
    """Perform actual firmware analysis using security tools"""
    start_time = time.time()
    
    try:
        # Run binwalk for initial analysis
        binwalk_cmd = f"binwalk {filepath}"
        binwalk_result = subprocess.run(binwalk_cmd, shell=True, capture_output=True, text=True)
        
        # Check for common vulnerabilities
        vulnerabilities = []
        
        # Example: Check for hardcoded credentials
        strings_cmd = f"strings {filepath} | grep -i 'password\|admin\|root'"
        strings_result = subprocess.run(strings_cmd, shell=True, capture_output=True, text=True)
        
        if strings_result.stdout:
            vulnerabilities.append({
                'type': 'Hardcoded Credentials',
                'severity': 'High',
                'location': 'Various',
                'description': 'Potential hardcoded credentials found',
                'evidence': strings_result.stdout.split('\n')[:5]  # Show first 5 matches
            })
        
        # Calculate risk score (simplified example)
        risk_score = min(10, len(vulnerabilities) * 2)  # 2 points per vulnerability
        
        return {
            'status': 'completed',
            'risk_score': risk_score,
            'vulnerabilities': vulnerabilities,
            'metadata': {
                'analysis_time': round(time.time() - start_time, 2),
                'tools_used': ['binwalk', 'strings'],
                'file_size': os.path.getsize(filepath)
            },
            'raw_output': {
                'binwalk': binwalk_result.stdout
            }
        }
    
    except Exception as e:
        return {
            'status': 'failed',
            'error': str(e),
            'risk_score': 0,
            'vulnerabilities': []
        }