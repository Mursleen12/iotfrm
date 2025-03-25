from flask import render_template, flash, redirect, url_for, send_from_directory
from flask_login import current_user, login_required
from app import db
from app.analysis import bp
from app.models import FirmwareAnalysis
from datetime import datetime
import os
import subprocess
import json
import magic
from config import Config

def run_security_analysis(filepath):
    """Run comprehensive security analysis on the firmware"""
    results = {
        'binwalk': {},
        'strings': {},
        'file_info': {},
        'vulnerabilities': [],
        'security_checks': {},
        'risk_score': 0
    }

    try:
        # 1. Run binwalk analysis
        binwalk_output = subprocess.check_output(
            ['binwalk', filepath],
            stderr=subprocess.STDOUT
        ).decode('utf-8')
        results['binwalk'] = {
            'output': binwalk_output,
            'signatures': parse_binwalk_output(binwalk_output)
        }
    except subprocess.CalledProcessError as e:
        results['binwalk'] = {'error': str(e.output.decode('utf-8'))}

    try:
        # 2. Run strings analysis
        strings_output = subprocess.check_output(
            ['strings', filepath],
            stderr=subprocess.PIPE
        ).decode('utf-8', errors='ignore')
        results['strings'] = {
            'output': strings_output[:5000],  # Limit size for storage
            'interesting_strings': find_interesting_strings(strings_output)
        }
    except subprocess.CalledProcessError as e:
        results['strings'] = {'error': str(e)}

    # 3. Get file information
    results['file_info'] = {
        'type': magic.from_file(filepath),
        'size': os.path.getsize(filepath)
    }

    # 4. Check for known vulnerabilities
    results['vulnerabilities'] = check_known_vulnerabilities(results)

    # 5. Perform security checks
    results['security_checks'] = perform_security_checks(filepath)

    # 6. Calculate risk score (0-100)
    results['risk_score'] = calculate_risk_score(results)

    return results

def parse_binwalk_output(output):
    """Parse binwalk output into structured data"""
    signatures = []
    for line in output.split('\n'):
        if line.strip() and not line.startswith('DECIMAL'):
            parts = line.split()
            if len(parts) >= 3:
                signatures.append({
                    'offset': parts[0],
                    'type': ' '.join(parts[1:-1]),
                    'description': parts[-1]
                })
    return signatures

def find_interesting_strings(strings_output):
    """Find potentially sensitive strings in output"""
    interesting = []
    keywords = [
        'password', 'admin', 'root', 'login', 
        'secret', 'key', 'certificate', 'http://',
        'https://', 'ftp://', 'token'
    ]
    for line in strings_output.split('\n'):
        if any(keyword in line.lower() for keyword in keywords):
            interesting.append(line.strip())
    return interesting[:100]  # Limit number of results

def check_known_vulnerabilities(results):
    """Check for known vulnerabilities based on analysis results"""
    vulnerabilities = []
    
    # Check binwalk results for known vulnerable components
    for sig in results['binwalk'].get('signatures', []):
        desc = sig['description'].lower()
        if 'linux' in desc:
            vulnerabilities.append({
                'component': 'Linux Kernel',
                'issue': 'Potential kernel vulnerabilities',
                'severity': 'high'
            })
        if 'busybox' in desc:
            vulnerabilities.append({
                'component': 'BusyBox',
                'issue': 'Potential BusyBox vulnerabilities',
                'severity': 'medium'
            })
    
    # Check strings for potential issues
    for string in results['strings'].get('interesting_strings', []):
        if 'password' in string.lower():
            vulnerabilities.append({
                'component': 'Firmware',
                'issue': 'Potential hardcoded credentials',
                'evidence': string[:100],
                'severity': 'critical'
            })
    
    return vulnerabilities

def perform_security_checks(filepath):
    """Perform basic security checks on the firmware"""
    checks = {
        'executable_stack': False,
        'stack_protection': False,
        'relro': 'none',
        'pie': 'none'
    }
    
    try:
        # Create temp directory for extraction
        temp_dir = os.path.join(Config.UPLOAD_FOLDER, f"temp_{os.getpid()}")
        os.makedirs(temp_dir, exist_ok=True)
        
        # Extract firmware
        subprocess.run(
            ['binwalk', '-e', filepath],
            cwd=temp_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        # Find and check ELF binaries
        for root, _, files in os.walk(temp_dir):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    # Check if file is ELF
                    file_type = subprocess.check_output(
                        ['file', file_path]
                    ).decode('utf-8')
                    if 'ELF' in file_type:
                        # Run checksec
                        checksec_output = subprocess.check_output(
                            ['checksec', '--file=' + file_path]
                        ).decode('utf-8')
                        
                        # Parse results
                        if 'Canary found' in checksec_output:
                            checks['stack_protection'] = True
                        if 'NX enabled' in checksec_output:
                            checks['executable_stack'] = False
                        if 'Full RELRO' in checksec_output:
                            checks['relro'] = 'full'
                        elif 'Partial RELRO' in checksec_output:
                            checks['relro'] = 'partial'
                        if 'PIE enabled' in checksec_output:
                            checks['pie'] = 'enabled'
                        
                        break  # Check just the first ELF found
                except:
                    continue
        
    except Exception as e:
        checks['error'] = str(e)
    finally:
        # Clean up
        if os.path.exists(temp_dir):
            subprocess.run(['rm', '-rf', temp_dir])
    
    return checks

def calculate_risk_score(results):
    """Calculate a risk score based on analysis findings"""
    score = 0
    
    # Vulnerabilities add to score
    for vuln in results.get('vulnerabilities', []):
        if vuln.get('severity') == 'critical':
            score += 20
        elif vuln.get('severity') == 'high':
            score += 15
        elif vuln.get('severity') == 'medium':
            score += 10
        else:
            score += 5
    
    # Security checks affect score
    checks = results.get('security_checks', {})
    if not checks.get('stack_protection', False):
        score += 15
    if checks.get('executable_stack', True):
        score += 20
    if checks.get('relro') == 'none':
        score += 15
    elif checks.get('relro') == 'partial':
        score += 5
    if checks.get('pie') != 'enabled':
        score += 10
    
    # Cap at 100
    return min(score, 100)

@bp.route('/analyze/<int:analysis_id>')
@login_required
def analyze(analysis_id):
    analysis = FirmwareAnalysis.query.get_or_404(analysis_id)
    if analysis.author != current_user:
        flash('You do not have permission to view this analysis.')
        return redirect(url_for('main.index'))
    
    try:
        # Set analysis status to processing
        analysis.analysis_status = 'processing'
        analysis.analysis_date = datetime.utcnow()
        db.session.commit()
        
        # Run comprehensive security analysis
        analysis_results = run_security_analysis(analysis.filepath)
        
        # Generate report file
        report_filename = f'report_{analysis.id}.json'
        report_path = os.path.join(Config.ANALYSIS_FOLDER, report_filename)
        
        with open(report_path, 'w') as f:
            json.dump(analysis_results, f, indent=2)
        
        # Update analysis record
        analysis.analysis_status = 'completed'
        analysis.report_path = report_path
        analysis.findings = json.dumps(analysis_results['vulnerabilities'])
        analysis.risk_score = analysis_results['risk_score']
        analysis.analysis_details = json.dumps({
            'binwalk': analysis_results['binwalk'],
            'security_checks': analysis_results['security_checks']
        })
        db.session.commit()
        
        return redirect(url_for('analysis.results', analysis_id=analysis.id))
    
    except subprocess.CalledProcessError as e:
        analysis.analysis_status = 'failed'
        analysis.findings = f"Analysis failed: {str(e.output.decode('utf-8'))}"
        db.session.commit()
        flash('Analysis failed due to a processing error.')
        return redirect(url_for('analysis.status', analysis_id=analysis.id))
    except Exception as e:
        analysis.analysis_status = 'failed'
        analysis.findings = f"Unexpected error: {str(e)}"
        db.session.commit()
        flash('An unexpected error occurred during analysis.')
        return redirect(url_for('analysis.status', analysis_id=analysis.id))

@bp.route('/results/<int:analysis_id>')
@login_required
def results(analysis_id):
    analysis = FirmwareAnalysis.query.get_or_404(analysis_id)
    if analysis.author != current_user:
        flash('You do not have permission to view this analysis.')
        return redirect(url_for('main.index'))
    
    if analysis.analysis_status != 'completed':
        flash('Analysis not yet completed.')
        return redirect(url_for('analysis.status', analysis_id=analysis.id))
    
    # Load the detailed report
    report_data = None
    if analysis.report_path and os.path.exists(analysis.report_path):
        with open(analysis.report_path, 'r') as f:
            report_data = json.load(f)
    if 'file_info' in report_data and 'metadata' not in report_data:
            report_data['metadata'] = {
                'file_type': report_data['file_info'].get('type', 'Unknown'),
                'file_size': report_data['file_info'].get('size', 0)}
    
    return render_template('analysis/results.html', 
                        analysis=analysis,
                        report=report_data)

@bp.route('/download_report/<int:analysis_id>')
@login_required
def download_report(analysis_id):
    analysis = FirmwareAnalysis.query.get_or_404(analysis_id)
    if analysis.author != current_user:
        flash('You do not have permission to download this report.')
        return redirect(url_for('main.index'))
    
    if not analysis.report_path or not os.path.exists(analysis.report_path):
        flash('Report not available.')
        return redirect(url_for('main.index'))
    
    return send_from_directory(
        Config.ANALYSIS_FOLDER,
        os.path.basename(analysis.report_path),
        as_attachment=True,
        mimetype='application/json'
    )

@bp.route('/status/<int:analysis_id>')
@login_required
def status(analysis_id):
    analysis = FirmwareAnalysis.query.get_or_404(analysis_id)
    if analysis.author != current_user:
        flash('You do not have permission to view this analysis.')
        return redirect(url_for('main.index'))
    return render_template('analysis/status.html', analysis=analysis)