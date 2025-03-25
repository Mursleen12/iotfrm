import subprocess
import os
import json
import magic
import sqlite3
from datetime import datetime
from config import Config

class FirmwareAnalyzer:
    def __init__(self, firmware_path):
        self.firmware_path = firmware_path
        self.results = {
            'metadata': {},
            'binwalk': {},
            'firmwalker': {},
            'security_checks': {},
            'vulnerabilities': [],
            'risk_score': 0
        }
    
    def run_analysis(self):
        self._extract_metadata()
        self._run_binwalk()
        self._run_firmwalker()
        self._perform_security_checks()
        self._check_vulnerabilities()
        self._calculate_risk_score()
        return self.results
    
    def _extract_metadata(self):
        self.results['metadata'] = {
            'filename': os.path.basename(self.firmware_path),
            'size': os.path.getsize(self.firmware_path),
            'file_type': magic.from_file(self.firmware_path),
            'analysis_date': datetime.utcnow().isoformat()
        }
    
    def _run_binwalk(self):
        try:
            result = subprocess.run(
                [Config.ANALYSIS_TOOLS['binwalk'], self.firmware_path],
                capture_output=True,
                text=True
            )
            self.results['binwalk'] = {
                'output': result.stdout,
                'signatures': self._parse_binwalk(result.stdout)
            }
        except Exception as e:
            self.results['binwalk'] = {'error': str(e)}
    
    def _parse_binwalk(self, output):
        signatures = []
        for line in output.split('\n'):
            if 'DECIMAL' in line and 'HEXADECIMAL' in line:
                continue
            if line.strip():
                parts = line.split()
                if len(parts) >= 3:
                    signatures.append({
                        'offset': parts[0],
                        'type': ' '.join(parts[1:-1]),
                        'description': parts[-1]
                    })
        return signatures
    
    def _run_firmwalker(self):
        try:
            temp_dir = os.path.join(Config.UPLOAD_FOLDER, 'temp_extracted')
            os.makedirs(temp_dir, exist_ok=True)
            
            subprocess.run(
                [Config.ANALYSIS_TOOLS['binwalk'], '-e', self.firmware_path],
                cwd=temp_dir,
                check=True
            )
            
            result = subprocess.run(
                [Config.ANALYSIS_TOOLS['firmwalker'], temp_dir],
                capture_output=True,
                text=True
            )
            self.results['firmwalker'] = self._parse_firmwalker(result.stdout)
        except Exception as e:
            self.results['firmwalker'] = {'error': str(e)}
        finally:
            # Clean up temporary files
            if os.path.exists(temp_dir):
                subprocess.run(['rm', '-rf', temp_dir])
    
    def _parse_firmwalker(self, output):
        findings = {}
        current_section = None
        for line in output.split('\n'):
            if line.startswith('##'):
                current_section = line[2:].strip()
                findings[current_section] = []
            elif current_section and line.strip():
                findings[current_section].append(line.strip())
        return findings
    
    def _perform_security_checks(self):
        checks = {
            'executable_stack': False,
            'stack_protection': False,
            'relro': 'None',
            'pie': 'None',
            'canary': False
        }
        
        try:
            # Find the main executable in extracted files
            temp_dir = os.path.join(Config.UPLOAD_FOLDER, 'temp_checksec')
            os.makedirs(temp_dir, exist_ok=True)
            
            subprocess.run(
                [Config.ANALYSIS_TOOLS['binwalk'], '-e', self.firmware_path],
                cwd=temp_dir,
                check=True
            )
            
            # Look for ELF binaries
            for root, _, files in os.walk(temp_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    if self._is_elf(file_path):
                        result = subprocess.run(
                            [Config.ANALYSIS_TOOLS['checksec'], '--file=' + file_path],
                            capture_output=True,
                            text=True
                        )
                        if 'No RELRO' not in result.stdout:
                            checks['relro'] = 'Partial' if 'Partial RELRO' in result.stdout else 'Full'
                        checks['executable_stack'] = 'NX disabled' in result.stdout
                        checks['stack_protection'] = 'Canary found' in result.stdout
                        checks['pie'] = 'PIE enabled' in result.stdout
                        break
            
            self.results['security_checks'] = checks
        except Exception as e:
            self.results['security_checks'] = {'error': str(e)}
        finally:
            if os.path.exists(temp_dir):
                subprocess.run(['rm', '-rf', temp_dir])
    
    def _is_elf(self, file_path):
        try:
            result = subprocess.run(
                [Config.ANALYSIS_TOOLS['file'], file_path],
                capture_output=True,
                text=True
            )
            return 'ELF' in result.stdout
        except:
            return False
    
    def _check_vulnerabilities(self):
        vulnerabilities = []
        
        # Check binwalk results for known components
        for sig in self.results['binwalk'].get('signatures', []):
            component = sig['description']
            for known_component, vulns in Config.KNOWN_VULNS.items():
                if known_component in component:
                    vulnerabilities.extend([
                        {'component': known_component, 'cve': cve}
                        for cve in vulns
                    ])
        
        # Check firmwalker results for potential issues
        for section, items in self.results['firmwalker'].items():
            if isinstance(items, list):
                for item in items:
                    if 'password' in item.lower():
                        vulnerabilities.append({
                            'component': 'Firmware',
                            'issue': 'Hardcoded credentials',
                            'location': item
                        })
        
        self.results['vulnerabilities'] = vulnerabilities
    
    def _calculate_risk_score(self):
        score = 0
        
        # Vulnerabilities add to score
        score += len(self.results['vulnerabilities']) * 10
        
        # Security checks affect score
        checks = self.results['security_checks']
        if checks.get('executable_stack', False):
            score += 20
        if checks.get('relro', 'None') == 'None':
            score += 15
        elif checks.get('relro', 'None') == 'Partial':
            score += 5
        if checks.get('pie', 'None') != 'PIE enabled':
            score += 10
        if not checks.get('stack_protection', False):
            score += 15
        
        # Cap score at 100
        self.results['risk_score'] = min(score, 100)