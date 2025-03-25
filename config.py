import os
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-here'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = os.path.join(basedir, 'uploads')
    ANALYSIS_FOLDER = os.path.join(basedir, 'analysis')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max upload size
    ALLOWED_EXTENSIONS = {'bin', 'hex', 'elf', 'img', 'zip'}
    ANALYSIS_TOOLS = {
        'binwalk': '/usr/bin/binwalk',
        'firmwalker': '/opt/firmwalker/firmwalker.sh',
        'checksec': '/usr/bin/checksec',
        'strings': '/usr/bin/strings',
        'file': '/usr/bin/file',
        'radare2': '/usr/bin/r2'
    }
    VULNERABILITY_DATABASE = os.path.join(basedir, 'data/vulnerabilities.db')
    KNOWN_VULNS = {
        'BusyBox': ['CVE-2021-42373', 'CVE-2021-42374', 'CVE-2021-42375'],
        'Linux': ['CVE-2022-0847', 'CVE-2021-4034'],
        'OpenSSL': ['CVE-2022-3602', 'CVE-2022-3786']
    }