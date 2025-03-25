from datetime import datetime
from app import db, login_manager
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    full_name = db.Column(db.String(120))
    company = db.Column(db.String(120))
    analyses = db.relationship('FirmwareAnalysis', backref='author', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

class FirmwareAnalysis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(256))
    filepath = db.Column(db.String(256))
    upload_date = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    analysis_status = db.Column(db.String(64), default='pending')
    report_path = db.Column(db.String(256))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    findings = db.Column(db.Text)
    risk_score = db.Column(db.Integer)
    analysis_date = db.Column(db.DateTime)
    analysis_details = db.Column(db.Text) 
    def __repr__(self):
        return f'<FirmwareAnalysis {self.filename}>'

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))