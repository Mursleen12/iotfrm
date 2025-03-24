from flask import Flask, render_template, redirect, url_for, flash, request
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_dance.contrib.google import make_google_blueprint, google
from werkzeug.security import generate_password_hash, check_password_hash
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "2aba2fc54fec461e7999c9c6138f20eaaf3b6ae8a6e9d34c79733d6eb1bc6ee2")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['UPLOAD_FOLDER'] = 'uploads/'
app.config['TEMPLATES_AUTO_RELOAD'] = True  # For development

db = SQLAlchemy(app)

# Google OAuth Setup
google_bp = make_google_blueprint(
    client_id=os.getenv("GOOGLE_OAUTH_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_OAUTH_CLIENT_SECRET"),
    scope=["profile", "email"],
    redirect_to="google_login"
)
app.register_blueprint(google_bp, url_prefix="/login")

login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    name = db.Column(db.String(100))
    password = db.Column(db.String(100))
    first_login = db.Column(db.Boolean, default=True)
    profile_complete = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    """Main landing page that shows different content based on auth status"""
    if current_user.is_authenticated and not current_user.profile_complete:
        return redirect(url_for('complete_profile'))
    return render_template('index.html')

@app.before_request
def require_profile_completion():
    """Ensure users complete their profile before accessing other pages"""
    exempt_endpoints = ['login', 'signup', 'static', 'complete_profile', 'google.login', 'logout']
    if (current_user.is_authenticated and 
        not current_user.profile_complete and 
        request.endpoint not in exempt_endpoints):
        return redirect(url_for('complete_profile'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash(f"Welcome back, {user.name}!", "success")
            if not user.profile_complete:
                return redirect(url_for('complete_profile'))
            return redirect(url_for('index'))
        
        flash('Invalid email or password', 'danger')
    
    return render_template('login.html')

@app.route('/complete-profile', methods=['GET', 'POST'])
@login_required
def complete_profile():
    """Handle profile completion for first-time users"""
    if request.method == 'POST':
        current_user.name = request.form.get('name', current_user.name)
        current_user.profile_complete = True
        db.session.commit()
        flash('Profile completed successfully!', 'success')
        return redirect(url_for('index'))
    
    return render_template('complete_profile.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Handle new user registration"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        name = request.form.get('name')
        password = request.form.get('password')
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists!', 'danger')
            return redirect(url_for('signup'))
        
        new_user = User(
            email=email,
            name=name,
            password=generate_password_hash(password)
        )
        db.session.add(new_user)
        db.session.commit()
        
        login_user(new_user)
        flash(f"Welcome, {name}! Please complete your profile.", "success")
        return redirect(url_for('complete_profile'))
    
    return render_template('signup.html')

@app.route('/login/google')
def google_login():
    """Handle Google OAuth login"""
    if not google.authorized:
        return redirect(url_for("google.login"))
    
    resp = google.get("/oauth2/v2/userinfo")
    if resp.ok:
        user_info = resp.json()
        email = user_info["email"]
        user = User.query.filter_by(email=email).first()
        
        if not user:
            user = User(
                email=email,
                name=user_info.get("name", "Google User"),
                password=None,
                profile_complete=True  # Skip profile completion for Google users
            )
            db.session.add(user)
            db.session.commit()
        
        login_user(user)
        flash(f"Welcome, {user.name}!", "success")
        return redirect(url_for('index'))
    
    flash("Google login failed", "danger")
    return redirect(url_for('login'))

@app.route('/logout')
@login_required
def logout():
    """Handle user logout"""
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for('index'))

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    """Handle firmware uploads"""
    if 'file' not in request.files:
        flash('No file selected', 'danger')
        return redirect(url_for('index'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No file selected', 'danger')
        return redirect(url_for('index'))
    
    if file:
        # Save the file and process it
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # TODO: Add your firmware analysis logic here
        
        flash('Firmware uploaded successfully! Analysis in progress...', 'success')
        return redirect(url_for('index'))

# Initialize database
with app.app_context():
    db.create_all()
    # Create uploads directory if it doesn't exist
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

if __name__ == '__main__':
    app.run(debug=True)