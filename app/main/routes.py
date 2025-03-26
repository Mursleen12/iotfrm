from flask import render_template, flash, redirect, url_for, request
from flask_login import current_user, login_required
from app import db
from app.main import bp
from app.models import FirmwareAnalysis
from app.main.forms import FirmwareUploadForm
import os
from datetime import datetime
from config import Config
from werkzeug.utils import secure_filename

@bp.route('/')
@bp.route('/index')
def index():
    if current_user.is_authenticated:
        analyses = current_user.analyses.order_by(FirmwareAnalysis.upload_date.desc()).all()
        # Ensure all analyses have a risk_score (default to 0 if None)
        for analysis in analyses:
            if analysis.risk_score is None:
                analysis.risk_score = 0
        return render_template('index.html', 
                            title='Dashboard' if current_user.is_authenticated else 'Home',
                            analyses=analyses)
    return render_template('index.html', title='Home')

@bp.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    form = FirmwareUploadForm()
    if form.validate_on_submit():
        file = form.firmware.data
        if file:
            filename = secure_filename(file.filename)
            if not os.path.exists(Config.UPLOAD_FOLDER):
                os.makedirs(Config.UPLOAD_FOLDER)
            filepath = os.path.join(Config.UPLOAD_FOLDER, filename)
            file.save(filepath)
            
            analysis = FirmwareAnalysis(
                filename=filename,
                filepath=filepath,
                author=current_user,
                analysis_status='pending',
                risk_score=0
            )
            db.session.add(analysis)
            db.session.commit()
            
            flash('Your firmware has been uploaded and is ready for analysis!', 'success')
            return redirect(url_for('analysis.analyze', analysis_id=analysis.id))
    
    return render_template('main/upload.html', title='Upload Firmware', form=form)

@bp.route('/about')
def about():
    return render_template('about.html', title='About')

@bp.route('/how_it_works')
def how_it_works():
    return render_template('how_it_works.html', title='How It Works')