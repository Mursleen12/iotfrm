from flask import render_template, flash, redirect, url_for, request
from flask_login import current_user, login_required
from app.models import db

from app.main import bp
from app.main.forms import FirmwareUploadForm
from app.models import FirmwareAnalysis
import os
from werkzeug.utils import secure_filename
from datetime import datetime
import magic
from config import Config

@bp.route('/')
@bp.route('/index')
def index():
    if current_user.is_authenticated:
        analyses = current_user.analyses.order_by(FirmwareAnalysis.upload_date.desc()).all()
        return render_template('index.html', title='Home', analyses=analyses)
    return render_template('index.html', title='Home')

@bp.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    form = FirmwareUploadForm()
    if form.validate_on_submit():
        file = form.firmware.data
        if file:
            filename = secure_filename(file.filename)
            filepath = os.path.join(Config.UPLOAD_FOLDER, filename)
            file.save(filepath)
            
            # Basic file type validation
            file_type = magic.from_file(filepath, mime=True)
            if not file_type.startswith('application/') and not file_type.startswith('application/octet-stream'):
                os.remove(filepath)
                flash('Invalid file type. Please upload a firmware file.')
                return redirect(url_for('main.upload_file'))
            
            analysis = FirmwareAnalysis(
                filename=filename,
                filepath=filepath,
                author=current_user,
                analysis_status='pending'
            )
            db.session.add(analysis)
            db.session.commit()
            
            flash('Your firmware has been uploaded and is ready for analysis!')
            return redirect(url_for('analysis.analyze', analysis_id=analysis.id))
    return render_template('main/upload.html', title='Upload Firmware', form=form)