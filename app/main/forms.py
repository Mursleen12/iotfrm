from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from wtforms import SubmitField

class FirmwareUploadForm(FlaskForm):
    firmware = FileField('Firmware File', validators=[FileRequired()])
    submit = SubmitField('Upload')