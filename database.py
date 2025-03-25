from app.init import db
from app.models import User, FirmwareAnalysis

def init_db():
    db.create_all()

def clear_db():
    db.drop_all()