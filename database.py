from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    input_text = db.Column(db.Text)
    input_url = db.Column(db.String(500))
    sender = db.Column(db.String(200))
    severity = db.Column(db.String(50))
    threats = db.Column(db.Text)
    recommendation = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)