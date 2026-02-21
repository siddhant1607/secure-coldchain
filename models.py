from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class EventLog(db.Model):
    __tablename__ = "event_logs"

    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(50), nullable=False)
    sequence = db.Column(db.Integer, nullable=False)
    event = db.Column(db.Text, nullable=False)
    hash = db.Column(db.String(100), nullable=False)
    signature = db.Column(db.Text, nullable=False)
    eth_tx = db.Column(db.String(100), nullable=True)