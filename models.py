from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class EventLog(db.Model):
    __tablename__ = "event_logs"

    id = db.Column(db.Integer, primary_key=True)

    device_id = db.Column(db.String(50), nullable=False, index=True)
    event = db.Column(db.Text, nullable=False)

    hash = db.Column(db.String(100), nullable=False)
    signature = db.Column(db.Text, nullable=False)

    eth_tx = db.Column(db.String(100), nullable=True)
    is_anchored = db.Column(db.Boolean, default=False)

    is_signature_valid = db.Column(db.Boolean, default=False)
    is_hash_valid = db.Column(db.Boolean, default=False)
    is_chain_valid = db.Column(db.Boolean, default=False)

    created_at = db.Column(db.DateTime, default=db.func.now())

    __table_args__ = (
        db.UniqueConstraint("device_id", "hash", name="unique_device_hash"),
    )


class Device(db.Model):
    __tablename__ = "devices"

    id = db.Column(db.Integer, primary_key=True)

    device_id = db.Column(db.String(50), unique=True, nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    registration_tx = db.Column(db.String, nullable=True)
    registered_at = db.Column(db.DateTime, default=db.func.now())