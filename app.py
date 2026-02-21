import os
from flask import Flask, request, jsonify
from dotenv import load_dotenv
from models import db, EventLog, Device

load_dotenv()

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)

@app.route("/")
def home():
    return "Backend Running"

@app.route("/event", methods=["POST"])
def receive_event():
    data = request.get_json()

    log = EventLog(
        device_id=data["device_id"],
        sequence=data["sequence"],
        event=data["event"],
        hash=data["hash"],
        signature=data["signature"],
        eth_tx=data.get("eth_tx")
    )

    db.session.add(log)
    db.session.commit()

    return jsonify({"status": "stored"}), 200

@app.route("/register-device", methods=["POST"])
def register_device():
    data = request.get_json()

    device_id = data["device_id"]
    public_key = data["public_key"]

    existing = Device.query.filter_by(device_id=device_id).first()
    if existing:
        return jsonify({"error": "Device already exists"}), 400

    new_device = Device(
        device_id=device_id,
        public_key=public_key
    )

    db.session.add(new_device)
    db.session.commit()

    return jsonify({"status": "device registered"})

@app.route("/init-db")
def init_db():
    with app.app_context():
        db.create_all()
    return "Database initialized"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)