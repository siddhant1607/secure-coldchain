import os
from flask import Flask, request, jsonify
from dotenv import load_dotenv
from models import db, EventLog, Device
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature
import binascii

load_dotenv()

app = Flask(__name__)

# ================= DATABASE CONFIG =================

app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,     # 🔥 Fixes SSL idle disconnect issue
    "pool_recycle": 300        # Recycle connections every 5 mins
}

db.init_app(app)

# 🔥 Create tables automatically on startup
with app.app_context():
    db.create_all()

def verify_signature(public_key_pem, hash_hex, signature_hex):
    try:
        # Remove 0x
        hash_bytes = bytes.fromhex(hash_hex[2:])
        signature_bytes = bytes.fromhex(signature_hex[2:])

        public_key = load_pem_public_key(public_key_pem.encode())

        public_key.verify(
            signature_bytes,
            hash_bytes,
            ec.ECDSA(hashes.SHA256())
        )

        return True

    except InvalidSignature:
        return False
    except Exception as e:
        print("Verification error:", e)
        return False

# ================= ROUTES =================

@app.route("/")
def home():
    return "Backend Running"


@app.route("/event", methods=["POST"])
def receive_event():
    data = request.get_json()

    device = Device.query.filter_by(device_id=data["device_id"]).first()

    if not device:
        return jsonify({"error": "Unknown device"}), 400

    is_valid = verify_signature(
        device.public_key,
        data["hash"],
        data["signature"]
    )

    log = EventLog(
        device_id=data["device_id"],
        sequence=data["sequence"],
        event=data["event"],
        hash=data["hash"],
        signature=data["signature"],
        eth_tx=data.get("eth_tx"),
        is_signature_valid=is_valid
    )

    db.session.add(log)
    db.session.commit()

    return jsonify({
        "status": "stored",
        "signature_valid": is_valid
    }), 200

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

    return jsonify({"status": "device registered"}), 200

# ================= LOCAL RUN =================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)