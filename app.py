import os
import hashlib
from flask import Flask, request, jsonify
from dotenv import load_dotenv
from models import db, EventLog, Device

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import utils

load_dotenv()

app = Flask(__name__)

# ================= DATABASE CONFIG =================

app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,
    "pool_recycle": 300
}

db.init_app(app)

with app.app_context():
    db.create_all()

# ================= HELPERS =================

GENESIS_HASH = "GENESIS"


def verify_signature(public_key_pem, hash_hex, signature_hex):
    try:
        hash_bytes = bytes.fromhex(hash_hex[2:])
        signature_bytes = bytes.fromhex(signature_hex[2:])

        public_key = load_pem_public_key(public_key_pem.encode())

        public_key.verify(
            signature_bytes,
            hash_bytes,
            ec.ECDSA(utils.Prehashed(hashes.SHA256()))
        )

        return True

    except InvalidSignature:
        return False
    except Exception as e:
        print("Verification error:", e)
        return False


def recompute_hash(event_string, previous_hash):
    payload = f"{event_string}|PREV={previous_hash}"
    digest = hashlib.sha256(payload.encode()).hexdigest()
    return "0x" + digest


# ================= ROUTES =================

@app.route("/")
def home():
    return "Backend Running"


@app.route("/event", methods=["POST"])
def receive_event():
    data = request.get_json()

    device_id = data.get("device_id")
    event = data.get("event")
    incoming_hash = data.get("hash")
    signature = data.get("signature")

    if not all([device_id, event, incoming_hash, signature]):
        return jsonify({"error": "Missing fields"}), 400

    device = Device.query.filter_by(device_id=device_id).first()

    if not device:
        return jsonify({"error": "Unknown device"}), 400

    # Get last VALID chain anchor
    last_valid_log = (
        EventLog.query
        .filter_by(device_id=device_id, is_chain_valid=True)
        .order_by(EventLog.id.desc())
        .first()
    )

    previous_hash = last_valid_log.hash if last_valid_log else GENESIS_HASH

    # Recompute hash server-side
    recomputed_hash = recompute_hash(event, previous_hash)
    is_hash_valid = recomputed_hash == incoming_hash

    # Verify signature against recomputed hash
    is_signature_valid = verify_signature(
        device.public_key,
        recomputed_hash,
        signature
    )

    is_chain_valid = is_hash_valid and is_signature_valid

    # Prevent duplicate replay
    existing = EventLog.query.filter_by(
        device_id=device_id,
        hash=incoming_hash
    ).first()

    if existing:
        return jsonify({"error": "Duplicate event"}), 400

    log = EventLog(
        device_id=device_id,
        event=event,
        hash=incoming_hash,
        signature=signature,
        is_signature_valid=is_signature_valid,
        is_hash_valid=is_hash_valid,
        is_chain_valid=is_chain_valid
    )

    db.session.add(log)
    db.session.commit()

    return jsonify({
        "stored": True,
        "hash_valid": is_hash_valid,
        "signature_valid": is_signature_valid,
        "chain_valid": is_chain_valid
    }), 200


@app.route("/register-device", methods=["POST"])
def register_device():
    data = request.get_json()

    device_id = data.get("device_id")
    public_key = data.get("public_key")

    if not device_id or not public_key:
        return jsonify({"error": "Missing fields"}), 400

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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)