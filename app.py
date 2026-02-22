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

from web3 import Web3

# ================= INIT =================

load_dotenv()

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)

with app.app_context():
    db.create_all()

GENESIS_HASH = "GENESIS"

# ================= ETHEREUM SETUP =================

INFURA_URL = os.getenv("INFURA_URL")
PRIVATE_KEY = os.getenv("ANCHOR_PRIVATE_KEY")

w3 = Web3(Web3.HTTPProvider(INFURA_URL))
ACCOUNT = w3.eth.account.from_key(PRIVATE_KEY)

CHAIN_ID = 11155111  # Sepolia


# ================= HELPER FUNCTIONS =================

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
        print("Signature verification error:", e)
        return False


def recompute_hash(event_string, previous_hash):
    payload = f"{event_string}|PREV={previous_hash}"
    digest = hashlib.sha256(payload.encode()).hexdigest()
    return "0x" + digest


def get_last_valid_hash(device_id):
    last_valid_log = (
        EventLog.query
        .filter_by(device_id=device_id, is_chain_valid=True)
        .order_by(EventLog.id.desc())
        .first()
    )

    return last_valid_log.hash if last_valid_log else GENESIS_HASH


def anchor_hash_to_eth(event_hash):
    try:
        tx = {
            "to": ACCOUNT.address,
            "value": 0,
            "data": w3.to_bytes(hexstr=event_hash),
            "gas": 200000,
            "gasPrice": w3.to_wei("5", "gwei"),
            "nonce": w3.eth.get_transaction_count(ACCOUNT.address),
            "chainId": CHAIN_ID
        }

        signed_tx = ACCOUNT.sign_transaction(tx)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)

        return tx_hash.hex()

    except Exception as e:
        print("Anchoring failed:", e)
        return None


# ================= ROUTES =================

@app.route("/")
def home():
    return "Backend Running"


# 🔁 Sync endpoint (for device reboot recovery)
@app.route("/sync", methods=["GET"])
def sync_device():
    device_id = request.args.get("device_id")

    if not device_id:
        return jsonify({"error": "Missing device_id"}), 400

    device = Device.query.filter_by(device_id=device_id).first()
    if not device:
        return jsonify({"error": "Unknown device"}), 400

    last_hash = get_last_valid_hash(device_id)

    return jsonify({"last_hash": last_hash}), 200


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

    # 🔒 Replay protection
    existing = EventLog.query.filter_by(
        device_id=device_id,
        hash=incoming_hash
    ).first()

    if existing:
        return jsonify({
            "accepted": False,
            "reason": "Duplicate event"
        }), 400

    # 🔗 Chain validation
    previous_hash = get_last_valid_hash(device_id)
    recomputed_hash = recompute_hash(event, previous_hash)

    is_hash_valid = (recomputed_hash == incoming_hash)

    is_signature_valid = verify_signature(
        device.public_key,
        recomputed_hash,
        signature
    )

    is_chain_valid = is_hash_valid and is_signature_valid

    eth_tx = None
    is_anchored = False

    if is_chain_valid:
        eth_tx = anchor_hash_to_eth(incoming_hash)
        if eth_tx:
            is_anchored = True

    # 📝 Store log
    log = EventLog(
        device_id=device_id,
        event=event,
        hash=incoming_hash,
        signature=signature,
        eth_tx=eth_tx,
        is_anchored=is_anchored,
        is_signature_valid=is_signature_valid,
        is_hash_valid=is_hash_valid,
        is_chain_valid=is_chain_valid
    )

    db.session.add(log)
    db.session.commit()

    return jsonify({
        "accepted": is_chain_valid,
        "anchored": is_anchored,
        "eth_tx": eth_tx
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

@app.route("/device/<device_id>", methods=["GET"])
def check_device(device_id):
    device = Device.query.filter_by(device_id=device_id).first()

    if device:
        return jsonify({
            "exists": True,
            "device_id": device_id,
            "registered_at": device.registered_at
        }), 200

    return jsonify({
        "exists": False,
        "device_id": device_id
    }), 404

@app.route("/logs", methods=["GET"])
def get_logs():
    device_id = request.args.get("device_id")

    logs = EventLog.query.filter_by(
        device_id=device_id
    ).order_by(EventLog.id.asc()).all()

    output = []

    for log in logs:
        output.append({
            "id": log.id,
            "event": log.event,
            "hash": log.hash,
            "eth_tx": log.eth_tx,
            "is_chain_valid": log.is_chain_valid,
            "is_signature_valid": log.is_signature_valid,
            "is_hash_valid": log.is_hash_valid
        })

    return jsonify(output), 200

@app.route("/debug-db")
def debug_db():
    from sqlalchemy import inspect
    inspector = inspect(db.engine)
    return {
        "tables": inspector.get_table_names()
    }

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
