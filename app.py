import os
import json
import hashlib
from flask import Flask, request, jsonify
from dotenv import load_dotenv
from models import db, EventLog, Device

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature

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


# ================= ETHEREUM =================

INFURA_URL = os.getenv("INFURA_URL")
PRIVATE_KEY = os.getenv("ANCHOR_PRIVATE_KEY")

w3 = Web3(Web3.HTTPProvider(INFURA_URL))
ACCOUNT = w3.eth.account.from_key(PRIVATE_KEY)

CHAIN_ID = 11155111  # Sepolia


# ================= SIGNATURE HELPERS =================

def verify_prehashed_signature(public_key_pem, digest_bytes, signature_hex):
    """
    Verifies ECDSA signature where digest is already SHA256(message)
    """
    try:
        normalized_pub = public_key_pem.replace("\r", "").strip()

        signature_bytes = bytes.fromhex(signature_hex.replace("0x", ""))

        public_key = load_pem_public_key(normalized_pub.encode())

        public_key.verify(
            signature_bytes,
            digest_bytes,
            ec.ECDSA(utils.Prehashed(hashes.SHA256()))
        )

        return True

    except InvalidSignature:
        return False
    except Exception as e:
        print("Signature verification error:", e)
        return False


def verify_registration(device_id, public_key_pem, signature_hex):
    """
    Registration uses:
    digest = SHA256(device_id + public_key)
    """
    # Restore real newlines
    public_key_pem = public_key_pem.replace("\\n", "\n")

    normalized_pub = public_key_pem.replace("\r", "").strip()

    message = (device_id.strip() + normalized_pub).encode()
    digest = hashlib.sha256(message).digest()

    return verify_prehashed_signature(
        normalized_pub,
        digest,
        signature_hex
    )


def verify_event_signature(public_key_pem, hash_hex, signature_hex):
    """
    Event signature verifies prehashed event hash
    """
    hash_bytes = bytes.fromhex(hash_hex.replace("0x", ""))

    return verify_prehashed_signature(
        public_key_pem,
        hash_bytes,
        signature_hex
    )


# ================= HASH CHAIN =================

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


# ================= BLOCKCHAIN =================

def anchor_payload(payload_dict):
    try:
        payload_json = json.dumps(payload_dict, sort_keys=True)
        payload_bytes = payload_json.encode()

        tx = {
            "to": ACCOUNT.address,
            "value": 0,
            "data": payload_bytes,
            "gas": 300000,
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


# -------- DEVICE REGISTER --------

@app.route("/device-register", methods=["POST"])
def device_register():

    data = request.get_json()

    device_id = data.get("device_id")
    public_key = data.get("public_key")
    signature = data.get("signature")

    if not all([device_id, public_key, signature]):
        return jsonify({"error": "Missing fields"}), 400

    if not verify_registration(device_id, public_key, signature):
        return jsonify({"error": "Invalid registration signature"}), 400

    if Device.query.filter_by(device_id=device_id).first():
        return jsonify({"error": "Device already registered"}), 400

    public_key = public_key.replace("\\n", "\n")

    new_device = Device(
        device_id=device_id,
        public_key=public_key
    )

    db.session.add(new_device)
    db.session.commit()

    return jsonify({"status": "registered"}), 200


# -------- DEVICE INFO --------

@app.route("/device/<device_id>", methods=["GET"])
def get_device(device_id):

    device = Device.query.filter_by(device_id=device_id).first()

    if not device:
        return jsonify({"exists": False}), 404

    return jsonify({
        "exists": True,
        "device_id": device.device_id,
        "public_key": device.public_key,
        "registered_at": device.registered_at
    }), 200


# -------- EVENT --------

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

    if EventLog.query.filter_by(device_id=device_id, hash=incoming_hash).first():
        return jsonify({"accepted": False, "reason": "Duplicate event"}), 400

    previous_hash = get_last_valid_hash(device_id)
    recomputed_hash = recompute_hash(event, previous_hash)

    is_hash_valid = (recomputed_hash == incoming_hash)

    is_signature_valid = verify_event_signature(
        device.public_key,
        recomputed_hash,
        signature
    )

    is_chain_valid = is_hash_valid and is_signature_valid

    log = EventLog(
        device_id=device_id,
        event=event,
        hash=incoming_hash,
        signature=signature,
        eth_tx=None,
        is_anchored=False,
        is_signature_valid=is_signature_valid,
        is_hash_valid=is_hash_valid,
        is_chain_valid=is_chain_valid
    )

    db.session.add(log)
    db.session.commit()

    return jsonify({
        "accepted": is_chain_valid
    }), 200


if __name__ == "__main__":
    print("RUNNING FLASK...")
    app.run(host="0.0.0.0", port=5000, debug=True)