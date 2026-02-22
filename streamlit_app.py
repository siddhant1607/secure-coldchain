import streamlit as st
import requests
import hashlib
import json
from web3 import Web3
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import utils

# ================= CONFIG =================

BACKEND_URL = "https://secure-coldchain.onrender.com"
INFURA_URL = "https://sepolia.infura.io/v3/YOUR_INFURA_KEY"

w3 = Web3(Web3.HTTPProvider(INFURA_URL))

GENESIS_HASH = "GENESIS"

# ================= UI SETUP =================

st.set_page_config(page_title="Cold Chain Audit Dashboard", layout="wide")
st.title("🔐 Secure Cold Chain - Audit Dashboard")

# ================= FETCH DEVICES =================

try:
    devices_res = requests.get(f"{BACKEND_URL}/device/ESP32_SIM")
except:
    st.error("Backend not reachable.")
    st.stop()

device_id = st.text_input("Enter Device ID", value="ESP32_SIM")

if not device_id:
    st.stop()

# ================= FETCH LOGS =================

try:
    response = requests.get(
        f"{BACKEND_URL}/logs",
        params={"device_id": device_id},
        timeout=10
    )
except Exception as e:
    st.error(f"Backend error: {e}")
    st.stop()

if response.status_code != 200:
    st.error("Failed to fetch logs.")
    st.stop()

logs = response.json()

if not logs:
    st.warning("No logs found for this device.")
    st.stop()

# ================= METRICS =================

total_events = len(logs)
total_violations = len([l for l in logs if l["event"].startswith("TEMP_VIOLATION")])
total_tampered = len([l for l in logs if not l["is_chain_valid"]])

col1, col2, col3 = st.columns(3)
col1.metric("Total Events", total_events)
col2.metric("Total Violations", total_violations)
col3.metric("Tampered Events", total_tampered)

st.divider()

# ================= VERIFICATION FUNCTION =================

def verify_event(log):

    result = {
        "chain": True,
        "signature": True,
        "blockchain": True,
        "reason": []
    }

    # 1️⃣ Chain recompute
    index = logs.index(log)
    previous_hash = GENESIS_HASH if index == 0 else logs[index - 1]["hash"]

    payload = f"{log['event']}|PREV={previous_hash}"
    recomputed_hash = "0x" + hashlib.sha256(payload.encode()).hexdigest()

    if recomputed_hash != log["hash"]:
        result["chain"] = False
        result["reason"].append("Chain mismatch")

    # 2️⃣ Signature verify
    try:
        device_info = requests.get(f"{BACKEND_URL}/device/{device_id}").json()
        public_key = device_info.get("public_key")

        if public_key:
            hash_bytes = bytes.fromhex(log["hash"].replace("0x", ""))
            signature_bytes = bytes.fromhex(log["signature"].replace("0x", ""))

            public_key_obj = load_pem_public_key(public_key.encode())

            public_key_obj.verify(
                signature_bytes,
                hash_bytes,
                ec.ECDSA(utils.Prehashed(hashes.SHA256()))
            )
        else:
            raise Exception("Public key not found")

    except Exception:
        result["signature"] = False
        result["reason"].append("Signature invalid")

    # 3️⃣ Blockchain verify (only if anchored)
    if log.get("eth_tx"):
        try:
            tx_hash = log["eth_tx"]
            if not tx_hash.startswith("0x"):
                tx_hash = "0x" + tx_hash

            tx = w3.eth.get_transaction(tx_hash)

            raw_input = tx["input"]
            raw_bytes = bytes.fromhex(raw_input.replace("0x", ""))
            decoded = raw_bytes.decode("utf-8")

            payload_on_chain = json.loads(decoded)

            if payload_on_chain.get("device_hash") != log["hash"]:
                result["blockchain"] = False
                result["reason"].append("Blockchain hash mismatch")

        except Exception:
            result["blockchain"] = False
            result["reason"].append("Blockchain verification failed")

    return result

# ================= TABLE DISPLAY =================

for log in logs:

    with st.expander(f"Log ID {log['id']} - {log['event']}"):

        st.write("**Event:**", log["event"])
        st.write("**Hash:**", log["hash"])
        st.write("**Anchored:**", log.get("is_anchored"))

        verify_btn = st.button(f"Verify Log {log['id']}")

        if verify_btn:
            verification = verify_event(log)

            if all([
                verification["chain"],
                verification["signature"],
                verification["blockchain"]
            ]):
                st.success("✅ Fully Verified")
            else:
                st.error("❌ Verification Failed")
                for r in verification["reason"]:
                    st.write("-", r)
