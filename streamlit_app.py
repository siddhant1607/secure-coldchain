import streamlit as st
import requests
import hashlib
import json
from web3 import Web3
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import utils

# CONFIG
BACKEND_URL = "https://secure-coldchain.onrender.com"
INFURA_URL = "https://sepolia.infura.io/v3/YOUR_REAL_INFURA_KEY"

w3 = Web3(Web3.HTTPProvider(INFURA_URL))
GENESIS_HASH = "GENESIS"

st.set_page_config(layout="wide")
st.title("🔐 Secure Cold Chain Audit")

device_id = st.text_input("Enter Device ID")

if not device_id:
    st.stop()

# Fetch logs
res = requests.get(f"{BACKEND_URL}/logs", params={"device_id": device_id})
if res.status_code != 200:
    st.error("Failed to fetch logs.")
    st.stop()

logs = res.json()
if not logs:
    st.warning("No logs found.")
    st.stop()

# Fetch public key
device_res = requests.get(f"{BACKEND_URL}/device/{device_id}")
if device_res.status_code != 200:
    st.error("Device not found.")
    st.stop()

public_key = device_res.json()["public_key"]

# Metrics
total = len(logs)
violations = len([l for l in logs if l["event"].startswith("TEMP_VIOLATION")])
tampered = len([l for l in logs if not l["is_chain_valid"]])

c1, c2, c3 = st.columns(3)
c1.metric("Total Events", total)
c2.metric("Violations", violations)
c3.metric("Tampered", tampered)

st.divider()

def verify_log(log, index):

    result = {"chain": True, "signature": True, "blockchain": True, "reason": []}

    # Chain
    prev = GENESIS_HASH if index == 0 else logs[index-1]["hash"]
    recomputed = "0x" + hashlib.sha256(
        f"{log['event']}|PREV={prev}".encode()
    ).hexdigest()

    if recomputed != log["hash"]:
        result["chain"] = False
        result["reason"].append("Chain mismatch")

    # Signature
    try:
        hash_bytes = bytes.fromhex(log["hash"].replace("0x", ""))
        sig_bytes = bytes.fromhex(log["signature"].replace("0x", ""))

        pub = load_pem_public_key(public_key.encode())
        pub.verify(sig_bytes, hash_bytes,
                   ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    except Exception:
        result["signature"] = False
        result["reason"].append("Signature invalid")

    # Blockchain (violations only)
    if log.get("eth_tx"):
        try:
            tx = w3.eth.get_transaction(log["eth_tx"])
            raw_input = tx["input"]

            if hasattr(raw_input, "hex"):
                raw_bytes = bytes(raw_input)
            elif isinstance(raw_input, str):
                raw_bytes = bytes.fromhex(raw_input.replace("0x",""))
            else:
                raw_bytes = raw_input

            decoded = raw_bytes.decode()
            payload = json.loads(decoded)

            if payload.get("device_hash") != log["hash"]:
                result["blockchain"] = False
                result["reason"].append("Blockchain mismatch")

        except Exception as e:
            result["blockchain"] = False
            result["reason"].append(f"Blockchain error: {str(e)}")

    return result


for i, log in enumerate(logs):

    with st.expander(f"Log {log['id']} — {log['event']}"):

        st.write("Hash:", log["hash"])
        st.write("Anchored:", log["is_anchored"])

        if log["event"].startswith("TEMP_VIOLATION"):
            if st.button(f"Verify {log['id']}"):
                v = verify_log(log, i)

                if all(v.values()):
                    st.success("✅ Fully Verified")
                else:
                    st.error("❌ Verification Failed")
                    for r in v["reason"]:
                        st.write("-", r)