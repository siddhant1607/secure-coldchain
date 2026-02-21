import requests
import hashlib
from web3 import Web3

# ================= CONFIG =================

BACKEND_URL = "https://secure-coldchain.onrender.com"
INFURA_URL = "https://sepolia.infura.io/v3/e188c99cec2d4625a7d915761a8b1073"
DEVICE_ID = "ESP32_SIM"

GENESIS_HASH = "GENESIS"

# ================= CONNECT TO ETH =================

w3 = Web3(Web3.HTTPProvider(INFURA_URL))

if not w3.is_connected():
    raise Exception("❌ Failed to connect to Sepolia via Infura.")

print("\n========= SECURE COLD CHAIN AUDIT =========\n")

# ================= FETCH LOGS =================

try:
    response = requests.get(
        f"{BACKEND_URL}/logs",
        params={"device_id": DEVICE_ID},
        timeout=10
    )
except Exception as e:
    raise Exception(f"❌ Backend connection failed: {str(e)}")

if response.status_code != 200:
    raise Exception(f"❌ Backend error: {response.status_code}")

try:
    logs = response.json()
except:
    raise Exception("❌ Failed to parse backend response.")

if not logs:
    print("No logs found.")
    exit()

previous_hash = GENESIS_HASH
overall_chain_valid = True

# ================= VERIFY EACH LOG =================

for log in logs:

    print(f"Log ID: {log['id']}")
    print(f"Event: {log['event']}")
    print(f"Stored Hash: {log['hash']}")

    # -------- Recompute Hash --------
    payload = f"{log['event']}|PREV={previous_hash}"
    recomputed_hash = "0x" + hashlib.sha256(payload.encode()).hexdigest()

    if recomputed_hash == log["hash"]:
        print("Chain Recompute: ✅ VALID")
    else:
        print("Chain Recompute: ❌ BROKEN")
        print(f"Expected Hash: {recomputed_hash}")
        overall_chain_valid = False

    # -------- Backend Flags --------
    print("Backend Flags:")
    print(f"  Chain Valid: {log['is_chain_valid']}")
    print(f"  Signature Valid: {log['is_signature_valid']}")
    print(f"  Hash Valid: {log['is_hash_valid']}")

    if not log["is_chain_valid"]:
        print("⚠ Backend marked this event invalid.")

    # -------- Blockchain Verification --------
    if log.get("eth_tx"):

        try:
            tx = w3.eth.get_transaction(log["eth_tx"])
            onchain_input = tx["input"]

            if onchain_input.lower() == log["hash"].lower():
                print("Blockchain Check: ✅ MATCH")
            else:
                print("Blockchain Check: ❌ MISMATCH")
                overall_chain_valid = False

            print(f"TX Hash: {log['eth_tx']}")
            print(f"Etherscan: https://sepolia.etherscan.io/tx/{log['eth_tx']}")

        except Exception as e:
            print("Blockchain Check: ❌ ERROR FETCHING TX")
            print(f"Error: {str(e)}")
            overall_chain_valid = False

    else:
        print("Blockchain Check: Not Anchored")

    print("\n--------------------------------------------\n")

    # Only extend chain if backend marked it valid
    if log["is_chain_valid"]:
        previous_hash = log["hash"]

# ================= FINAL RESULT =================

if overall_chain_valid:
    print("✅ OVERALL STATUS: CHAIN INTEGRITY VERIFIED")
else:
    print("❌ OVERALL STATUS: CHAIN COMPROMISED OR INVALID EVENTS FOUND")

print("\n========= AUDIT COMPLETE =========\n")