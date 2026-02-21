import requests

BACKEND_URL = "https://secure-coldchain.onrender.com"

# ================= DEVICE REGISTRY =================

DEVICES = {
    "ESP32_SIM": """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEvPQyjj63ePDdWTRAnfLinvG1OZtg
XtUhpK2eJ62CMjMCFU4qRfRABb3H7V8ZV+MnhnWpEAfG3y68ae8e2rjw6A==
-----END PUBLIC KEY-----"""
}


# ================= FUNCTIONS =================

def device_exists(device_id):
    for attempt in range(3):
        try:
            response = requests.get(
                f"{BACKEND_URL}/device/{device_id}",
                timeout=40
            )

            if response.status_code == 200:
                return True
            elif response.status_code == 404:
                return False

        except Exception as e:
            print(f"Retry {attempt+1}/3...")
    
    return False


def register_device(device_id, public_key):
    try:
        response = requests.post(
            f"{BACKEND_URL}/register-device",
            json={
                "device_id": device_id,
                "public_key": public_key
            },
            timeout=10
        )

        if response.status_code == 200:
            print(f"✅ {device_id} registered successfully.")
        else:
            print(f"⚠ Failed to register {device_id}: {response.text}")

    except Exception as e:
        print(f"❌ Error registering {device_id}: {str(e)}")


# ================= MAIN =================

print("\n========== DEVICE ADMIN DASHBOARD ==========\n")

for device_id, public_key in DEVICES.items():

    print(f"🔎 Checking device: {device_id}")

    if device_exists(device_id):
        print(f"ℹ {device_id} already exists.\n")
    else:
        print(f"⚠ {device_id} not found. Registering...")
        register_device(device_id, public_key)
        print()

print("========== ADMIN TASK COMPLETE ==========\n")