from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
)
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import json

# ================= GENERATE KEYPAIR =================

private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
public_key = private_key.public_key()

private_pem = private_key.private_bytes(
    Encoding.PEM,
    PrivateFormat.TraditionalOpenSSL,
    NoEncryption(),
).decode()

public_pem = public_key.public_bytes(
    Encoding.PEM,
    PublicFormat.SubjectPublicKeyInfo,
).decode()

DEVICE_ID = "ESP32_WOK1"

print("PRIVATE KEY:\n", private_pem)
print("PUBLIC KEY:\n", public_pem)

# ================= BUILD MESSAGE (LIKE ESP32) =================

message = (DEVICE_ID + public_pem).encode()

# ================= SIGN (LIKE ESP32 SHOULD) =================

signature = private_key.sign(
    message,
    ec.ECDSA(hashes.SHA256())
)

signature_hex = "0x" + signature.hex()

print("\nSignature:", signature_hex)

# ================= VERIFY (LIKE BACKEND) =================

try:
    public_key.verify(
        signature,
        message,
        ec.ECDSA(hashes.SHA256())
    )
    print("\n✅ Verification SUCCESS")
except InvalidSignature:
    print("\n❌ Verification FAILED")