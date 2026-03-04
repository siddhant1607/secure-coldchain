# 🧊 Secure Cold Chain Monitor

A blockchain-anchored IoT system for tamper-proof monitoring of temperature-sensitive supply chains using ESP32, cryptographic hash chains, and Ethereum for violation anchoring.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-green.svg)
![Flask](https://img.shields.io/badge/flask-3.1-red.svg)
![ESP32](https://img.shields.io/badge/ESP32-Arduino-00979D.svg)

---

## 📋 Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [System Architecture](#system-architecture)
- [Hardware Components](#hardware-components)
- [Software Stack](#software-stack)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [API Documentation](#api-documentation)
- [Security Features](#security-features)
- [How It Works](#how-it-works)
- [Deployment](#deployment)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

---

## 🔍 Overview

Secure Cold Chain Monitor is an end-to-end IoT solution designed to ensure the integrity of temperature-sensitive supply chains (pharmaceuticals, vaccines, food, etc.). The system uses **cryptographic hash chains** for tamper detection and **Ethereum blockchain anchoring** for immutable violation records.

### Problem Statement
Traditional cold chain monitoring systems are vulnerable to:
- Post-facto data manipulation
- Device tampering without detection
- Lack of cryptographic proof
- No immutable audit trails

### Solution
This system provides:
- **Cryptographic chain of custody** using ECDSA signatures
- **Tamper-evident logging** with SHA-256 hash chains
- **Blockchain anchoring** of critical violations on Ethereum Sepolia
- **Real-time monitoring** via Streamlit dashboard
- **Offline resilience** with local chain verification

---

## ✨ Key Features

### 🔐 Security
- **ECDSA P-256 signatures** on all sensor events
- **SHA-256 hash chaining** for tamper detection
- **Blockchain anchoring** of violations to Ethereum
- **Replay attack protection** via hash uniqueness
- **Chain integrity verification** on backend

### 📊 Monitoring
- **Temperature & Humidity** tracking (DHT11 sensor)
- **Tilt detection** (MPU6050 accelerometer)
- **Shock detection** via accelerometer thresholds
- **Light tampering** detection (LDR sensor)
- **Seal integrity** monitoring (Reed switch)
- **Impact detection** (impact sensor)

### 🌐 Dashboard
- Real-time sensor readings visualization
- Event timeline with violation tracking
- Temperature trend charts with threshold lines
- Chain integrity metrics
- Blockchain transaction verification
- Filterable event logs

---

## 🏗️ System Architecture

```
┌─────────────────┐         ┌──────────────────┐         ┌─────────────────┐
│   ESP32 Device  │────────▶│  Flask Backend   │────────▶│  PostgreSQL DB  │
│  (Sensor Node)  │  HTTPS  │  (Chain Verifier)│         │  (Event Store)  │
└─────────────────┘         └──────────────────┘         └─────────────────┘
        │                            │
        │ Crypto Hash Chain          │ Violation Anchoring
        │                            │
        ▼                            ▼
┌─────────────────┐         ┌──────────────────┐
│  Local NVS      │         │  Ethereum        │
│  (Private Key)  │         │  Sepolia Testnet │
└─────────────────┘         └──────────────────┘
                                     │
                                     │ Verification
                                     ▼
                            ┌──────────────────┐
                            │  Streamlit UI    │
                            │  (Dashboard)     │
                            └──────────────────┘
```

### Data Flow

1. **Sensor Reading** → ESP32 reads environmental data
2. **Event Creation** → Device creates structured event string
3. **Hash Chain** → SHA-256(Event || Previous Hash)
4. **Signature** → ECDSA sign the hash with private key
5. **Transmission** → HTTPS POST to backend
6. **Verification** → Backend validates signature and chain
7. **Storage** → Event logged to PostgreSQL
8. **Anchoring** → Violations anchored to Ethereum (optional)
9. **Visualization** → Streamlit dashboard displays data

---

## 🔧 Hardware Components

### Required Hardware
| Component | Model | Purpose |
|-----------|-------|---------|
| Microcontroller | ESP32-WROOM-32 | Main processing & WiFi |
| Temperature/Humidity | DHT11 | Environmental monitoring |
| Accelerometer | MPU6050 | Tilt & shock detection |
| Real-Time Clock | DS3231 | Accurate timestamping |
| Light Sensor | LDR + Voltage Divider | Tamper detection |
| Magnetic Switch | Reed Switch | Seal monitoring |
| Impact Sensor | SW-420 | Physical impact detection |

### Pin Configuration
```cpp
#define DHTPIN 14        // DHT11 data pin
#define LDR_PIN 25       // Light sensor
#define IMPACT_PIN 27    // Impact sensor
#define REED_PIN 26      // Reed switch
#define MPU_ADDR 0x69    // MPU6050 I2C address

// I2C Pins
SDA = GPIO 23
SCL = GPIO 22
```

### Circuit Diagram
```
ESP32                       Sensors
                                
GPIO14 ──────────────────── DHT11 Data
GPIO25 ──────┬─────────────── LDR (with pullup)
GPIO26 ──────┼─────────────── Reed Switch
GPIO27 ──────┴─────────────── Impact Sensor

GPIO23 (SDA) ───┬─────────── MPU6050 SDA
GPIO22 (SCL) ───┴─────────── MPU6050 SCL
                └─────────── DS3231 SDA/SCL
```

---

## 💻 Software Stack

### Backend (Flask)
- **Python 3.8+**
- **Flask** - Web framework
- **SQLAlchemy** - ORM
- **PostgreSQL** - Database
- **Web3.py** - Ethereum interaction
- **Cryptography** - ECDSA verification
- **Gunicorn** - Production server

### Frontend (Streamlit)
- **Streamlit 1.54+** - Dashboard framework
- **Plotly** - Interactive charts
- **Pandas** - Data manipulation
- **Requests** - HTTP client

### Firmware (ESP32)
- **Arduino Framework**
- **WiFi** - Connectivity
- **HTTPClient** - API calls
- **mbedTLS** - Cryptography
- **Wire** - I2C communication
- **DHT** - Sensor library
- **RTClib** - RTC interface

---

## 🚀 Installation

### Prerequisites
- Python 3.8 or higher
- PostgreSQL 12+
- Arduino IDE with ESP32 board support
- Infura account (for Ethereum)
- Git

### Backend Setup

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/secure-coldchain.git
cd secure-coldchain
```

2. **Create virtual environment**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Set up PostgreSQL**
```bash
# Create database
psql -U postgres
CREATE DATABASE coldchain;
\q
```

5. **Configure environment variables**
Create a `.env` file:
```env
DATABASE_URL=postgresql://user:password@localhost:5432/coldchain
INFURA_URL=https://sepolia.infura.io/v3/YOUR_PROJECT_ID
ANCHOR_PRIVATE_KEY=0xYOUR_ETHEREUM_PRIVATE_KEY
REGISTER_PASSWORD=your_secure_registration_password
```

6. **Initialize database**
```bash
python
>>> from app import app, db
>>> with app.app_context():
...     db.create_all()
>>> exit()
```

7. **Run the backend**
```bash
python app.py
# Server runs on http://localhost:5000
```

### Frontend Setup

1. **Navigate to project directory**
```bash
cd secure-coldchain
```

2. **Update backend URL in streamlit_app.py**
```python
BACKEND_URL = "http://localhost:5000"  # For local development
```

3. **Run Streamlit**
```bash
streamlit run streamlit_app.py
# Dashboard opens at http://localhost:8501
```

### Firmware Setup

1. **Install Arduino IDE**
   - Download from [arduino.cc](https://arduino.cc)

2. **Add ESP32 board support**
   - File → Preferences
   - Add to "Additional Board Manager URLs":
     ```
     https://dl.espressif.com/dl/package_esp32_index.json
     ```
   - Tools → Board → Boards Manager → Install "ESP32 by Espressif"

3. **Install required libraries**
   - Sketch → Include Library → Manage Libraries
   - Install: `RTClib`, `DHT sensor library`, `Adafruit Unified Sensor`

4. **Configure firmware**
Edit `esp32_firmware.ino`:
```cpp
const char* ssid = "Your-WiFi-SSID";
const char* password = "Your-WiFi-Password";
const char* DEVICE_ID = "ESP32-DEVICE-001";
const char* BASE_URL = "https://your-backend.com";
const char* REGISTER_PASSWORD = "your_secure_password";
```

5. **Upload firmware**
   - Connect ESP32 via USB
   - Tools → Board → ESP32 Dev Module
   - Tools → Port → Select your COM port
   - Click Upload

---

## ⚙️ Configuration

### Temperature Thresholds
```cpp
#define TEMP_MIN 2.0    // Minimum safe temperature (°C)
#define TEMP_MAX 8.0    // Maximum safe temperature (°C)
#define TEMP_DELTA 0.5  // Minimum change to log (°C)
```

### Humidity Thresholds
```cpp
#define HUM_MIN 30.0    // Minimum humidity (%)
#define HUM_MAX 70.0    // Maximum humidity (%)
#define HUM_DELTA 5.0   // Minimum change to log (%)
```

### Tilt Thresholds
```cpp
#define TILT_WARN 20    // Warning threshold (degrees)
#define TILT_VIOL 60    // Violation threshold (degrees)
#define TILT_DELTA 10   // Minimum change to log (degrees)
```

### Shock Threshold
```cpp
#define SHOCK_THRESHOLD 28000  // Accelerometer threshold
```

### Heartbeat Interval
```cpp
#define HEARTBEAT_INTERVAL 30000  // 30 seconds
```

---

## 📖 Usage

### Device Registration

1. **First-time setup**: Upload firmware to ESP32
2. **Auto-registration**: Device generates keypair and registers automatically
3. **Verify**: Check Serial Monitor for registration confirmation
4. **Dashboard**: Device appears in Streamlit interface

### Monitoring

1. **Access Dashboard**: Navigate to `http://localhost:8501`
2. **Enter Device ID**: Type your device ID (e.g., `ESP32-WOK3`)
3. **Click Load Data**: View real-time sensor readings
4. **Explore Tabs**:
   - **Dashboard**: Overview and charts
   - **Violations**: Detailed violation history
   - **Event Log**: Complete audit trail
   - **Blockchain**: Anchored transaction verification

### Event Types

| Type | Description | Anchored? |
|------|-------------|-----------|
| `EVENT_LOG` | Normal sensor readings | No |
| `EVENT_WARNING` | Minor threshold breach | No |
| `EVENT_VIOLATION` | Critical threshold breach | Yes |

### Violation Types

- `TEMP_VIOLATION` - Temperature out of range
- `HUM_VIOLATION` - Humidity out of range
- `TILT_WARNING` - Moderate tilt detected
- `TILT_VIOLATION` - Severe tilt detected
- `SHOCK_DETECTED` - Physical shock event
- `LIGHT_TAMPER` - Unexpected light exposure
- `SEAL_OPEN` - Container seal broken
- `IMPACT_EVENT` - Physical impact detected

---

## 🔌 API Documentation

### Base URL
```
http://localhost:5000
```

### Endpoints

#### 1. Health Check
```http
GET /
```
**Response:**
```json
"Backend Running"
```

#### 2. Register Device
```http
POST /register-device
```
**Request Body:**
```json
{
  "device_id": "ESP32-001",
  "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
  "signature": "0x1234...",
  "password": "registration_password"
}
```
**Response:**
```json
{
  "status": "device registered",
  "eth_tx": "0xabc123..."
}
```

#### 3. Sync Chain
```http
GET /sync?device_id=ESP32-001
```
**Response:**
```json
{
  "last_hash": "0x789def..."
}
```

#### 4. Submit Event
```http
POST /event
```
**Request Body:**
```json
{
  "device_id": "ESP32-001",
  "event": "TEMP_VIOLATION|ESP32-001|TEMP=12.5|TS=2024-03-04T10:30:00",
  "type": "EVENT_VIOLATION",
  "hash": "0xabc123...",
  "signature": "0xdef456..."
}
```
**Response:**
```json
{
  "accepted": true,
  "anchored": true,
  "eth_tx": "0x789abc..."
}
```

#### 5. Get Logs
```http
GET /logs?device_id=ESP32-001
```
**Response:**
```json
[
  {
    "id": 1,
    "event": "SENSOR_READING|ESP32-001|TEMP=5.2|HUM=55.0|TILT=2.1|TS=2024-03-04T10:00:00",
    "event_type": "EVENT_LOG",
    "hash": "0x123abc...",
    "signature": "0x456def...",
    "eth_tx": null,
    "is_chain_valid": true,
    "is_signature_valid": true,
    "is_hash_valid": true,
    "is_anchored": false
  }
]
```

---

## 🔒 Security Features

### Cryptographic Hash Chain

Each event creates a hash chain:
```
Hash(N) = SHA256(Event(N) || Hash(N-1))
```

**Genesis Hash**: `"GENESIS"` (starting point)

**Example Chain:**
```
Hash_0 = "GENESIS"
Hash_1 = SHA256("SENSOR_READING|...|PREV=GENESIS")
Hash_2 = SHA256("TEMP_VIOLATION|...|PREV=0xHash_1")
Hash_3 = SHA256("SENSOR_READING|...|PREV=0xHash_2")
```

**Tamper Detection**: If any event is modified, all subsequent hashes become invalid.

### ECDSA Signatures

- **Algorithm**: ECDSA with P-256 curve
- **Hash**: SHA-256
- **Key Storage**: Secure NVS on ESP32
- **Verification**: Backend validates all signatures

**Signature Process:**
1. Device creates event string
2. Computes hash chain
3. Signs hash with private key
4. Transmits event + hash + signature
5. Backend verifies signature against device's public key

### Blockchain Anchoring

**When**: Only for `EVENT_VIOLATION` events
**Network**: Ethereum Sepolia Testnet
**Method**: Transaction with event data in `data` field
**Purpose**: Immutable, timestamped proof of violation

**Anchored Data:**
```json
{
  "type": "VIOLATION",
  "device_id": "ESP32-001",
  "event": "TEMP_VIOLATION|...",
  "device_hash": "0x123...",
  "signature": "0x456..."
}
```

### Replay Protection

- **Unique Hash**: Each event must have a unique hash
- **Database Constraint**: `UNIQUE(device_id, hash)`
- **Rejection**: Duplicate events are rejected by backend

---

## 🔍 How It Works

### 1. Device Initialization
```
ESP32 Boot → Check NVS for Keys
    ↓ No Keys
Generate ECDSA Keypair
    ↓
Store Private Key in NVS
    ↓
Sign Registration Message
    ↓
Send to Backend (/register-device)
    ↓
Backend Verifies & Stores Public Key
    ↓
Anchor Registration to Blockchain
```

### 2. Event Generation
```
Sensor Reading → Check Thresholds
    ↓ Violation Detected
Create Event String: "TEMP_VIOLATION|ESP32-001|TEMP=12.5|TS=..."
    ↓
Build Chain: Event || "PREV=" || previousHash
    ↓
Hash: SHA256(chainedString)
    ↓
Sign: ECDSA(hash, privateKey)
    ↓
Send: {event, hash, signature} → Backend
```

### 3. Backend Verification
```
Receive Event → Check Device Registered
    ↓
Verify Signature: ECDSA.verify(signature, hash, publicKey)
    ↓
Get Last Valid Hash from DB
    ↓
Recompute Hash: SHA256(event || previousHash)
    ↓
Compare: receivedHash == recomputedHash
    ↓ Valid
Check Event Type
    ↓ EVENT_VIOLATION
Anchor to Ethereum
    ↓
Store Event in PostgreSQL
```

### 4. Dashboard Visualization
```
Streamlit UI → API Call /logs?device_id=X
    ↓
Parse Events → Extract Sensor Data
    ↓
Render Charts: Temperature, Timeline, etc.
    ↓
Show Violations with Blockchain Links
```

---

## 🌐 Deployment

### Backend Deployment (Render)

1. **Create Render account**: [render.com](https://render.com)

2. **Create Web Service**:
   - Connect GitHub repository
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `gunicorn app:app`

3. **Add PostgreSQL**:
   - Create PostgreSQL database on Render
   - Copy connection string to environment variables

4. **Configure Environment Variables**:
   - `DATABASE_URL`: Render PostgreSQL URL
   - `INFURA_URL`: Your Infura endpoint
   - `ANCHOR_PRIVATE_KEY`: Ethereum wallet key
   - `REGISTER_PASSWORD`: Device registration password

5. **Deploy**: Render auto-deploys on push

### Frontend Deployment (Streamlit Cloud)

1. **Push to GitHub**: Ensure `streamlit_app.py` is in repo

2. **Deploy on Streamlit Cloud**:
   - Visit [share.streamlit.io](https://share.streamlit.io)
   - Connect GitHub repository
   - Select `streamlit_app.py`
   - Deploy

3. **Update BACKEND_URL** in `streamlit_app.py` to your Render URL

### Production Considerations

- **HTTPS**: Enable SSL/TLS on backend
- **Rate Limiting**: Add API rate limiting
- **Monitoring**: Set up logging and alerts
- **Backup**: Automated database backups
- **Scaling**: Use load balancer for multiple devices
- **Security**: Rotate Ethereum keys periodically

---

## 🐛 Troubleshooting

### ESP32 Issues

**Problem**: Device won't connect to WiFi
```
Solution:
- Check SSID and password in firmware
- Ensure 2.4GHz network (ESP32 doesn't support 5GHz)
- Check router firewall settings
```

**Problem**: "Failed to load key from NVS"
```
Solution:
- Send "WIPE" command within 5 seconds of boot
- Device will erase NVS and generate new keypair
```

**Problem**: Backend returns "Invalid signature"
```
Solution:
- Re-register device (wipe NVS and reboot)
- Check clock synchronization (RTC battery)
- Verify backend has correct public key
```

### Backend Issues

**Problem**: Database connection failed
```
Solution:
- Check DATABASE_URL in .env
- Verify PostgreSQL is running
- Test connection: psql -U user -d coldchain
```

**Problem**: Ethereum anchoring fails
```
Solution:
- Check INFURA_URL is valid
- Verify wallet has sufficient Sepolia ETH
- Check ANCHOR_PRIVATE_KEY format (0x prefix)
```

### Dashboard Issues

**Problem**: "Backend is waking up" message
```
Solution:
- Wait 30-60 seconds (Render cold start)
- Refresh page
- Check backend URL in streamlit_app.py
```

**Problem**: No data displayed
```
Solution:
- Verify device ID is correct
- Check device has sent events
- Use /logs API endpoint to verify data exists
```

---

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. **Fork the repository**
2. **Create feature branch**: `git checkout -b feature/amazing-feature`
3. **Commit changes**: `git commit -m 'Add amazing feature'`
4. **Push to branch**: `git push origin feature/amazing-feature`
5. **Open Pull Request**

### Development Setup

```bash
# Clone your fork
git clone https://github.com/yourusername/secure-coldchain.git
cd secure-coldchain

# Create branch
git checkout -b feature/my-feature

# Install dev dependencies
pip install -r requirements.txt
pip install pytest black flake8

# Run tests
pytest tests/

# Format code
black .

# Lint
flake8 .
```

### Code Style

- **Python**: Follow PEP 8
- **C++**: Follow Arduino style guide
- **Comments**: Document complex logic
- **Tests**: Add tests for new features

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **mbedTLS** - Cryptography library for ESP32
- **Web3.py** - Ethereum integration
- **Streamlit** - Dashboard framework
- **Flask** - Backend framework
- **Infura** - Ethereum node infrastructure

---

## 📞 Support

For issues and questions:
- **GitHub Issues**: [Create an issue](https://github.com/yourusername/secure-coldchain/issues)
- **Email**: support@yourproject.com
- **Documentation**: [Wiki](https://github.com/yourusername/secure-coldchain/wiki)

---

## 🗺️ Roadmap

- [ ] Add GPS location tracking
- [ ] Implement multi-device dashboard
- [ ] Add SMS/email alerts for violations
- [ ] Support for Polygon/Ethereum mainnet
- [ ] Mobile app (React Native)
- [ ] Machine learning anomaly detection
- [ ] PDF report generation
- [ ] Multi-language support

---

**Built with ❤️ for supply chain integrity**
