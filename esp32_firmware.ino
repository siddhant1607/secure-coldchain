#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <Wire.h>
#include <RTClib.h>
#include <DHT.h>
#include <Preferences.h>
#include <math.h>

#include "mbedtls/sha256.h"
#include "mbedtls/pk.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "nvs_flash.h"

/* ================= PIN DEFINITIONS ================= */

#define DHTPIN 14
#define DHTTYPE DHT11

#define LDR_PIN 25
#define IMPACT_PIN 27
#define REED_PIN 26

#define MPU_ADDR 0x69

/* ================= WIFI CONFIG ================= */

const char* ssid = "Your-SSID";
const char* password = "Your-Device-Name";

/* ================= DEVICE CONFIG ================= */

const char* DEVICE_ID = "ESP32-XX";

/* ================= BACKEND CONFIG ================= */

const char* BASE_URL = "Your-Backend-URL";
const char* REGISTER_PASSWORD = "Your-Register-Password";

String REGISTER_URL;
String EVENT_URL;
String SYNC_URL;

/* ================= SENSOR OBJECTS ================= */

DHT dht(DHTPIN, DHTTYPE);
RTC_DS3231 rtc;
bool rtcAvailable = false;

Preferences prefs;

/* ================= MPU VARIABLES ================= */

int16_t ax, ay, az;

/* ================= THRESHOLDS ================= */

#define TEMP_MIN 2.0
#define TEMP_MAX 8.0
#define TEMP_DELTA 0.5

#define HUM_MIN 30.0
#define HUM_MAX 70.0
#define HUM_DELTA 5.0

#define TILT_WARN 20
#define TILT_VIOL 60
#define TILT_DELTA 10

#define SHOCK_THRESHOLD 28000

#define HEARTBEAT_INTERVAL 30000

/* ================= STATE VARIABLES ================= */

float lastViolationTemp = -1000;
float lastViolationHum = -1000;
float lastViolationTilt = -1000;

bool ldrViolationActive = false;
bool reedViolationActive = false;
bool impactViolationActive = false;

unsigned long lastShockTime = 0;
unsigned long lastHeartbeat = 0;

/* ================= CRYPTO VARIABLES ================= */

String previousHash = "GENESIS";

mbedtls_pk_context pk;
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;

/* ================= TIMESTAMP ================= */

String getTimestamp() {

  if (!rtcAvailable) return "NO_RTC";

  DateTime now = rtc.now() + TimeSpan(0,0,0,0); //Set Time Offset according to the RTC Calibration 

  char buffer[25];

  sprintf(buffer,
          "%04d-%02d-%02dT%02d:%02d:%02d",
          now.year(),
          now.month(),
          now.day(),
          now.hour(),
          now.minute(),
          now.second());

  return String(buffer);
}

/* ================= CRYPTO INIT ================= */

void initCrypto() {

  mbedtls_pk_init(&pk);
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);

  const char* pers = "esp32-core";

  mbedtls_ctr_drbg_seed(
    &ctr_drbg,
    mbedtls_entropy_func,
    &entropy,
    (const unsigned char*)pers,
    strlen(pers)
  );
}

/* ================= SHA256 ================= */

String sha256(String input) {

  uint8_t hash[32];
  mbedtls_sha256_context ctx;

  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0);
  mbedtls_sha256_update(&ctx,
                        (const uint8_t*)input.c_str(),
                        input.length());
  mbedtls_sha256_finish(&ctx, hash);
  mbedtls_sha256_free(&ctx);

  String out = "0x";

  for (int i = 0; i < 32; i++) {
    if (hash[i] < 16) out += "0";
    out += String(hash[i], HEX);
  }

  return out;
}

/* ================= KEY HANDLING ================= */

bool loadPrivateKey() {

  prefs.begin("device", true);
  String storedKey = prefs.getString("privkey", "");
  prefs.end();

  if (storedKey == "") {
    Serial.println("⚠ No private key in NVS");
    return false;
  }

  int ret = mbedtls_pk_parse_key(
      &pk,
      (const unsigned char*)storedKey.c_str(),
      storedKey.length() + 1,
      NULL,
      0,
      mbedtls_ctr_drbg_random,
      &ctr_drbg
  );

  if (ret != 0) {
    Serial.println("❌ Failed to load key from NVS");
    return false;
  }

  Serial.println("✅ Private key loaded from NVS");

  return true;
}

/* ================= KEY GENERATION ================= */

void generateKeypair() {

  Serial.println("🔐 Generating new keypair...");

  mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));

  mbedtls_ecp_gen_key(
      MBEDTLS_ECP_DP_SECP256R1,
      mbedtls_pk_ec(pk),
      mbedtls_ctr_drbg_random,
      &ctr_drbg
  );

  unsigned char priv_buf[1600];
  unsigned char pub_buf[800];

  memset(priv_buf, 0, sizeof(priv_buf));
  memset(pub_buf, 0, sizeof(pub_buf));

  mbedtls_pk_write_key_pem(&pk, priv_buf, sizeof(priv_buf));
  mbedtls_pk_write_pubkey_pem(&pk, pub_buf, sizeof(pub_buf));

  String privateKey = String((char*)priv_buf);
  String publicKey  = String((char*)pub_buf);

  prefs.begin("device", false);
  prefs.putString("privkey", privateKey);
  prefs.putBool("registered", false);
  prefs.end();

  Serial.println("✅ Keypair stored in NVS");

  registerDevice(publicKey);
}

/* ================= SIGN HASH ================= */

String signHash(String hashHex) {

  uint8_t hash[32];

  for (int i = 0; i < 32; i++) {
    hash[i] = strtoul(
      hashHex.substring(2 + i * 2, 4 + i * 2).c_str(),
      NULL,
      16
    );
  }

  uint8_t sig[128];
  size_t sigLen = 0;

  int ret = mbedtls_pk_sign(
      &pk,
      MBEDTLS_MD_SHA256,
      hash,
      32,
      sig,
      sizeof(sig),
      &sigLen,
      mbedtls_ctr_drbg_random,
      &ctr_drbg
  );

  if (ret != 0) {
    Serial.println("❌ Signature failed");
    return "";
  }

  String out = "0x";

  for (size_t i = 0; i < sigLen; i++) {
    if (sig[i] < 16) out += "0";
    out += String(sig[i], HEX);
  }

  return out;
}

/* ================= REGISTER DEVICE ================= */

void registerDevice(String publicKeyRaw) {

  String escaped = publicKeyRaw;
  escaped.replace("\r", "");
  escaped.replace("\n", "\\n");

  String message = String(DEVICE_ID) + publicKeyRaw;
  String digestHex = sha256(message);
  String signature = signHash(digestHex);

  WiFiClientSecure client;
  client.setInsecure();

  HTTPClient https;
  https.begin(client, REGISTER_URL);
  https.addHeader("Content-Type", "application/json");

  String payload =
      "{"
      "\"device_id\":\"" + String(DEVICE_ID) + "\","
      "\"public_key\":\"" + escaped + "\","
      "\"signature\":\"" + signature + "\","
      "\"password\":\"" + String(REGISTER_PASSWORD) + "\""
      "}";

  Serial.println("📡 Registering device...");

  int code = https.POST(payload);

  Serial.print("🌐 HTTP Status: ");
  Serial.println(code);

  String response = https.getString();

  Serial.println("📩 Backend Response:");
  Serial.println(response);

  if (code == 200) {

    prefs.begin("device", false);
    prefs.putBool("registered", true);
    prefs.end();

    Serial.println("✅ Device registration saved");
  }

  https.end();
}

/* ================= SYNC ================= */

void syncPreviousHash() {

  WiFiClientSecure client;
  client.setInsecure();

  HTTPClient https;
  https.begin(client, SYNC_URL);

  int code = https.GET();

  Serial.print("Sync HTTP Code: ");
  Serial.println(code);

  if (code == 200) {

    String response = https.getString();

    int start = response.indexOf(":\"") + 2;
    int end = response.indexOf("\"", start);

    if (start > 1 && end > start) {

      previousHash = response.substring(start, end);

      Serial.println("🔄 Synced previousHash:");
      Serial.println(previousHash);
    }
  }

  https.end();
}

/* ================= SEND EVENT ================= */

void sendEvent(String eventType, String event, String hash, String sig) {

  WiFiClientSecure client;
  client.setInsecure();

  HTTPClient https;
  https.begin(client, EVENT_URL);
  https.addHeader("Content-Type", "application/json");

  String payload =
      "{"
      "\"device_id\":\"" + String(DEVICE_ID) + "\","
      "\"event\":\"" + event + "\","
      "\"type\":\"" + eventType + "\","
      "\"hash\":\"" + hash + "\","
      "\"signature\":\"" + sig + "\""
      "}";

  Serial.println("------------------------------------------------");
  Serial.println("📤 Sending Event");
  Serial.println(event);
  Serial.println(eventType);

  Serial.print("Hash: ");
  Serial.println(hash);

  Serial.print("Prev: ");
  Serial.println(previousHash);

  int code = https.POST(payload);

  Serial.print("🌐 HTTP Status: ");
  Serial.println(code);

  if (code == 200) {

    String response = https.getString();

    Serial.println("📩 Backend Response:");
    Serial.println(response);

    if (response.indexOf("\"accepted\":true") != -1) {

      previousHash = hash;

      // Persist hash to NVS (survive reboot)
      prefs.begin("device", false);
      prefs.putString("prevhash", previousHash);
      prefs.end();

      Serial.println("✅ Chain advanced");
    }

    if (response.indexOf("eth_tx") != -1) {
      Serial.println("⛓ Blockchain anchor detected");
    }

  }

  https.end();
}

/* ================= EVENT WRAPPER ================= */

void emitEvent(String type, String event) {

  Serial.println("=================================");
  Serial.print("EVENT TYPE: ");
  Serial.println(type);

  Serial.print("EVENT: ");
  Serial.println(event);

  Serial.println("=================================");

  // Create hash chain and send to server
  String chained = event + "|PREV=" + previousHash;
  String hash = sha256(chained);
  String sig = signHash(hash);

  sendEvent(type, event, hash, sig);
}

/* ================= SETUP ================= */

void setup() {

  Serial.begin(115200);
  delay(1500);

  /* ================= NVS WIPE COMMAND ================= */
  
  Serial.println("\n========================================");
  Serial.println("Send 'WIPE' to erase NVS (5 sec window)");
  Serial.println("========================================\n");
  
  unsigned long startTime = millis();
  String command = "";
  
  while (millis() - startTime < 5000) {
    
    if (Serial.available()) {
      command = Serial.readStringUntil('\n');
      command.trim();
      command.toUpperCase();
      
      if (command == "WIPE") {
        Serial.println("\n🔥 WIPING NVS...");
        
        nvs_flash_erase();
        nvs_flash_init();
        
        Serial.println("✅ NVS ERASED!");
        Serial.println("\n⚠ REBOOTING IN 3 SECONDS...\n");
        
        delay(3000);
        ESP.restart();
      }
    }
    
    // Visual countdown
    if ((millis() - startTime) % 1000 == 0) {
      Serial.print(".");
    }
  }
  
  Serial.println("\n\n✅ Normal boot continuing...\n");
  Serial.println("Initializing System...");

  // Initialize I2C for RTC and MPU
  Wire.begin(23, 22);

  // Initialize RTC
  if (rtc.begin()) {
    rtcAvailable = true;
    Serial.println("DS3231 OK");
  }
  else {
    Serial.println("DS3231 NOT DETECTED");
  }

  // Initialize MPU6050
  Wire.beginTransmission(MPU_ADDR);
  Wire.write(0x6B);
  Wire.write(0);
  Wire.endTransmission(true);

  Serial.println("MPU6050 Ready");

  // Initialize DHT
  dht.begin();

  // Initialize digital pins
  pinMode(LDR_PIN, INPUT_PULLUP);
  pinMode(IMPACT_PIN, INPUT_PULLUP);
  pinMode(REED_PIN, INPUT_PULLUP);

  // Initialize crypto
  initCrypto();

  // Setup URLs
  REGISTER_URL = String(BASE_URL) + "/register-device";
  EVENT_URL    = String(BASE_URL) + "/event";
  SYNC_URL     = String(BASE_URL) + "/sync?device_id=" + DEVICE_ID;

  // Connect to WiFi
  WiFi.begin(ssid, password);

  Serial.print("Connecting to WiFi");
  while (WiFi.status() != WL_CONNECTED) {
    delay(200);
    Serial.print(".");
  }

  Serial.println("\n✅ WiFi connected");

  // Handle device registration
  bool keyLoaded = loadPrivateKey();

  prefs.begin("device", true);
  bool registered = prefs.getBool("registered", false);
  prefs.end();

  if (!keyLoaded) {
    generateKeypair();
  }
  else if (!registered) {

    unsigned char pub_buf[800];
    memset(pub_buf, 0, sizeof(pub_buf));

    mbedtls_pk_write_pubkey_pem(&pk, pub_buf, sizeof(pub_buf));

    registerDevice(String((char*)pub_buf));
  }

  delay(1000);

  // Load previous hash from NVS (restore chain after reboot)
  prefs.begin("device", true);
  previousHash = prefs.getString("prevhash", "GENESIS");
  prefs.end();

  Serial.print("📦 Loaded previousHash: ");
  Serial.println(previousHash);

  syncPreviousHash();

  Serial.println("System Ready");
}

/* ================= LOOP ================= */

void loop() {

  /* ================= WiFi Reconnection ================= */

  if (WiFi.status() != WL_CONNECTED) {

    Serial.println("⚠ WiFi disconnected. Reconnecting...");

    WiFi.disconnect();
    WiFi.begin(ssid, password);

    delay(2000);

    return;
  }

  /* ================= Main Loop ================= */

  String ts = getTimestamp();

  /* ================= DHT (Temperature & Humidity) ================= */

  float temp = dht.readTemperature();
  float hum = dht.readHumidity();

  if (!isnan(temp) && !isnan(hum)) {

    Serial.print("Temp: ");
    Serial.print(temp);
    Serial.print(" | Hum: ");
    Serial.println(hum);

    /* ---- TEMP VIOLATION ---- */

    if (temp > TEMP_MAX || temp < TEMP_MIN) {

      bool first = (lastViolationTemp >= TEMP_MIN &&
                    lastViolationTemp <= TEMP_MAX);

      bool delta = abs(temp - lastViolationTemp) >= TEMP_DELTA;

      if (first || delta) {

        lastViolationTemp = temp;

        String event =
          "TEMP_VIOLATION|" +
          String(DEVICE_ID) +
          "|TEMP=" + String(temp, 1) +
          "|TS=" + ts;

        emitEvent("EVENT_VIOLATION", event);
      }
    }
    else {
      lastViolationTemp = temp;
    }

    /* ---- HUM VIOLATION ---- */

    if (hum > HUM_MAX || hum < HUM_MIN) {

      bool first = (lastViolationHum >= HUM_MIN &&
                    lastViolationHum <= HUM_MAX);

      bool delta = abs(hum - lastViolationHum) >= HUM_DELTA;

      if (first || delta) {

        lastViolationHum = hum;

        String event =
          "HUM_VIOLATION|" +
          String(DEVICE_ID) +
          "|HUM=" + String(hum, 1) +
          "|TS=" + ts;

        emitEvent("EVENT_VIOLATION", event);
      }
    }
    else {
      lastViolationHum = hum;
    }
  }

  /* ================= LDR (Light Detection) ================= */

  bool light = digitalRead(LDR_PIN) == LOW;

  if (light && !ldrViolationActive) {

    ldrViolationActive = true;

    emitEvent(
      "EVENT_VIOLATION",
      "LIGHT_TAMPER|" +
      String(DEVICE_ID) +
      "|TS=" + ts
    );
  }

  if (!light)
    ldrViolationActive = false;

  /* ================= REED SWITCH (Seal Detection) ================= */

  bool reedOpen = digitalRead(REED_PIN) == HIGH;

  if (reedOpen && !reedViolationActive) {

    reedViolationActive = true;

    emitEvent(
      "EVENT_VIOLATION",
      "SEAL_OPEN|" +
      String(DEVICE_ID) +
      "|TS=" + ts
    );
  }

  if (!reedOpen)
    reedViolationActive = false;

  /* ================= IMPACT SENSOR ================= */

  bool impact = digitalRead(IMPACT_PIN) == HIGH;

  if (impact && !impactViolationActive) {

    impactViolationActive = true;

    emitEvent(
      "EVENT_VIOLATION",
      "IMPACT_EVENT|" +
      String(DEVICE_ID) +
      "|TS=" + ts
    );
  }

  if (!impact)
    impactViolationActive = false;

  /* ================= MPU6050 (Tilt & Shock) ================= */

  Wire.beginTransmission(MPU_ADDR);
  Wire.write(0x3B);
  Wire.endTransmission(false);
  Wire.requestFrom(MPU_ADDR, 6, true);

  ax = Wire.read() << 8 | Wire.read();
  ay = Wire.read() << 8 | Wire.read();
  az = Wire.read() << 8 | Wire.read();

  float ax_g = ax / 16384.0;
  float az_g = az / 16384.0;

  float tilt = atan2(ax_g, az_g) * 180 / PI;

  float accel = sqrt(ax * ax + ay * ay + az * az);

  Serial.print("Tilt: ");
  Serial.print(tilt);
  Serial.print(" | Accel: ");
  Serial.println(accel);

  /* ---- TILT WARNING ---- */

  if (abs(tilt) > TILT_WARN && abs(tilt) < TILT_VIOL) {

    bool delta = abs(tilt - lastViolationTilt) >= TILT_DELTA;

    if (delta) {

      lastViolationTilt = tilt;

      emitEvent(
        "EVENT_WARNING",
        "TILT_WARNING|" +
        String(DEVICE_ID) +
        "|TILT=" + String(tilt, 1) +
        "|TS=" + ts
      );
    }
  }

  /* ---- TILT VIOLATION ---- */

  if (abs(tilt) >= TILT_VIOL) {

    bool delta = abs(tilt - lastViolationTilt) >= TILT_DELTA;

    if (delta) {

      lastViolationTilt = tilt;

      emitEvent(
        "EVENT_VIOLATION",
        "TILT_VIOLATION|" +
        String(DEVICE_ID) +
        "|TILT=" + String(tilt, 1) +
        "|TS=" + ts
      );
    }
  }

  /* ---- SHOCK ---- */

  if (accel > SHOCK_THRESHOLD &&
      millis() - lastShockTime > 2000) {

    lastShockTime = millis();

    emitEvent(
      "EVENT_VIOLATION",
      "SHOCK_DETECTED|" +
      String(DEVICE_ID) +
      "|ACCEL=" + String(accel, 0) +
      "|TS=" + ts
    );
  }

  /* ================= HEARTBEAT ================= */

  if (millis() - lastHeartbeat > HEARTBEAT_INTERVAL) {

    lastHeartbeat = millis();

    emitEvent(
      "EVENT_LOG",
      "SENSOR_READING|" +
      String(DEVICE_ID) +
      "|TEMP=" + String(temp, 1) +
      "|HUM=" + String(hum, 1) +
      "|TILT=" + String(tilt, 1) +
      "|TS=" + ts
    );
  }

  delay(2000);
}
