#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <ArduinoJson.h>

#include "config.h"
#include "PN5180ISO15693.h"
#include "DumpManager.h"
#include "web_ui.h"

PN5180ISO15693 nfc(PN5180_NSS, PN5180_BUSY, PN5180_RST);
DumpManager dumps;
WebServer server(80);

// Shared data buffer for tag operations
static uint8_t dataBuffer[ISO15693_MAX_DATA_SIZE];

// Emulation state
static ISO15693TagInfo emuTagInfo;
static uint8_t emuDataBuffer[ISO15693_MAX_DATA_SIZE];

// Guard macro: reject NFC operations while emulating
#define GUARD_EMULATION() do { \
    if (nfc.emuState.active) { \
        server.send(200, "application/json", \
            "{\"status\":\"error\",\"message\":\"Stop emulation first\"}"); \
        return; \
    } } while(0)

// ============================================================
// API Handlers
// ============================================================

void handleRoot() {
    server.send_P(200, "text/html", INDEX_HTML);
}

// GET /api/read — full read (inventory + sysinfo + all blocks)
void handleRead() {
    GUARD_EMULATION();
    ISO15693TagInfo info;
    memset(&info, 0, sizeof(info));
    memset(dataBuffer, 0, sizeof(dataBuffer));

    if (!nfc.readTag(&info, dataBuffer, sizeof(dataBuffer))) {
        server.send(200, "application/json",
            "{\"status\":\"error\",\"message\":\"Failed to read tag\"}");
        return;
    }

    String json = DumpManager::tagToJson(&info, dataBuffer);

    // Wrap in API response
    StaticJsonDocument<64> wrapper;
    wrapper["status"] = "ok";
    String response;
    serializeJson(wrapper, response);
    // Insert data object: {"status":"ok","data":{...}}
    response = "{\"status\":\"ok\",\"data\":" + json + "}";

    server.send(200, "application/json", response);
}

// POST /api/write — write all blocks, body = {uid, blockSize, blockCount, data}
void handleWrite() {
    GUARD_EMULATION();
    if (!server.hasArg("plain")) {
        server.send(200, "application/json",
            "{\"status\":\"error\",\"message\":\"No body\"}");
        return;
    }

    StaticJsonDocument<4096> doc;
    DeserializationError err = deserializeJson(doc, server.arg("plain"));
    if (err) {
        server.send(200, "application/json",
            "{\"status\":\"error\",\"message\":\"Invalid JSON\"}");
        return;
    }

    const char *uidStr = doc["uid"];
    uint8_t uid[8];
    if (!uidStr || !DumpManager::hexToUid(String(uidStr), uid)) {
        server.send(200, "application/json",
            "{\"status\":\"error\",\"message\":\"Invalid UID\"}");
        return;
    }

    uint8_t blockSize = doc["blockSize"] | 4;
    uint8_t blockCount = doc["blockCount"] | 0;
    const char *dataStr = doc["data"];

    if (!dataStr || blockCount == 0) {
        server.send(200, "application/json",
            "{\"status\":\"error\",\"message\":\"No data\"}");
        return;
    }

    memset(dataBuffer, 0, sizeof(dataBuffer));
    if (!DumpManager::hexToBytes(String(dataStr), dataBuffer, sizeof(dataBuffer))) {
        server.send(200, "application/json",
            "{\"status\":\"error\",\"message\":\"Invalid hex data\"}");
        return;
    }

    uint8_t writtenCount = 0;
    uint8_t actualBlockCount = 0;
    if (!nfc.writeTag(blockCount, blockSize, dataBuffer,
                      &writtenCount, &actualBlockCount)) {
        String msg = "Write failed at block " + String(writtenCount)
                   + " (tag has " + String(actualBlockCount) + " blocks)";
        server.send(200, "application/json",
            "{\"status\":\"error\",\"message\":\"" + msg + "\"}");
        return;
    }

    String resp = "{\"status\":\"ok\",\"written\":" + String(writtenCount)
                + ",\"tagBlocks\":" + String(actualBlockCount) + "}";
    server.send(200, "application/json", resp);
}

// POST /api/csetuid — set UID, body = {uid, version}
void handleCSetUID() {
    GUARD_EMULATION();
    if (!server.hasArg("plain")) {
        server.send(200, "application/json",
            "{\"status\":\"error\",\"message\":\"No body\"}");
        return;
    }

    StaticJsonDocument<256> doc;
    deserializeJson(doc, server.arg("plain"));

    const char *uidStr = doc["uid"];
    const char *ver = doc["version"];
    uint8_t uid[8];

    if (!uidStr || !DumpManager::hexToUid(String(uidStr), uid)) {
        server.send(200, "application/json",
            "{\"status\":\"error\",\"message\":\"Invalid UID\"}");
        return;
    }

    if (uid[7] != 0xE0) {
        server.send(200, "application/json",
            "{\"status\":\"error\",\"message\":\"UID must start with E0\"}");
        return;
    }

    bool ok;
    if (ver && strcmp(ver, "v2") == 0) {
        ok = nfc.setUID_v2(uid);
    } else {
        ok = nfc.setUID_v1(uid);
    }

    if (!ok) {
        server.send(200, "application/json",
            "{\"status\":\"error\",\"message\":\"Set UID failed\"}");
        return;
    }

    server.send(200, "application/json", "{\"status\":\"ok\"}");
}

// GET /api/dumps — list saved dumps
void handleListDumps() {
    String list = dumps.listDumps();
    server.send(200, "application/json",
        "{\"status\":\"ok\",\"dumps\":" + list + "}");
}

// GET /api/dump?name=xxx — get specific dump
void handleGetDump() {
    if (!server.hasArg("name")) {
        server.send(200, "application/json",
            "{\"status\":\"error\",\"message\":\"Missing name\"}");
        return;
    }
    String name = server.arg("name");
    String json = dumps.loadDump(name.c_str());
    if (json.isEmpty()) {
        server.send(200, "application/json",
            "{\"status\":\"error\",\"message\":\"Dump not found\"}");
        return;
    }
    server.send(200, "application/json",
        "{\"status\":\"ok\",\"data\":" + json + "}");
}

// POST /api/dump?name=xxx — save dump
void handleSaveDump() {
    if (!server.hasArg("name") || !server.hasArg("plain")) {
        server.send(200, "application/json",
            "{\"status\":\"error\",\"message\":\"Missing name or body\"}");
        return;
    }
    String name = server.arg("name");

    // Validate name: alphanumeric, underscore, dash only
    for (unsigned int i = 0; i < name.length(); i++) {
        char c = name.charAt(i);
        if (!isalnum(c) && c != '_' && c != '-') {
            server.send(200, "application/json",
                "{\"status\":\"error\",\"message\":\"Invalid name\"}");
            return;
        }
    }

    if (!dumps.saveDump(name.c_str(), server.arg("plain"))) {
        server.send(200, "application/json",
            "{\"status\":\"error\",\"message\":\"Save failed\"}");
        return;
    }
    server.send(200, "application/json", "{\"status\":\"ok\"}");
}

// DELETE /api/dump?name=xxx — delete dump
void handleDeleteDump() {
    if (!server.hasArg("name")) {
        server.send(200, "application/json",
            "{\"status\":\"error\",\"message\":\"Missing name\"}");
        return;
    }
    if (!dumps.deleteDump(server.arg("name").c_str())) {
        server.send(200, "application/json",
            "{\"status\":\"error\",\"message\":\"Delete failed\"}");
        return;
    }
    server.send(200, "application/json", "{\"status\":\"ok\"}");
}

// POST /api/dump/rename — rename dump, body = {oldName, newName}
void handleRenameDump() {
    if (!server.hasArg("plain")) {
        server.send(200, "application/json",
            "{\"status\":\"error\",\"message\":\"No body\"}");
        return;
    }
    StaticJsonDocument<256> doc;
    deserializeJson(doc, server.arg("plain"));
    const char *oldName = doc["oldName"];
    const char *newName = doc["newName"];
    if (!oldName || !newName) {
        server.send(200, "application/json",
            "{\"status\":\"error\",\"message\":\"Missing oldName or newName\"}");
        return;
    }
    // Validate new name
    String nn(newName);
    for (unsigned int i = 0; i < nn.length(); i++) {
        char c = nn.charAt(i);
        if (!isalnum(c) && c != '_' && c != '-') {
            server.send(200, "application/json",
                "{\"status\":\"error\",\"message\":\"Invalid name\"}");
            return;
        }
    }
    if (!dumps.renameDump(oldName, newName)) {
        server.send(200, "application/json",
            "{\"status\":\"error\",\"message\":\"Rename failed\"}");
        return;
    }
    server.send(200, "application/json", "{\"status\":\"ok\"}");
}

// ============================================================
// Emulation API Handlers
// ============================================================

// POST /api/emulate/start — body = {name: "dumpName"}
void handleEmulateStart() {
    if (nfc.emuState.active) {
        server.send(200, "application/json",
            "{\"status\":\"error\",\"message\":\"Already emulating\"}");
        return;
    }
    if (!server.hasArg("plain")) {
        server.send(200, "application/json",
            "{\"status\":\"error\",\"message\":\"No body\"}");
        return;
    }
    StaticJsonDocument<256> doc;
    deserializeJson(doc, server.arg("plain"));
    const char *name = doc["name"];
    if (!name) {
        server.send(200, "application/json",
            "{\"status\":\"error\",\"message\":\"Missing dump name\"}");
        return;
    }

    // Load dump from SPIFFS
    String json = dumps.loadDump(name);
    if (json.isEmpty()) {
        server.send(200, "application/json",
            "{\"status\":\"error\",\"message\":\"Dump not found\"}");
        return;
    }

    memset(&emuTagInfo, 0, sizeof(emuTagInfo));
    memset(emuDataBuffer, 0, sizeof(emuDataBuffer));
    if (!DumpManager::jsonToTag(json, &emuTagInfo, emuDataBuffer, sizeof(emuDataBuffer))) {
        server.send(200, "application/json",
            "{\"status\":\"error\",\"message\":\"Invalid dump data\"}");
        return;
    }

    nfc.setupEmulation(&emuTagInfo, emuDataBuffer);
    server.send(200, "application/json", "{\"status\":\"ok\"}");
}

// POST /api/emulate/stop
void handleEmulateStop() {
    if (!nfc.emuState.active) {
        server.send(200, "application/json", "{\"status\":\"ok\"}");
        return;
    }
    nfc.teardownEmulation();
    server.send(200, "application/json", "{\"status\":\"ok\"}");
}

// GET /api/emulate/status
void handleEmulateStatus() {
    String json = "{\"active\":" + String(nfc.emuState.active ? "true" : "false")
                + ",\"fieldDetected\":" + String(nfc.emuState.fieldDetected ? "true" : "false")
                + ",\"cmdCount\":" + String(nfc.emuState.cmdCount) + "}";
    server.send(200, "application/json", json);
}

// ============================================================
// Setup & Loop
// ============================================================

void setup() {
    Serial.begin(115200);
    Serial.println("\n=== NFC Tool ===");

    // Init PN5180
    nfc.begin();
    Serial.println("PN5180 initialized");

    // Init SPIFFS
    dumps.begin();
    Serial.println("SPIFFS initialized");

    // Start WiFi
#if CFG_WIFI_MODE == CFG_WIFI_STA
    WiFi.mode(WIFI_STA);
    WiFi.begin(STA_SSID, STA_PASS);
    Serial.print("Connecting to ");
    Serial.print(STA_SSID);
    unsigned long startMs = millis();
    while (WiFi.status() != WL_CONNECTED && millis() - startMs < STA_CONNECT_TIMEOUT) {
        delay(500);
        Serial.print(".");
    }
    Serial.println();
    if (WiFi.status() == WL_CONNECTED) {
        Serial.print("Connected! IP: ");
        Serial.println(WiFi.localIP());
    } else {
        Serial.println("STA connect failed, falling back to AP mode");
        WiFi.disconnect();
        WiFi.mode(WIFI_AP);
        WiFi.softAP(AP_SSID, AP_PASS);
        Serial.print("AP IP: ");
        Serial.println(WiFi.softAPIP());
    }
#else
    WiFi.mode(WIFI_AP);
    WiFi.softAP(AP_SSID, AP_PASS);
    Serial.print("AP started: ");
    Serial.println(AP_SSID);
    Serial.print("IP: ");
    Serial.println(WiFi.softAPIP());
#endif

    // Register web server routes
    server.on("/", HTTP_GET, handleRoot);
    server.on("/api/read", HTTP_GET, handleRead);
    server.on("/api/write", HTTP_POST, handleWrite);
    server.on("/api/csetuid", HTTP_POST, handleCSetUID);
    server.on("/api/dumps", HTTP_GET, handleListDumps);
    server.on("/api/dump", HTTP_GET, handleGetDump);
    server.on("/api/dump", HTTP_POST, handleSaveDump);
    server.on("/api/dump", HTTP_DELETE, handleDeleteDump);
    server.on("/api/dump/rename", HTTP_POST, handleRenameDump);
    server.on("/api/emulate/start", HTTP_POST, handleEmulateStart);
    server.on("/api/emulate/stop", HTTP_POST, handleEmulateStop);
    server.on("/api/emulate/status", HTTP_GET, handleEmulateStatus);
    server.onNotFound([]() {
        server.send(404, "text/plain", "Not found");
    });

    server.begin();
    Serial.println("Web server started on port 80");
#if CFG_WIFI_MODE == CFG_WIFI_STA
    if (WiFi.status() == WL_CONNECTED) {
        Serial.print("Open http://");
        Serial.println(WiFi.localIP());
    } else {
        Serial.println("Connect to WiFi '" AP_SSID "' then open http://192.168.4.1");
    }
#else
    Serial.println("Connect to WiFi '" AP_SSID "' (password: " AP_PASS ")");
    Serial.println("Then open http://192.168.4.1");
#endif
}

void loop() {
    server.handleClient();
    if (nfc.emuState.active) {
        nfc.emulationLoop();
    }
}
