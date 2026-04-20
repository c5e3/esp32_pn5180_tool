#include "DumpManager.h"

bool DumpManager::begin() {
    if (!SPIFFS.begin(true)) {
        Serial.println("SPIFFS mount failed");
        return false;
    }
    return true;
}

String DumpManager::dumpPath(const char *name) {
    return String("/dumps/") + name;
}

bool DumpManager::saveDump(const char *name, const String &json) {
    String path = dumpPath(name);
    File f = SPIFFS.open(path, FILE_WRITE);
    if (!f) return false;
    f.print(json);
    f.close();
    return true;
}

String DumpManager::loadDump(const char *name) {
    String path = dumpPath(name);
    File f = SPIFFS.open(path, FILE_READ);
    if (!f) return "";
    String content = f.readString();
    f.close();
    return content;
}

bool DumpManager::deleteDump(const char *name) {
    return SPIFFS.remove(dumpPath(name));
}

bool DumpManager::renameDump(const char *oldName, const char *newName) {
    String oldPath = dumpPath(oldName);
    String newPath = dumpPath(newName);
    if (!SPIFFS.exists(oldPath)) return false;
    if (SPIFFS.exists(newPath)) return false;
    return SPIFFS.rename(oldPath, newPath);
}

String DumpManager::listDumps() {
    StaticJsonDocument<2048> doc;
    JsonArray arr = doc.to<JsonArray>();

    File root = SPIFFS.open("/dumps");
    if (!root || !root.isDirectory()) {
        // Create the directory by writing a temp file
        File tmp = SPIFFS.open("/dumps/.init", FILE_WRITE);
        if (tmp) { tmp.close(); SPIFFS.remove("/dumps/.init"); }
        return "[]";
    }

    File f = root.openNextFile();
    while (f) {
        String fname = f.name();
        size_t fsize = f.size();
        // Strip path prefix
        int lastSlash = fname.lastIndexOf('/');
        if (lastSlash >= 0) fname = fname.substring(lastSlash + 1);
        // Skip hidden/init files
        if (fname.length() > 0 && fname.charAt(0) != '.') {
            JsonObject obj = arr.createNestedObject();
            obj["name"] = fname;
            obj["size"] = fsize;
        }
        f = root.openNextFile();
    }

    String result;
    serializeJson(doc, result);
    return result;
}

size_t DumpManager::usedBytes() {
    size_t total = 0;
    File root = SPIFFS.open("/dumps");
    if (!root || !root.isDirectory()) return 0;
    File f = root.openNextFile();
    while (f) {
        String fname = f.name();
        int lastSlash = fname.lastIndexOf('/');
        if (lastSlash >= 0) fname = fname.substring(lastSlash + 1);
        if (fname.length() > 0 && fname.charAt(0) != '.') {
            total += f.size();
        }
        f = root.openNextFile();
    }
    return total;
}

// ============================================================
// Tag ↔ JSON Conversion
// ============================================================

/*
  Dump format (JSON):
  {
    "type": "ISO15693",
    "uid": "E004015012345678",
    "dsfid": "00",
    "afi": "00",
    "icRef": "00",
    "blockSize": 4,
    "blockCount": 28,
    "data": "AABBCCDD..."
  }
  - uid is MSB-first hex (conventional display order)
  - data is hex string of all blocks concatenated
*/

String DumpManager::tagToJson(ISO15693TagInfo *info, uint8_t *data) {
    StaticJsonDocument<4096> doc;
    doc["type"] = "ISO15693";
    doc["uid"] = uidToHex(info->uid);

    char hex3[3];
    snprintf(hex3, sizeof(hex3), "%02X", info->dsfid);
    doc["dsfid"] = String(hex3);
    snprintf(hex3, sizeof(hex3), "%02X", info->afi);
    doc["afi"] = String(hex3);
    snprintf(hex3, sizeof(hex3), "%02X", info->icRef);
    doc["icRef"] = String(hex3);

    doc["blockSize"] = info->blockSize;
    doc["blockCount"] = info->blockCount;

    uint16_t totalBytes = (uint16_t)info->blockCount * info->blockSize;
    doc["data"] = bytesToHex(data, totalBytes);

    String result;
    serializeJson(doc, result);
    return result;
}

bool DumpManager::jsonToTag(const String &json, ISO15693TagInfo *info,
                             uint8_t *data, uint16_t maxDataLen) {
    StaticJsonDocument<4096> doc;
    DeserializationError err = deserializeJson(doc, json);
    if (err) return false;

    const char *type = doc["type"];
    if (!type || strcmp(type, "ISO15693") != 0) return false;

    const char *uidStr = doc["uid"];
    if (!uidStr || !hexToUid(String(uidStr), info->uid)) return false;

    const char *dsfidStr = doc["dsfid"];
    info->dsfid = dsfidStr ? (uint8_t)strtoul(dsfidStr, NULL, 16) : 0;

    const char *afiStr = doc["afi"];
    info->afi = afiStr ? (uint8_t)strtoul(afiStr, NULL, 16) : 0;

    const char *icRefStr = doc["icRef"];
    info->icRef = icRefStr ? (uint8_t)strtoul(icRefStr, NULL, 16) : 0;

    info->blockSize = doc["blockSize"] | 4;
    info->blockCount = doc["blockCount"] | 0;

    uint16_t totalBytes = (uint16_t)info->blockCount * info->blockSize;
    if (totalBytes > maxDataLen) return false;

    const char *dataStr = doc["data"];
    if (!dataStr || !hexToBytes(String(dataStr), data, maxDataLen)) return false;

    info->valid = true;
    return true;
}

// ============================================================
// Hex Conversion Helpers
// ============================================================

// Convert UID from LSB-first bytes to MSB-first hex string
  // e.g., uid={0x5E,0x4D,0xC8,0xB1,0xF2,0xA3,0x07,0xE0} → "E007A3F2B1C84D5E"
String DumpManager::uidToHex(uint8_t *uid) {
    char hex[17];
    for (int i = 7; i >= 0; i--) {
        snprintf(&hex[(7 - i) * 2], 3, "%02X", uid[i]);
    }
    hex[16] = '\0';
    return String(hex);
}

// Convert MSB-first hex string to LSB-first UID bytes
bool DumpManager::hexToUid(const String &hex, uint8_t *uid) {
    if (hex.length() != 16) return false;
    for (int i = 0; i < 8; i++) {
        String byteStr = hex.substring(i * 2, i * 2 + 2);
        uid[7 - i] = (uint8_t)strtoul(byteStr.c_str(), NULL, 16);
    }
    return true;
}

String DumpManager::bytesToHex(uint8_t *data, uint16_t len) {
    String hex;
    hex.reserve(len * 2);
    for (uint16_t i = 0; i < len; i++) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02X", data[i]);
        hex += buf;
    }
    return hex;
}

bool DumpManager::hexToBytes(const String &hex, uint8_t *data, uint16_t maxLen) {
    if (hex.length() % 2 != 0) return false;
    uint16_t len = hex.length() / 2;
    if (len > maxLen) return false;
    for (uint16_t i = 0; i < len; i++) {
        String byteStr = hex.substring(i * 2, i * 2 + 2);
        data[i] = (uint8_t)strtoul(byteStr.c_str(), NULL, 16);
    }
    return true;
}
