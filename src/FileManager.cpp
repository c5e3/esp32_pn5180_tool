#include "FileManager.h"

bool FileManager::begin() {
    if (!SPIFFS.begin(true)) {
        Serial.println("SPIFFS mount failed");
        return false;
    }
    return true;
}

String FileManager::dumpPath(const char *name) {
    return String("/dumps/") + name;
}

bool FileManager::saveDump(const char *name, const String &json) {
    String path = dumpPath(name);
    File f = SPIFFS.open(path, FILE_WRITE);
    if (!f) return false;
    f.print(json);
    f.close();
    return true;
}

String FileManager::loadDump(const char *name) {
    String path = dumpPath(name);
    File f = SPIFFS.open(path, FILE_READ);
    if (!f) return "";
    String content = f.readString();
    f.close();
    return content;
}

bool FileManager::deleteDump(const char *name) {
    return SPIFFS.remove(dumpPath(name));
}

bool FileManager::renameDump(const char *oldName, const char *newName) {
    String oldPath = dumpPath(oldName);
    String newPath = dumpPath(newName);
    if (!SPIFFS.exists(oldPath)) return false;
    if (SPIFFS.exists(newPath)) return false;
    return SPIFFS.rename(oldPath, newPath);
}

String FileManager::listDumps() {
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
            // Read just the "type" field from the dump JSON for the badge
            String path2 = String("/dumps/") + fname;
            File df = SPIFFS.open(path2, FILE_READ);
            if (df) {
                StaticJsonDocument<128> meta;
                DeserializationError merr = deserializeJson(meta, df);
                df.close();
                if (!merr && meta.containsKey("type")) {
                    obj["type"] = meta["type"].as<const char *>();
                }
            }
        }
        f = root.openNextFile();
    }

    String result;
    serializeJson(doc, result);
    return result;
}

size_t FileManager::usedBytes() {
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

String FileManager::tagToJson(ISO15693TagInfo *info, uint8_t *data) {
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

bool FileManager::jsonToTag(const String &json, ISO15693TagInfo *info,
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
String FileManager::uidToHex(uint8_t *uid) {
    char hex[17];
    for (int i = 7; i >= 0; i--) {
        snprintf(&hex[(7 - i) * 2], 3, "%02X", uid[i]);
    }
    hex[16] = '\0';
    return String(hex);
}

// Convert MSB-first hex string to LSB-first UID bytes
bool FileManager::hexToUid(const String &hex, uint8_t *uid) {
    if (hex.length() != 16) return false;
    for (int i = 0; i < 8; i++) {
        String byteStr = hex.substring(i * 2, i * 2 + 2);
        uid[7 - i] = (uint8_t)strtoul(byteStr.c_str(), NULL, 16);
    }
    return true;
}

String FileManager::bytesToHex(uint8_t *data, uint16_t len) {
    String hex;
    hex.reserve(len * 2);
    for (uint16_t i = 0; i < len; i++) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02X", data[i]);
        hex += buf;
    }
    return hex;
}

bool FileManager::hexToBytes(const String &hex, uint8_t *data, uint16_t maxLen) {
    if (hex.length() % 2 != 0) return false;
    uint16_t len = hex.length() / 2;
    if (len > maxLen) return false;
    for (uint16_t i = 0; i < len; i++) {
        String byteStr = hex.substring(i * 2, i * 2 + 2);
        data[i] = (uint8_t)strtoul(byteStr.c_str(), NULL, 16);
    }
    return true;
}

// ============================================================
// MIFARE ↔ JSON Conversion
// ============================================================

/*
  MIFARE dump format:
  {
    "type": "MFC1K",          // MFC1K | MFC4K | MFCMINI | MFUL | MFPLUS2K | MFPLUS4K
    "uid": "AABBCCDD",        // 4/7/10 bytes MSB-first hex
    "sak": "08",
    "atqa": "0400",
    "blockCount": 64,
    "blockSize": 16,          // 16 for MFC/MFPLUS, 4 for MFUL
    "data": "AABBCC...",      // all blocks concatenated
    "blockRead": "1111...0",  // 1=read, 0=failed, length=blockCount
    "keyUsed": "11110000..."  // per-sector: 0=none,1=keyA,2=keyB
  }
*/

String FileManager::mifareToJson(MifareTagInfo *info) {
    // Use DynamicJsonDocument for potentially large 4K dumps
    DynamicJsonDocument doc(6144);
    doc["type"] = PN5180MIFARE::typeString(info->type);

    // UID: MSB-first hex
    String uidStr;
    for (int i = 0; i < info->uidLen; i++) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02X", info->uid[i]);
        uidStr += buf;
    }
    doc["uid"] = uidStr;

    char sak[3];
    snprintf(sak, sizeof(sak), "%02X", info->sak);
    doc["sak"] = String(sak);

    char atqa[5];
    snprintf(atqa, sizeof(atqa), "%02X%02X", info->atqa[0], info->atqa[1]);
    doc["atqa"] = String(atqa);

    uint16_t bytesPerBlock = (info->type == MIFARE_ULTRALIGHT) ? 4 : 16;
    doc["blockCount"] = info->blockCount;
    doc["blockSize"]  = bytesPerBlock;

    // Data: all blocks concatenated
    uint16_t totalBytes = info->blockCount * bytesPerBlock;
    doc["data"] = bytesToHex(info->data, totalBytes);

    // blockRead bitmask string
    String br;
    br.reserve(info->blockCount + 1);
    for (uint16_t b = 0; b < info->blockCount; b++) {
        br += info->blockRead[b] ? '1' : '0';
    }
    doc["blockRead"] = br;

    // keyUsed per sector
    uint8_t ns = (info->type == MIFARE_ULTRALIGHT) ? 0 : PN5180MIFARE::totalSectors(info->type);
    // make totalSectors public — we call it via static in cpp
    String ku;
    for (uint8_t s = 0; s < ns; s++) {
        ku += (char)('0' + info->keyUsed[s]);
    }
    if (ku.length() > 0) doc["keyUsed"] = ku;

    String result;
    serializeJson(doc, result);
    return result;
}

bool FileManager::jsonToMifare(const String &json, MifareTagInfo *info) {
    DynamicJsonDocument doc(6144);
    DeserializationError err = deserializeJson(doc, json);
    if (err) return false;

    memset(info, 0, sizeof(MifareTagInfo));

    const char *typeStr = doc["type"] | "";
    if      (strcmp(typeStr, "MFC1K")    == 0) info->type = MIFARE_CLASSIC_1K;
    else if (strcmp(typeStr, "MFC4K")    == 0) info->type = MIFARE_CLASSIC_4K;
    else if (strcmp(typeStr, "MFCMINI")  == 0) info->type = MIFARE_CLASSIC_MINI;
    else if (strcmp(typeStr, "MFUL")     == 0) info->type = MIFARE_ULTRALIGHT;
    else if (strcmp(typeStr, "MFPLUS2K") == 0) info->type = MIFARE_PLUS_SL1_2K;
    else if (strcmp(typeStr, "MFPLUS4K") == 0) info->type = MIFARE_PLUS_SL1_4K;
    else return false;

    const char *uidStr = doc["uid"] | "";
    uint8_t uidLen = strlen(uidStr) / 2;
    if (uidLen < 4 || uidLen > 10) return false;
    for (uint8_t i = 0; i < uidLen; i++) {
        char h[3] = { uidStr[i*2], uidStr[i*2+1], 0 };
        info->uid[i] = (uint8_t)strtoul(h, NULL, 16);
    }
    info->uidLen = uidLen;

    const char *sakStr = doc["sak"] | "00";
    info->sak = (uint8_t)strtoul(sakStr, NULL, 16);

    const char *atqaStr = doc["atqa"] | "0000";
    char ah[3] = { atqaStr[0], atqaStr[1], 0 };
    info->atqa[0] = (uint8_t)strtoul(ah, NULL, 16);
    char ah2[3] = { atqaStr[2], atqaStr[3], 0 };
    info->atqa[1] = (uint8_t)strtoul(ah2, NULL, 16);

    info->blockCount  = doc["blockCount"] | 0;
    uint16_t bytesPerBlock = doc["blockSize"] | 16;

    const char *dataStr = doc["data"] | "";
    uint16_t totalBytes = info->blockCount * bytesPerBlock;
    if (totalBytes > MAX_MIFARE_DATA) return false;
    hexToBytes(String(dataStr), info->data, MAX_MIFARE_DATA);

    const char *brStr = doc["blockRead"] | "";
    for (uint16_t b = 0; b < info->blockCount && brStr[b]; b++) {
        info->blockRead[b] = (brStr[b] == '1');
    }

    const char *kuStr = doc["keyUsed"] | "";
    for (uint8_t s = 0; s < 40 && kuStr[s]; s++) {
        info->keyUsed[s] = (uint8_t)(kuStr[s] - '0');
    }

    info->valid = true;
    return true;
}

