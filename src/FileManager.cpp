#include "FileManager.h"
#include "PN5180MIFARE.h"
#include <vector>
#include <algorithm>
#include <climits>

// /dicts/ filename convention:
//   <protocol>_<name>.txt        e.g. mfc_std.txt, mfc_ext.txt, mfc_transit.txt
// Anything in /dicts/ is treated as a dictionary except /dicts/config.json
// (the persistent enable/disable state), which is hidden from listings.
static bool dictFilenameMatches(const String &fname, const char *protocol) {
    String prefix = String(protocol) + "_";
    return fname.startsWith(prefix) && fname.endsWith(".txt");
}

static bool isDictListed(const String &fname) {
    // Hide only the config file; show every other entry.
    return fname != "config.json";
}

// Forward decls for dict config helpers (definitions live further down)
static bool readDictConfig(StaticJsonDocument<1024> &out);
static bool writeDictConfig(StaticJsonDocument<1024> &doc);
static int  dictOrderIndex(StaticJsonDocument<1024> &cfg, const char *name);

// Scan /dicts/ and append any files not yet present in cfg.order to the end
// (defaulting them to enabled). Mutates cfg in-place. Returns true if cfg
// was changed and the caller should persist it. Must be called BEFORE any
// other openNextFile()-based iteration of /dicts/.
static bool ensureDictsRegistered(StaticJsonDocument<1024> &cfg) {
    std::vector<String> present;
    File root = SPIFFS.open("/dicts");
    if (root && root.isDirectory()) {
        for (File f = root.openNextFile(); f; f = root.openNextFile()) {
            String fname = f.name();
            int slash = fname.lastIndexOf('/');
            if (slash >= 0) fname = fname.substring(slash + 1);
            if (fname.length() == 0 || fname.charAt(0) == '.') continue;
            if (!isDictListed(fname)) continue;
            present.push_back(fname);
        }
    }

    if (!cfg.containsKey("order")) cfg.createNestedArray("order");
    JsonArray order = cfg["order"].as<JsonArray>();
    bool changed = false;
    for (const String &name : present) {
        if (dictOrderIndex(cfg, name.c_str()) == INT_MAX) {
            order.add(name);
            changed = true;
        }
    }
    return changed;
}

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
    return listFiles("dumps");
}

String FileManager::listFiles(const char *folder) {
    StaticJsonDocument<2048> doc;
    JsonArray arr = doc.to<JsonArray>();

    String basePath = String("/") + folder;
    bool isDumps = (strcmp(folder, "dumps") == 0);
    bool isDicts = (strcmp(folder, "dicts") == 0);

    File root = SPIFFS.open(basePath);
    if (!root || !root.isDirectory()) {
        // Touch a hidden init file so the prefix exists for future openNextFile calls
        File tmp = SPIFFS.open(basePath + "/.init", FILE_WRITE);
        if (tmp) { tmp.close(); SPIFFS.remove(basePath + "/.init"); }
        return "[]";
    }

    // For dicts, gather names first so we can sort them by configured order.
    // Auto-register any new files (append to order, default-enabled) so the
    // UI ordering survives reboots and the read path picks them up.
    StaticJsonDocument<1024> cfg;
    if (isDicts) {
        readDictConfig(cfg);
        if (ensureDictsRegistered(cfg)) writeDictConfig(cfg);
    }
    std::vector<String> dictNames;

    File f = root.openNextFile();
    while (f) {
        String fname = f.name();
        size_t fsize = f.size();
        int lastSlash = fname.lastIndexOf('/');
        if (lastSlash >= 0) fname = fname.substring(lastSlash + 1);
        if (fname.length() > 0 && fname.charAt(0) != '.') {
            // For dicts: hide config.json; everything else is shown as a dict.
            bool include = isDicts ? isDictListed(fname) : true;
            if (include) {
                if (isDicts) {
                    dictNames.push_back(fname);
                } else {
                    JsonObject obj = arr.createNestedObject();
                    obj["name"] = fname;
                    obj["size"] = fsize;
                    if (isDumps) {
                        String path2 = basePath + "/" + fname;
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
                }
            }
        }
        f = root.openNextFile();
    }

    if (isDicts) {
        std::stable_sort(dictNames.begin(), dictNames.end(), [&cfg](const String &a, const String &b) {
            int ia = dictOrderIndex(cfg, a.c_str());
            int ib = dictOrderIndex(cfg, b.c_str());
            if (ia != ib) return ia < ib;
            return strcmp(a.c_str(), b.c_str()) < 0;
        });
        for (const String &name : dictNames) {
            String path2 = basePath + "/" + name;
            File df = SPIFFS.open(path2, FILE_READ);
            size_t sz = df ? df.size() : 0;
            if (df) df.close();
            JsonObject obj = arr.createNestedObject();
            obj["name"]    = name;
            obj["size"]    = sz;
            obj["enabled"] = isDictEnabled(name.c_str());
        }
    }

    String result;
    serializeJson(doc, result);
    return result;
}

bool FileManager::deleteFile(const char *folder, const char *name) {
    return SPIFFS.remove(String("/") + folder + "/" + name);
}

String FileManager::loadFile(const char *folder, const char *name) {
    String path = String("/") + folder + "/" + name;
    File f = SPIFFS.open(path, FILE_READ);
    if (!f) return "";
    String content = f.readString();
    f.close();
    return content;
}

// ============================================================
// Dictionary management — /dicts/config.json
// ============================================================
//
// Format:
//   { "disabled": ["mfc_ext.txt", ...],
//     "order":    ["mfc_std.txt", "mfc_ext.txt", ...] }
//
// Files default to enabled when absent from `disabled`. Files not present in
// `order` are appended in the order returned by SPIFFS. The config file is
// hidden from listFiles("dicts") so users can't accidentally delete it.

// Read the entire config.json into `out`. Returns false if missing/invalid.
static bool readDictConfig(StaticJsonDocument<1024> &out) {
    File f = SPIFFS.open("/dicts/config.json", FILE_READ);
    if (!f) return false;
    DeserializationError err = deserializeJson(out, f);
    f.close();
    return !err;
}

static bool writeDictConfig(StaticJsonDocument<1024> &doc) {
    File w = SPIFFS.open("/dicts/config.json", FILE_WRITE);
    if (!w) return false;
    serializeJson(doc, w);
    w.close();
    return true;
}

bool FileManager::isDictEnabled(const char *filename) {
    StaticJsonDocument<1024> doc;
    if (!readDictConfig(doc)) return true;
    JsonArray arr = doc["disabled"].as<JsonArray>();
    for (JsonVariant v : arr) {
        const char *s = v.as<const char *>();
        if (s && strcmp(s, filename) == 0) return false;
    }
    return true;
}

bool FileManager::setDictEnabled(const char *filename, bool enabled) {
    StaticJsonDocument<1024> doc;
    readDictConfig(doc);  // ok if missing
    if (!doc.containsKey("disabled")) doc.createNestedArray("disabled");
    JsonArray arr = doc["disabled"].as<JsonArray>();

    for (size_t i = 0; i < arr.size(); ) {
        const char *s = arr[i].as<const char *>();
        if (s && strcmp(s, filename) == 0) { arr.remove(i); } else { i++; }
    }
    if (!enabled) arr.add(filename);
    return writeDictConfig(doc);
}

bool FileManager::setDictOrder(const String &jsonArray) {
    StaticJsonDocument<1024> incoming;
    if (deserializeJson(incoming, jsonArray)) return false;
    if (!incoming.is<JsonArray>()) return false;

    StaticJsonDocument<1024> doc;
    readDictConfig(doc);
    doc.remove("order");
    JsonArray dst = doc.createNestedArray("order");
    for (JsonVariant v : incoming.as<JsonArray>()) {
        const char *s = v.as<const char *>();
        if (s && s[0] && strcmp(s, "config.json") != 0) dst.add(s);
    }
    return writeDictConfig(doc);
}

// Returns the index of `name` in the configured order, or INT_MAX if absent.
static int dictOrderIndex(StaticJsonDocument<1024> &cfg, const char *name) {
    JsonArray arr = cfg["order"].as<JsonArray>();
    int i = 0;
    for (JsonVariant v : arr) {
        const char *s = v.as<const char *>();
        if (s && strcmp(s, name) == 0) return i;
        i++;
    }
    return INT_MAX;
}

// Check enabled state against an already-loaded config doc.
// Use this when iterating /dicts/ — calling isDictEnabled() (which opens
// /dicts/config.json) inside an openNextFile() loop corrupts SPIFFS
// directory iteration on ESP32.
static bool dictEnabledIn(StaticJsonDocument<1024> &cfg, const char *name) {
    JsonArray arr = cfg["disabled"].as<JsonArray>();
    for (JsonVariant v : arr) {
        const char *s = v.as<const char *>();
        if (s && strcmp(s, name) == 0) return false;
    }
    return true;
}

int FileManager::loadDictKeys(const char *protocol, uint8_t (*keys)[6], int maxKeys) {
    StaticJsonDocument<1024> cfg;
    readDictConfig(cfg);
    if (ensureDictsRegistered(cfg)) writeDictConfig(cfg);

    // Collect matching filenames first (no other file ops during iteration —
    // SPIFFS on ESP32 corrupts openNextFile() state if another file is opened
    // mid-loop). Filter enabled/disabled against the in-memory cfg.
    std::vector<String> names;
    File root = SPIFFS.open("/dicts");
    if (root && root.isDirectory()) {
        for (File f = root.openNextFile(); f; f = root.openNextFile()) {
            String fname = f.name();
            int slash = fname.lastIndexOf('/');
            if (slash >= 0) fname = fname.substring(slash + 1);
            if (dictFilenameMatches(fname, protocol) && dictEnabledIn(cfg, fname.c_str())) {
                names.push_back(fname);
            }
        }
    }
    std::stable_sort(names.begin(), names.end(), [&cfg](const String &a, const String &b) {
        int ia = dictOrderIndex(cfg, a.c_str());
        int ib = dictOrderIndex(cfg, b.c_str());
        if (ia != ib) return ia < ib;
        return strcmp(a.c_str(), b.c_str()) < 0;
    });

    int total = 0;
    for (const String &name : names) {
        if (total >= maxKeys) break;
        String path = String("/dicts/") + name;
        int loaded = PN5180MIFARE::loadKeysFromFile(path.c_str(), keys + total, maxKeys - total);
        if (loaded > 0) total += loaded;
    }
    return total;
}

size_t FileManager::usedBytes() {
    size_t total = 0;
    const char *folders[] = {"dumps", "dicts"};
    for (auto folder : folders) {
        File root = SPIFFS.open(String("/") + folder);
        if (!root || !root.isDirectory()) continue;
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

