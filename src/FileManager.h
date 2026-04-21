#ifndef FILE_MANAGER_H
#define FILE_MANAGER_H

#include <Arduino.h>
#include <SPIFFS.h>
#include <ArduinoJson.h>
#include "PN5180ISO15693.h"
#include "PN5180MIFARE.h"

class FileManager {
public:
    bool begin();
    bool saveDump(const char *name, const String &json);
    String loadDump(const char *name);
    bool deleteDump(const char *name);
    bool renameDump(const char *oldName, const char *newName);
    String listDumps(); // Returns JSON array: [{"name":"x","size":123,"type":"ISO15693"},...]

    // Generic folder operations (folder: "dumps" or "dicts")
    String listFiles(const char *folder);   // JSON array: [{"name":"x","size":123[,"type":"..."][,"enabled":true]}]
    bool   deleteFile(const char *folder, const char *name);
    String loadFile(const char *folder, const char *name);

    // Dictionary management — files in /dicts/ named <protocol>_<name>.txt
    // Enable/disable + order persisted in /dicts/config.json (hidden from listings).
    static constexpr const char *DICT_PROTO_MFC = "mfc";   // MIFARE Classic & Plus SL1
    bool   isDictEnabled(const char *filename);            // default true if not in config
    bool   setDictEnabled(const char *filename, bool enabled);
    bool   setDictOrder(const String &jsonArray);          // body: ["a.txt","b.txt",...]
    // Accumulate keys from every enabled <protocol>_*.txt file in the configured
    // order. Returns total key count loaded; stops once `maxKeys` is reached.
    int    loadDictKeys(const char *protocol, uint8_t (*keys)[6], int maxKeys);

    size_t usedBytes();  // Sum of all file sizes across /dumps and /dicts

    // ISO 15693 tag JSON helpers
    static String tagToJson(ISO15693TagInfo *info, uint8_t *data);
    static bool jsonToTag(const String &json, ISO15693TagInfo *info, uint8_t *data, uint16_t maxDataLen);

    // MIFARE tag JSON helpers
    static String mifareToJson(MifareTagInfo *info);
    static bool jsonToMifare(const String &json, MifareTagInfo *info);

    // UID display helpers (convert between LSB-first bytes and MSB-first hex string)
    static String uidToHex(uint8_t *uid);       // LSB-first → "E004015012345678"
    static bool hexToUid(const String &hex, uint8_t *uid); // "E004015012345678" → LSB-first
    static String bytesToHex(uint8_t *data, uint16_t len);
    static bool hexToBytes(const String &hex, uint8_t *data, uint16_t maxLen);

private:
    String dumpPath(const char *name);
};

#endif
