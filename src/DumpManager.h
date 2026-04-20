#ifndef DUMP_MANAGER_H
#define DUMP_MANAGER_H

#include <Arduino.h>
#include <SPIFFS.h>
#include <ArduinoJson.h>
#include "PN5180ISO15693.h"

class DumpManager {
public:
    bool begin();
    bool saveDump(const char *name, const String &json);
    String loadDump(const char *name);
    bool deleteDump(const char *name);
    bool renameDump(const char *oldName, const char *newName);
    String listDumps(); // Returns JSON array: ["name1","name2",...]

    // Conversion helpers
    static String tagToJson(ISO15693TagInfo *info, uint8_t *data);
    static bool jsonToTag(const String &json, ISO15693TagInfo *info, uint8_t *data, uint16_t maxDataLen);

    // UID display helpers (convert between LSB-first bytes and MSB-first hex string)
    static String uidToHex(uint8_t *uid);       // LSB-first → "E004015012345678"
    static bool hexToUid(const String &hex, uint8_t *uid); // "E004015012345678" → LSB-first
    static String bytesToHex(uint8_t *data, uint16_t len);
    static bool hexToBytes(const String &hex, uint8_t *data, uint16_t maxLen);

private:
    String dumpPath(const char *name);
};

#endif
