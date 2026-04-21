#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <Update.h>
#include <ArduinoJson.h>

#include "config.h"
#include "PN5180ISO15693.h"
#include "PN5180MIFARE.h"
#include "FileManager.h"
#include "web_ui.h"

PN5180ISO15693 nfc(PN5180_NSS, PN5180_BUSY, PN5180_RST);
PN5180MIFARE   nfcMifare(PN5180_NSS, PN5180_BUSY, PN5180_RST);
FileManager files;
WebServer server(80);

// Emulation state
static ISO15693TagInfo emuTagInfo;
static uint8_t emuDataBuffer[ISO15693_MAX_DATA_SIZE];

// ============================================================
// Async read state (FreeRTOS task on Core 0)
// ============================================================
enum ReadState { RS_IDLE, RS_RUNNING, RS_DONE, RS_ERROR };
static volatile ReadState readState = RS_IDLE;
static MifareTagInfo   asyncMifareInfo;
static ISO15693TagInfo asyncISO15693Info;
static uint8_t         asyncDataBuffer[ISO15693_MAX_DATA_SIZE];
static String          asyncResultJson;
static volatile bool   nfcBusy = false;  // true while readTask runs on Core 0

// Read progress — updated by PN5180MIFARE during dictionary attack / block reads.
// Read by handleRead() to report status to the UI.
//   phase: 0=idle, 1=detect, 2=authenticating, 3=reading block
volatile int16_t g_progCurBlock    = -1;
volatile int16_t g_progTotalBlocks = 0;
volatile int8_t  g_progKeyType     = -1;   // 0=A, 1=B, -1=none
volatile uint8_t g_progPhase       = 0;
// Cooperative cancel flag — UI sets via POST /api/read/cancel; readTask and
// the long-running PN5180MIFARE loops check it between operations.
volatile bool    g_readCancel      = false;

// FreeRTOS binary semaphore signalled by PN5180 IRQ pin ISR.
// mfcAuthBlock() sleeps on this instead of SPI-polling every 1ms.
SemaphoreHandle_t g_irqSem = NULL;

void IRAM_ATTR pn5180IrqISR() {
    BaseType_t woken = pdFALSE;
    xSemaphoreGiveFromISR(g_irqSem, &woken);
    portYIELD_FROM_ISR(woken);
}

static void readTask(void *) {
    nfcBusy = true;
    g_readCancel      = false;
    g_progPhase       = 1;   // detecting
    g_progCurBlock    = -1;
    g_progTotalBlocks = 0;
    g_progKeyType     = -1;

    // =========================================================
    // PHASE 1 — Quick protocol detection, fastest response first.
    // No SPIFFS work yet: we want to know what we're dealing with
    // before paying the dictionary-load cost.
    //
    // Detection order (add new protocols here in speed order):
    //   1. ISO 14443A  — WUPA 7-bit short frame, card replies in ~2ms
    //   2. ISO 15693   — INVENTORY SOF, VCD-to-VICC round-trip ~10ms
    //   (future: ISO 18092/NFC-F ~5ms, ISO 14443B ~5ms)
    // =========================================================

    // --- 1. ISO 14443A / MIFARE (WUPA ~2ms) ---
    {
        nfcMifare.loadISO14443Config();
        nfcMifare.activateRF();
        delay(50);

        memset(&asyncMifareInfo, 0, sizeof(asyncMifareInfo));
        if (nfcMifare.detectTag(&asyncMifareInfo)) {
            Serial.printf("[read] ISO14443A: %s UID:", PN5180MIFARE::typeString(asyncMifareInfo.type));
            for (int i = 0; i < asyncMifareInfo.uidLen; i++) Serial.printf(" %02X", asyncMifareInfo.uid[i]);
            Serial.printf(" SAK=0x%02X\n", asyncMifareInfo.sak);
            g_progTotalBlocks = asyncMifareInfo.blockCount;

            // === PHASE 2: Full read for identified protocol ===
            bool ok = false;
            switch (asyncMifareInfo.type) {
                case MIFARE_CLASSIC_1K:
                case MIFARE_CLASSIC_4K:
                case MIFARE_CLASSIC_MINI:
                case MIFARE_PLUS_SL1_2K:
                case MIFARE_PLUS_SL1_4K: {
                    // Halt + RF-off so the ~100ms SPIFFS read doesn't time out
                    // the active card session, then load dicts and re-activate.
                    nfcMifare.haltTag();
                    nfcMifare.disableRF();

                    static uint8_t preKeys1[PN5180MIFARE::MAX_DICT_KEYS][6];
                    static uint8_t preKeys2[PN5180MIFARE::MAX_DICT_KEYS][6];
                    int n1 = files.loadDictKeys(FileManager::DICT_PROTO_MFC, preKeys1, PN5180MIFARE::MAX_DICT_KEYS);
                    int n2 = 0;  // reserved for a second keyset (e.g. Plus AES) when needed
                    Serial.printf("[read] MFC dict keys loaded: %d\n", n1);

                    if (nfcMifare.reActivateCard(&asyncMifareInfo)) {
                        ok = nfcMifare.mfcReadAllBlocks(&asyncMifareInfo, preKeys1, n1, preKeys2, n2);
                    } else {
                        Serial.println("[read] reActivate after dict load failed");
                    }
                    break;
                }
                case MIFARE_ULTRALIGHT:
                    ok = nfcMifare.mfulReadAllPages(&asyncMifareInfo);
                    break;
                default:
                    Serial.println("[read] Unsupported ISO14443A type");
                    break;
            }

            nfcMifare.haltTag();
            nfcMifare.disableRF();
            if (g_readCancel) {
                asyncResultJson = "{\"status\":\"error\",\"message\":\"Cancelled\"}";
                readState = RS_ERROR;
            } else {
                asyncResultJson = "{\"status\":\"ok\",\"data\":" + FileManager::mifareToJson(&asyncMifareInfo) + "}";
                readState = RS_DONE;
            }
            g_progPhase = 0;
            nfcBusy = false;
            vTaskDelete(NULL);
            return;
        }
        nfcMifare.disableRF();
    }

    // --- 2. ISO 15693 (INVENTORY ~10ms) ---
    //   nfc.readTag() handles RF activation, inventory, block reads, and RF off internally.
    {
        memset(&asyncISO15693Info, 0, sizeof(asyncISO15693Info));
        memset(asyncDataBuffer, 0, sizeof(asyncDataBuffer));
        if (nfc.readTag(&asyncISO15693Info, asyncDataBuffer, sizeof(asyncDataBuffer))) {
            asyncResultJson = "{\"status\":\"ok\",\"data\":" + FileManager::tagToJson(&asyncISO15693Info, asyncDataBuffer) + "}";
            readState = RS_DONE;
            g_progPhase = 0;
            nfcBusy = false;
            vTaskDelete(NULL);
            return;
        }
    }

    asyncResultJson = g_readCancel
        ? "{\"status\":\"error\",\"message\":\"Cancelled\"}"
        : "{\"status\":\"error\",\"message\":\"No tag found\"}";
    readState = RS_ERROR;
    g_progPhase = 0;
    nfcBusy = false;
    vTaskDelete(NULL);
}

// Guard macro: reject NFC operations while emulating
#define GUARD_EMULATION() do { \
    if (nfc.emuState.active) { \
        server.send(200, "application/json", \
            "{\"status\":\"error\",\"message\":\"Stop emulation first\"}"); \
        return; \
    } } while(0)

// Guard macro: reject NFC operations while async read is running
#define GUARD_NFC_BUSY() do { \
    if (nfcBusy) { \
        server.send(200, "application/json", \
            "{\"status\":\"error\",\"message\":\"NFC busy — read in progress\"}"); \
        return; \
    } } while(0)

// ============================================================
// API Handlers
// ============================================================

void handleRoot() {
    server.send_P(200, "text/html", INDEX_HTML);
}

// GET /api/read -- auto-detect ISO14443A (MIFARE) first, then ISO15693
// Returns 202 {"status":"running"} while in progress; poll until 200.
void handleRead() {
    GUARD_EMULATION();

    if (readState == RS_RUNNING) {
        String body = "{\"status\":\"running\""
                      ",\"phase\":"       + String((int)g_progPhase) +
                      ",\"block\":"       + String((int)g_progCurBlock) +
                      ",\"totalBlocks\":" + String((int)g_progTotalBlocks) +
                      ",\"keyType\":"     + String((int)g_progKeyType) + "}";
        server.send(202, "application/json", body);
        return;
    }
    if (readState == RS_DONE || readState == RS_ERROR) {
        String result = asyncResultJson;
        asyncResultJson = "";
        readState = RS_IDLE;
        server.send(200, "application/json", result);
        return;
    }

    // Kick off background read on Core 0 (Arduino loop runs on Core 1)
    readState = RS_RUNNING;
    xTaskCreatePinnedToCore(readTask, "readTask", 16384, NULL, 1, NULL, 0);
    server.send(202, "application/json", "{\"status\":\"running\"}");
}

// POST /api/read/cancel — request cooperative cancel of an in-flight read.
// readTask + PN5180MIFARE loops check g_readCancel between operations and
// abort early. Returns immediately; the polling /api/read call will then
// resolve to {status:"error",message:"Cancelled"}.
void handleReadCancel() {
    if (readState == RS_RUNNING) {
        g_readCancel = true;
        server.send(200, "application/json", "{\"status\":\"ok\"}");
    } else {
        server.send(200, "application/json",
            "{\"status\":\"error\",\"message\":\"No read in progress\"}");
    }
}

// POST /api/write — write all blocks, body = {type, uid, blockSize, blockCount, data, setUid?, writeTrailers?}
//   type:          "ISO15693" (default) | "MFC1K"|"MFC4K"|"MFCMINI"|"MFPLUS2K"|"MFPLUS4K" | "MFUL"
//   setUid:        for MFC, also write block 0 using auto-detected magic capability
//   writeTrailers: for MFC, also write sector trailers (DANGEROUS — can brick sector)
void handleWrite() {
    GUARD_EMULATION();
    GUARD_NFC_BUSY();
    if (!server.hasArg("plain")) {
        server.send(200, "application/json",
            "{\"status\":\"error\",\"message\":\"No body\"}");
        return;
    }

    DynamicJsonDocument doc(12288);
    DeserializationError err = deserializeJson(doc, server.arg("plain"));
    if (err) {
        server.send(200, "application/json",
            "{\"status\":\"error\",\"message\":\"Invalid JSON\"}");
        return;
    }

    const char *typeStr   = doc["type"]   | "ISO15693";
    const char *uidStr    = doc["uid"]    | "";
    uint8_t blockSize     = doc["blockSize"]  | 4;
    uint16_t blockCount   = doc["blockCount"] | 0;
    const char *dataStr   = doc["data"];
    bool   setUid         = doc["setUid"]        | false;
    bool   writeTrailers  = doc["writeTrailers"] | false;

    if (!dataStr || blockCount == 0) {
        server.send(200, "application/json",
            "{\"status\":\"error\",\"message\":\"No data\"}");
        return;
    }

    memset(asyncDataBuffer, 0, sizeof(asyncDataBuffer));
    if (!FileManager::hexToBytes(String(dataStr), asyncDataBuffer, sizeof(asyncDataBuffer))) {
        server.send(200, "application/json",
            "{\"status\":\"error\",\"message\":\"Invalid hex data\"}");
        return;
    }

    // ── MIFARE Classic / Plus / Ultralight write path ─────────────────────
    bool isMFC  = (strncmp(typeStr, "MFC",     3) == 0) ||
                  (strncmp(typeStr, "MFPLUS",  6) == 0);
    bool isMFUL = (strcmp(typeStr,  "MFUL") == 0);

    if (isMFC || isMFUL) {
        // Build a MifareTagInfo from the dump and dispatch to writeTagFromDump
        memset(&asyncMifareInfo, 0, sizeof(asyncMifareInfo));
        if      (strcmp(typeStr, "MFC1K")    == 0) asyncMifareInfo.type = MIFARE_CLASSIC_1K;
        else if (strcmp(typeStr, "MFC4K")    == 0) asyncMifareInfo.type = MIFARE_CLASSIC_4K;
        else if (strcmp(typeStr, "MFCMINI")  == 0) asyncMifareInfo.type = MIFARE_CLASSIC_MINI;
        else if (strcmp(typeStr, "MFUL")     == 0) asyncMifareInfo.type = MIFARE_ULTRALIGHT;
        else if (strcmp(typeStr, "MFPLUS2K") == 0) asyncMifareInfo.type = MIFARE_PLUS_SL1_2K;
        else if (strcmp(typeStr, "MFPLUS4K") == 0) asyncMifareInfo.type = MIFARE_PLUS_SL1_4K;
        asyncMifareInfo.blockCount = blockCount;
        memcpy(asyncMifareInfo.data, asyncDataBuffer, (size_t)blockCount * (isMFUL ? 4 : 16));

        nfcBusy = true;
        bool ok = false;
        uint16_t magic = 0, written = 0;
        if (isMFUL) {
            // MFUL: plain write, no magic detection needed.
            // Detect using the module-static asyncMifareInfo (no extra ~4 KB on
            // the loopTask stack) before dispatching the write.
            nfcMifare.loadISO14443Config();
            nfcMifare.activateRF();
            delay(50);
            MifareTagInfo *live = (MifareTagInfo *)malloc(sizeof(MifareTagInfo));
            if (live) {
                if (nfcMifare.detectTag(live)) {
                    ok = nfcMifare.mfulWriteAllPages(&asyncMifareInfo, &written);
                }
                free(live);
            }
            nfcMifare.haltTag();
            nfcMifare.disableRF();
        } else {
            // MFC: load dictionary keys then dispatch
            static uint8_t dk1[PN5180MIFARE::MAX_DICT_KEYS][6];
            int n1 = files.loadDictKeys(FileManager::DICT_PROTO_MFC, dk1, PN5180MIFARE::MAX_DICT_KEYS);
            ok = nfcMifare.writeTagFromDump(&asyncMifareInfo, dk1, n1, nullptr, 0,
                                             setUid, writeTrailers, &magic, &written);
        }
        nfcBusy = false;
        g_progPhase = 0;

        if (!ok) {
            server.send(200, "application/json",
                "{\"status\":\"error\",\"message\":\"Write failed (no tag or auth failure)\"}");
            return;
        }
        String resp = "{\"status\":\"ok\",\"written\":" + String(written)
                    + ",\"magic\":" + String(magic) + "}";
        server.send(200, "application/json", resp);
        return;
    }

    // ── ISO 15693 write path (original behaviour) ─────────────────────────
    uint8_t uid[8];
    if (!uidStr || !FileManager::hexToUid(String(uidStr), uid)) {
        server.send(200, "application/json",
            "{\"status\":\"error\",\"message\":\"Invalid UID\"}");
        return;
    }

    uint8_t writtenCount = 0;
    uint8_t actualBlockCount = 0;
    if (!nfc.writeTag(blockCount, blockSize, asyncDataBuffer,
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
    GUARD_NFC_BUSY();
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

    if (!uidStr || !FileManager::hexToUid(String(uidStr), uid)) {
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

// GET /api/dumps?folder=dumps|dicts  — list files in a SPIFFS folder
void handleListDumps() {
    String folder = server.hasArg("folder") ? server.arg("folder") : "dumps";
    if (folder != "dumps" && folder != "dicts") folder = "dumps";  // whitelist
    String list = files.listFiles(folder.c_str());
    server.send(200, "application/json",
        "{\"status\":\"ok\",\"dumps\":" + list + "}");
}

// ============================================================
// Chunked file upload â€” POST /api/upload?name=xxx
// Uses the WebServer upload callback so the body is never
// buffered in RAM; each chunk is written directly to SPIFFS.
// ============================================================

static File   uploadFileHandle;
static bool   uploadOk     = false;
static String uploadFolder = "dumps";

static bool isValidFilename(const String &name) {
    if (name.length() == 0 || name.charAt(0) == '.') return false;
    for (unsigned int i = 0; i < name.length(); i++) {
        char c = name.charAt(i);
        if (!isalnum(c) && c != '_' && c != '-' && c != '.') return false;
    }
    return true;
}

void handleUploadChunk() {
    HTTPUpload &upload = server.upload();

    if (upload.status == UPLOAD_FILE_START) {
        uploadOk = false;
        String name = server.hasArg("name") ? server.arg("name") : String(upload.filename.c_str());
        uploadFolder = server.hasArg("folder") ? server.arg("folder") : "dumps";
        if (uploadFolder != "dumps" && uploadFolder != "dicts") uploadFolder = "dumps";
        if (!isValidFilename(name)) {
            Serial.println("Upload: invalid filename");
            return;
        }
        String path = "/" + uploadFolder + "/" + name;
        Serial.println("Upload start: " + path);
        uploadFileHandle = SPIFFS.open(path, FILE_WRITE);
        if (!uploadFileHandle) {
            Serial.println("Upload: failed to open file");
            return;
        }
        uploadOk = true;

    } else if (upload.status == UPLOAD_FILE_WRITE) {
        if (uploadFileHandle) {
            size_t written = uploadFileHandle.write(upload.buf, upload.currentSize);
            if (written != upload.currentSize) {
                Serial.println("Upload: write error (storage full?)");
                uploadFileHandle.close();
                String name = server.hasArg("name") ? server.arg("name") : String(upload.filename.c_str());
                SPIFFS.remove("/" + uploadFolder + "/" + name);
                uploadFileHandle = File(); // invalidate
                uploadOk = false;
            }
        }

    } else if (upload.status == UPLOAD_FILE_END) {
        if (uploadFileHandle) {
            uploadFileHandle.close();
            Serial.println("Upload done: " + String(upload.totalSize) + " bytes");
        }

    } else if (upload.status == UPLOAD_FILE_ABORTED) {
        if (uploadFileHandle) {
            String name = server.hasArg("name") ? server.arg("name") : String(upload.filename.c_str());
            uploadFileHandle.close();
            SPIFFS.remove("/" + uploadFolder + "/" + name);
            Serial.println("Upload aborted");
        }
        uploadOk = false;
    }
}

void handleUploadDone() {
    if (!uploadOk) {
        server.send(200, "application/json",
            "{\"status\":\"error\",\"message\":\"Upload failed â€” storage may be full\"}");
        return;
    }
    server.send(200, "application/json", "{\"status\":\"ok\"}");
}

// GET /api/dump?name=xxx â€” get specific dump
void handleGetDump() {
    if (!server.hasArg("name")) {
        server.send(200, "application/json",
            "{\"status\":\"error\",\"message\":\"Missing name\"}");
        return;
    }
    String name = server.arg("name");
    String json = files.loadDump(name.c_str());
    if (json.isEmpty()) {
        server.send(200, "application/json",
            "{\"status\":\"error\",\"message\":\"Dump not found\"}");
        return;
    }
    server.send(200, "application/json",
        "{\"status\":\"ok\",\"data\":" + json + "}");
}

// POST /api/dump?name=xxx â€” save dump
void handleSaveDump() {
    if (!server.hasArg("name") || !server.hasArg("plain")) {
        server.send(200, "application/json",
            "{\"status\":\"error\",\"message\":\"Missing name or body\"}");
        return;
    }
    String name = server.arg("name");

    // Validate name: alphanumeric, underscore, dash, dot; must not start with dot
    if (name.length() == 0 || name.charAt(0) == '.') {
        server.send(200, "application/json",
            "{\"status\":\"error\",\"message\":\"Invalid name\"}");
        return;
    }
    for (unsigned int i = 0; i < name.length(); i++) {
        char c = name.charAt(i);
        if (!isalnum(c) && c != '_' && c != '-' && c != '.') {
            server.send(200, "application/json",
                "{\"status\":\"error\",\"message\":\"Invalid name\"}");
            return;
        }
    }

    if (!files.saveDump(name.c_str(), server.arg("plain"))) {
        server.send(200, "application/json",
            "{\"status\":\"error\",\"message\":\"Save failed\"}");
        return;
    }
    server.send(200, "application/json", "{\"status\":\"ok\"}");
}

// DELETE /api/dump?name=xxx[&folder=dumps|dicts]  — delete a file
void handleDeleteDump() {
    if (!server.hasArg("name")) {
        server.send(200, "application/json",
            "{\"status\":\"error\",\"message\":\"Missing name\"}");
        return;
    }
    String folder = server.hasArg("folder") ? server.arg("folder") : "dumps";
    if (folder != "dumps" && folder != "dicts") folder = "dumps";
    if (!files.deleteFile(folder.c_str(), server.arg("name").c_str())) {
        server.send(200, "application/json",
            "{\"status\":\"error\",\"message\":\"Delete failed\"}");
        return;
    }
    server.send(200, "application/json", "{\"status\":\"ok\"}");
}

// POST /api/dump/rename â€” rename dump, body = {oldName, newName}
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
    if (nn.length() == 0 || nn.charAt(0) == '.') {
        server.send(200, "application/json",
            "{\"status\":\"error\",\"message\":\"Invalid name\"}");
        return;
    }
    for (unsigned int i = 0; i < nn.length(); i++) {
        char c = nn.charAt(i);
        if (!isalnum(c) && c != '_' && c != '-' && c != '.') {
            server.send(200, "application/json",
                "{\"status\":\"error\",\"message\":\"Invalid name\"}");
            return;
        }
    }
    if (!files.renameDump(oldName, newName)) {
        server.send(200, "application/json",
            "{\"status\":\"error\",\"message\":\"Rename failed\"}");
        return;
    }
    server.send(200, "application/json", "{\"status\":\"ok\"}");
}

// POST /api/dicts/toggle  body = {name, enabled}  — enable/disable a dictionary
void handleDictToggle() {
    if (!server.hasArg("plain")) {
        server.send(200, "application/json",
            "{\"status\":\"error\",\"message\":\"No body\"}");
        return;
    }
    StaticJsonDocument<256> doc;
    if (deserializeJson(doc, server.arg("plain"))) {
        server.send(200, "application/json",
            "{\"status\":\"error\",\"message\":\"Invalid JSON\"}");
        return;
    }
    const char *name = doc["name"];
    bool enabled     = doc["enabled"] | true;
    if (!name) {
        server.send(200, "application/json",
            "{\"status\":\"error\",\"message\":\"Missing name\"}");
        return;
    }
    if (!files.setDictEnabled(name, enabled)) {
        server.send(200, "application/json",
            "{\"status\":\"error\",\"message\":\"Save failed\"}");
        return;
    }
    server.send(200, "application/json", "{\"status\":\"ok\"}");
}

// POST /api/dicts/order  body = ["a.txt","b.txt",...]  — reorder dictionaries
void handleDictOrder() {
    if (!server.hasArg("plain")) {
        server.send(200, "application/json",
            "{\"status\":\"error\",\"message\":\"No body\"}");
        return;
    }
    if (!files.setDictOrder(server.arg("plain"))) {
        server.send(200, "application/json",
            "{\"status\":\"error\",\"message\":\"Invalid order\"}");
        return;
    }
    server.send(200, "application/json", "{\"status\":\"ok\"}");
}

// ============================================================
// Emulation API Handlers
// ============================================================

// POST /api/emulate/start â€” body = {uid, dsfid, afi, icRef, blockSize, blockCount, data}
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
    StaticJsonDocument<4096> doc;
    DeserializationError err = deserializeJson(doc, server.arg("plain"));
    if (err) {
        server.send(200, "application/json",
            "{\"status\":\"error\",\"message\":\"Invalid JSON\"}");
        return;
    }

    const char *uidStr = doc["uid"];
    memset(&emuTagInfo, 0, sizeof(emuTagInfo));
    if (!uidStr || !FileManager::hexToUid(String(uidStr), emuTagInfo.uid)) {
        server.send(200, "application/json",
            "{\"status\":\"error\",\"message\":\"Invalid UID\"}");
        return;
    }

    emuTagInfo.blockSize  = doc["blockSize"]  | 4;
    emuTagInfo.blockCount = doc["blockCount"] | 0;
    emuTagInfo.dsfid  = (uint8_t)strtoul(doc["dsfid"]  | "00", nullptr, 16);
    emuTagInfo.afi    = (uint8_t)strtoul(doc["afi"]    | "00", nullptr, 16);
    emuTagInfo.icRef  = (uint8_t)strtoul(doc["icRef"]  | "00", nullptr, 16);
    emuTagInfo.valid  = true;

    const char *dataStr = doc["data"];
    if (!dataStr || emuTagInfo.blockCount == 0) {
        server.send(200, "application/json",
            "{\"status\":\"error\",\"message\":\"No block data\"}");
        return;
    }

    memset(emuDataBuffer, 0, sizeof(emuDataBuffer));
    if (!FileManager::hexToBytes(String(dataStr), emuDataBuffer, sizeof(emuDataBuffer))) {
        server.send(200, "application/json",
            "{\"status\":\"error\",\"message\":\"Invalid block data\"}");
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

// GET /api/spiffs â€” filesystem usage
void handleSpiffsInfo() {
    size_t total = SPIFFS.totalBytes();
    size_t used  = files.usedBytes();   // sum of actual file sizes (SPIFFS.usedBytes() is unreliable on ESP32)
    String json = "{\"status\":\"ok\",\"used\":" + String(used)
                + ",\"total\":" + String(total) + "}";
    server.send(200, "application/json", json);
}

// GET /api/rawfile?name=xxx[&folder=dumps|dicts]  — serve raw file for download
void handleRawFile() {
    if (!server.hasArg("name")) {
        server.send(400, "text/plain", "Missing name");
        return;
    }
    String name   = server.arg("name");
    String folder = server.hasArg("folder") ? server.arg("folder") : "dumps";
    if (folder != "dumps" && folder != "dicts") folder = "dumps";
    String content = files.loadFile(folder.c_str(), name.c_str());
    if (content.isEmpty()) {
        server.send(404, "text/plain", "Not found");
        return;
    }
    String ct = "application/octet-stream";
    if (name.endsWith(".json") || name.endsWith(".JSON")) ct = "application/json";
    else if (name.endsWith(".txt")  || name.endsWith(".TXT"))  ct = "text/plain";
    server.sendHeader("Content-Disposition", "attachment; filename=\"" + name + "\"");
    server.send(200, ct, content);
}

// ============================================================
// Setup & Loop
// ============================================================

// HTTP OTA: POST /api/ota with firmware.bin as body.
// Usage (PowerShell): Invoke-WebRequest http://192.168.24.135/api/ota -Method POST -InFile .pio\build\esp32\firmware.bin
void handleOTAUpload() {
    HTTPUpload &up = server.upload();
    if (up.status == UPLOAD_FILE_START) {
        Serial.printf("[OTA] Start: %s (%u bytes)\n", up.filename.c_str(), server.header("Content-Length").toInt());
        if (!Update.begin(UPDATE_SIZE_UNKNOWN)) {
            Update.printError(Serial);
        }
    } else if (up.status == UPLOAD_FILE_WRITE) {
        if (Update.write(up.buf, up.currentSize) != up.currentSize) {
            Update.printError(Serial);
        }
    } else if (up.status == UPLOAD_FILE_END) {
        if (Update.end(true)) {
            Serial.printf("[OTA] Done: %u bytes. Rebooting...\n", up.totalSize);
            server.send(200, "text/plain", "OTA OK - rebooting\n");
            delay(200);
            ESP.restart();
        } else {
            Update.printError(Serial);
            server.send(500, "text/plain", "OTA FAILED\n");
        }
    }
}
void handleOTADone() {}  // body handled by handleOTAUpload

// Parameterized live-debug for ISO14443A without reflashing.
// Query params:
//   sigpro=<0-7>  SIGPRO_CONFIG override (default 2)
//   stop=wupa|anticoll|select  how far to run (default select)
//   tries=<1-10>  repeat count (default 1)
void handleTest14443() {
    GUARD_NFC_BUSY();
    uint8_t sigpro = server.hasArg("sigpro") ? (uint8_t)server.arg("sigpro").toInt() : 2;
    String  stop   = server.hasArg("stop")   ? server.arg("stop")                    : "select";
    uint8_t tries  = server.hasArg("tries")  ? (uint8_t)server.arg("tries").toInt()  : 1;
    if (tries < 1) tries = 1;
    if (tries > 10) tries = 10;
    String result = nfcMifare.debugDetect(sigpro, stop.c_str(), tries);
    server.send(200, "application/json", result);
}

// Live single-key auth test.
// /api/testauth?key=9FB25CAAA8DC&block=3&type=a
void handleTestAuth() {
    GUARD_NFC_BUSY();
    if (!server.hasArg("key")) {
        server.send(200, "application/json", "{\"status\":\"error\",\"message\":\"Missing key\"}");
        return;
    }
    String ks = server.arg("key");
    ks.trim();
    if (ks.length() != 12) {
        server.send(200, "application/json", "{\"status\":\"error\",\"message\":\"Key must be 12 hex chars\"}");
        return;
    }
    uint8_t key[6];
    for (int i = 0; i < 6; i++) {
        char h[3] = { ks.charAt(i*2), ks.charAt(i*2+1), 0 };
        char *end;
        key[i] = (uint8_t)strtol(h, &end, 16);
        if (*end != '\0') {
            server.send(200, "application/json", "{\"status\":\"error\",\"message\":\"Invalid hex\"}");
            return;
        }
    }
    uint8_t block = server.hasArg("block") ? (uint8_t)server.arg("block").toInt() : 0;
    bool useKeyA = !server.hasArg("type") || server.arg("type") == "a" || server.arg("type") == "A";
    String result = nfcMifare.debugAuth(key, block, useKeyA);
    server.send(200, "application/json", result);
}

// Dump EEPROM bytes + key registers for both ISO14443A and ISO15693 configs via Serial
void handleRegDump() {
    GUARD_NFC_BUSY();
    nfcMifare.dumpRFConfigs();
    server.send(200, "text/plain", "See Serial monitor\n");
}

// Card identification / clone fingerprinting (port of proxmark3 `hf mf info`).
// Runs magic-card probes + backdoor key auth + block-0 fingerprint.
void handleIdentCard() {
    GUARD_EMULATION();
    GUARD_NFC_BUSY();
    nfcBusy = true;
    String result = nfcMifare.identCard();
    nfcBusy = false;
    server.send(200, "application/json", result);
}

void setup() {
    Serial.begin(115200);
    Serial.println("\n=== NFC Tool ===");

    // Init PN5180
    nfc.begin();
    Serial.println("PN5180 initialized");

    // IRQ interrupt — PN5180 IRQ pin asserts HIGH on any enabled IRQ event.
    // mfcAuthBlock() sleeps on g_irqSem instead of polling; wrong-key returns in ~5ms.
    g_irqSem = xSemaphoreCreateBinary();
    pinMode(PN5180_IRQ, INPUT);
    attachInterrupt(digitalPinToInterrupt(PN5180_IRQ), pn5180IrqISR, RISING);
    Serial.println("PN5180 IRQ armed on GPIO4");

    // Init SPIFFS
    files.begin();
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
    server.on("/api/read/cancel", HTTP_POST, handleReadCancel);
    server.on("/api/write", HTTP_POST, handleWrite);
    server.on("/api/csetuid", HTTP_POST, handleCSetUID);
    server.on("/api/dumps", HTTP_GET, handleListDumps);
    server.on("/api/dump", HTTP_GET, handleGetDump);
    server.on("/api/dump", HTTP_POST, handleSaveDump);
    server.on("/api/dump", HTTP_DELETE, handleDeleteDump);
    server.on("/api/dump/rename", HTTP_POST, handleRenameDump);
    server.on("/api/dicts/toggle", HTTP_POST, handleDictToggle);
    server.on("/api/dicts/order",  HTTP_POST, handleDictOrder);
    server.on("/api/emulate/start", HTTP_POST, handleEmulateStart);
    server.on("/api/emulate/stop", HTTP_POST, handleEmulateStop);
    server.on("/api/emulate/status", HTTP_GET, handleEmulateStatus);
    server.on("/api/test14443", HTTP_GET, handleTest14443);
    server.on("/api/testauth",  HTTP_GET, handleTestAuth);
    server.on("/api/regdump",   HTTP_GET, handleRegDump);
    server.on("/api/cident",    HTTP_GET, handleIdentCard);
    server.on("/api/spiffs",    HTTP_GET, handleSpiffsInfo);
    server.on("/api/rawfile", HTTP_GET, handleRawFile);
    server.on("/api/upload", HTTP_POST, handleUploadDone, handleUploadChunk);
    server.on("/api/ota",    HTTP_POST, handleOTADone,    handleOTAUpload);
    server.onNotFound([]() {
        server.send(404, "text/plain", "Not found");
    });

    server.begin();
    Serial.println("Web server started on port 80");

    // HTTP OTA available at POST /api/ota
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
