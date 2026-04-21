#ifndef PN5180MIFARE_H
#define PN5180MIFARE_H

#include <Arduino.h>
#include "PN5180ISO15693.h"   // reuse SPI low-level and register ops via inheritance

// ---------------------------------------------------------------------------
// ISO 14443A / MIFARE constants
// ---------------------------------------------------------------------------

// PN5180 RF config bytes for ISO14443A
#define RF_TX_ISO14443A_106   0x00
#define RF_RX_ISO14443A_106   0x80

// ISO 14443A-specific register fields (shared base regs live in PN5180ISO15693.h)
#define REG_CRC_RX_CONFIG   0x12   // bit 0 = RX CRC enable
#define REG_CRC_TX_CONFIG   0x19   // bit 0 = TX CRC enable

// ISO 14443A commands
#define REQA       0x26
#define WUPA       0x52
#define ANTICOLL1  0x93
#define SELECT1    0x93
#define ANTICOLL2  0x95
#define SELECT2    0x95
#define ANTICOLL3  0x97
#define SELECT3    0x97
#define RATS       0xE0
#define HALT_CMD   0x50

// MIFARE Classic commands
#define MFC_AUTH_KEY_A  0x60
#define MFC_AUTH_KEY_B  0x61
#define MFC_READ        0x30
#define MFC_WRITE       0xA0

// MIFARE Ultralight commands
#define MFUL_READ   0x30
#define MFUL_WRITE  0xA2

// SAK values
#define SAK_MFC_1K        0x08
#define SAK_MFC_4K        0x18
#define SAK_MFC_MINI      0x09
#define SAK_MFUL          0x00
#define SAK_MFPLUS_SL1_2K 0x10
#define SAK_MFPLUS_SL1_4K 0x11
#define SAK_MFPLUS_SL2    0x20

// Layout limits
#define MFC_1K_BLOCKS   64
#define MFC_4K_BLOCKS   256
#define MFC_MINI_BLOCKS 20
#define MFUL_PAGES      16    // standard Ultralight; 48 for UL-C

// Maximum data buffer (4K)
#define MAX_MIFARE_DATA (MFC_4K_BLOCKS * 16)

// ---------------------------------------------------------------------------
// Structs
// ---------------------------------------------------------------------------

enum MifareType {
    MIFARE_UNKNOWN     = 0,
    MIFARE_CLASSIC_1K  = 1,
    MIFARE_CLASSIC_4K  = 2,
    MIFARE_CLASSIC_MINI = 3,
    MIFARE_ULTRALIGHT  = 4,
    MIFARE_PLUS_SL1_2K = 5,
    MIFARE_PLUS_SL1_4K = 6,
    MIFARE_PLUS_SL2    = 7,
};

// Magic-card flavours (auto-detected by detectMagicType()).
// Values are bit-flags so multiple capabilities can coexist (e.g. a card may
// answer both Gen 1A wakeup and the Gen 4 backdoor).
enum MagicType {
    MAGIC_NONE     = 0,
    MAGIC_GEN1A    = 1 << 0,   // 0x40 + 0x43 magic wakeup, blocks unauth-writeable
    MAGIC_GEN1B    = 1 << 1,   // 0x40 ack but no 0x43 ack; same write protocol
    MAGIC_GEN2_CUID= 1 << 2,   // standard auth, but block 0 is writeable (probed)
    MAGIC_GEN3     = 1 << 3,   // APDU 0x90 0xFB/0xF0 0xCC 0xCC for UID/block0
    MAGIC_GEN4_GTU = 1 << 4,   // 0xCF backdoor read/write any block
    MAGIC_GDM      = 1 << 5,   // USCUID GDM auth (0x80) + GDM write (0xA8)
};

struct MifareTagInfo {
    uint8_t     uid[10];     // up to 10 bytes (single, double, triple cascade)
    uint8_t     uidLen;      // 4, 7, or 10
    uint8_t     sak;
    uint8_t     atqa[2];
    MifareType  type;
    uint16_t    blockCount;  // total blocks / pages
    bool        valid;

    // Read result
    uint8_t     data[MAX_MIFARE_DATA];    // blockCount * 16 bytes
    // Which blocks were successfully read
    bool        blockRead[MFC_4K_BLOCKS];
    // Key used per sector (0=none, 1=keyA, 2=keyB)
    uint8_t     keyUsed[40];    // max 40 sectors in 4K
};

// ---------------------------------------------------------------------------
// PN5180MIFARE class
// ---------------------------------------------------------------------------

class PN5180MIFARE : public PN5180ISO15693 {
public:
    using PN5180ISO15693::PN5180ISO15693;  // inherit constructor

    // High-level: detect + read tag using dictionary keys
    // Returns true if a tag was found. Info/data are populated even on partial reads.
    bool readTag(MifareTagInfo *info, const char *dictPath1 = nullptr, const char *dictPath2 = nullptr);

    // ---------------------------------------------------------------------------
    // Internal helpers (public for testing)
    // ---------------------------------------------------------------------------

    bool loadISO14443Config();
    void dumpRFConfigs();   // print EEPROM + registers for both protocols to Serial
    // Live debug: run WUPA [+ANTICOLL [+SELECT]] with overridable SIGPRO_CONFIG.
    // stop: "wupa" | "anticoll" | "select"  tries: 1-10
    // Returns JSON string (printed to Serial too).
    String debugDetect(uint8_t sigpro, const char *stop, uint8_t tries);

    // Live debug: REQA + SELECT + MIFARE_AUTHENTICATE with caller-supplied key.
    // Returns JSON describing detect result and the raw 1-byte auth status.
    String debugAuth(const uint8_t key[6], uint8_t block, bool useKeyA);

    // Card identification / clone fingerprinting (proxmark "hf mf info" port).
    // Runs magic-card probes (Gen1A/1B, Gen2, Gen3, Gen4 GTU, Gen4 GDM,
    // Super Card, FUID), tries Fudan/NXP/Infineon backdoor keys, and
    // matches block-0 against a known-clone fingerprint table.
    // Returns a JSON string. Manages RF on/off internally.
    String identCard();

    bool detectTag(MifareTagInfo *info);          // REQA + anticollision + SELECT
    bool reActivateCard(MifareTagInfo *info);     // RF cycle + SELECT (after auth failure)
    bool reSelectCard(MifareTagInfo *info);       // WUPA + SELECT only, no RF cycle (faster)
    bool haltTag();

    // MIFARE Classic
    bool mfcReadAllBlocks(MifareTagInfo *info,
                          uint8_t (*keys1)[6], int n1,
                          uint8_t (*keys2)[6], int n2);
    bool mfcAuthBlock(MifareTagInfo *info, uint8_t block, uint8_t *key, bool useKeyA);
    bool mfcReadBlock(uint8_t block, uint8_t *out16);
    // Standard MIFARE Classic WRITE (0xA0) — caller must have authenticated first.
    bool mfcWriteBlock(uint8_t block, const uint8_t *data16);

    // MIFARE Ultralight
    bool mfulReadAllPages(MifareTagInfo *info);
    bool mfulReadPage(uint8_t page, uint8_t *out4);
    // MFUL WRITE (0xA2) writes 4 bytes per page — no auth needed for plain UL.
    bool mfulWritePage(uint8_t page, const uint8_t *data4);
    bool mfulWriteAllPages(MifareTagInfo *dump, uint16_t *outWritten);

    // ---------------------------------------------------------------------------
    // Magic / Chinese-clone card primitives (port of proxmark3 mifarecmd.c)
    // ---------------------------------------------------------------------------

    // Auto-detect magic-card flavour. Performs RF cycles + probes; afterwards
    // RF is left ON and the card is HALTed (caller should re-detect/re-select
    // before issuing further commands). Returns OR'd MagicType bit-flags
    // (MAGIC_NONE if no magic detected).
    uint16_t detectMagicType(MifareTagInfo *info);

    // --- Gen 1A / 1B (CUID/UID) ---
    // 0x40 (7-bit) + 0x43 magic wakeup. After this, *all* blocks on the card
    // can be written via plain MIFARE WRITE without authentication.
    bool gen1Wakeup(bool *isGen1B = nullptr);
    // After gen1Wakeup, write a 16-byte block. Sends WRITE 0xA0 + ACK roundtrip
    // then 16 bytes + CRC + ACK. No auth, no Crypto1.
    bool gen1WriteBlock(uint8_t block, const uint8_t *data16);

    // --- Gen 3 (APDU magic) ---
    // Send 0x90 0xFB 0xCC 0xCC + uidLen + uid + CRC. Sets the UID. Card
    // recomputes BCC and stays selected. Caller must have selected the tag.
    bool gen3SetUID(const uint8_t *uid, uint8_t uidLen);
    // Send 0x90 0xF0 0xCC 0xCC 0x10 + 16 bytes block 0 + CRC. Overwrites
    // the manufacturer block (UID + BCC + SAK + ATQA + manufacturer bytes).
    bool gen3SetBlock0(const uint8_t *block16);
    // Send 0x90 0xFD 0x11 0x11 0x00 + CRC. Permanently locks the UID — once
    // sent, no further Gen3 commands are accepted.
    bool gen3Freeze();

    // --- Gen 4 GTU (backdoor read/write any block, any sector) ---
    // 0xCF + pwd[4] + 0xCD + blockno + 16 bytes data + CRC. Default pwd 00000000.
    bool gen4WriteBlock(uint8_t block, const uint8_t pwd[4], const uint8_t *data16);
    bool gen4ReadBlock(uint8_t block, const uint8_t pwd[4], uint8_t *out16);

    // --- GDM / USCUID magic auth + GDM-write ---
    // GDM auth uses cmd 0x80 instead of 0x60/0x61, then write uses 0xA8.
    bool gdmAuthBlock(MifareTagInfo *info, uint8_t block, const uint8_t key[6], bool useKeyA);
    bool gdmWriteBlock(uint8_t block, const uint8_t *data16);

    // --- High-level dump → tag write with auto magic detection ---
    // dump:           the source dump (data + UID + sector keys live in trailers).
    // keys1/n1, keys2/n2: dictionary keys to try when normal auth is needed.
    // writeBlock0:    if true, attempt to overwrite block 0 (UID) using whichever
    //                 magic capability the card supports (Gen1/Gen3/Gen4/CUID).
    // writeTrailers:  if true, also write sector trailer blocks (DANGEROUS — wrong
    //                 access bits can permanently brick a sector).
    // outMagic, outWritten: detected magic flags + count of blocks successfully
    //                       written (both optional).
    bool writeTagFromDump(MifareTagInfo *dump,
                          uint8_t (*keys1)[6], int n1,
                          uint8_t (*keys2)[6], int n2,
                          bool writeBlock0,
                          bool writeTrailers,
                          uint16_t *outMagic = nullptr,
                          uint16_t *outWritten = nullptr);

    // Dictionary key loading
    // MAX_DICT_KEYS is exposed here so callers can pre-size their arrays before RF activation
    static constexpr int MAX_DICT_KEYS = 2000;
    static int loadKeysFromFile(const char *path, uint8_t (*keys)[6], int maxKeys);

    // Utility
    static const char *typeString(MifareType t);
    static uint8_t totalSectors(MifareType type);

private:
    bool sendCmd14443(uint8_t *cmd, uint8_t cmdLen, uint8_t *resp, uint8_t *respLen, uint16_t timeoutMs = 50);
    bool transceive14443(uint8_t *data, uint8_t dataLen, uint8_t *resp, uint8_t *respLen, uint16_t timeoutMs = 50);
    bool transceiveInAuth(uint8_t *data, uint8_t dataLen, uint8_t *resp, uint8_t *respLen, uint16_t timeoutMs = 100);
    uint8_t crc8(uint8_t *data, uint8_t len);
    void    appendCRC16(uint8_t *data, uint8_t *len);
    bool    checkCRC16(uint8_t *data, uint8_t len);  // checks last 2 bytes

    // Sector layout helpers
    static uint8_t blockToSector(MifareType type, uint8_t block);
    static uint8_t sectorFirstBlock(MifareType type, uint8_t sector);
    static uint8_t sectorBlockCount(MifareType type, uint8_t sector);
    static uint8_t sectorTrailerBlock(MifareType type, uint8_t sector);
};

#endif
