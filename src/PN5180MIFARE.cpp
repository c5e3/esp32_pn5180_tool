/*
 * PN5180MIFARE.cpp — ISO 14443A / MIFARE driver for PN5180
 *
 * Supports:
 *   MIFARE Classic 1K/4K/Mini  — key dictionary attack + block read
 *   MIFARE Ultralight           — plain read
 *   MIFARE Plus SL1             — treated as MIFARE Classic compatible
 *
 * Inherits all SPI/register primitives from PN5180ISO15693.
 */

#include "PN5180MIFARE.h"
#include <SPIFFS.h>
#include <freertos/semphr.h>
#include <memory>

// Signalled by pn5180IrqISR() in main.cpp whenever PN5180 asserts its IRQ pin.
extern SemaphoreHandle_t g_irqSem;

// Progress state owned by main.cpp — updated here so the web UI can poll it.
extern volatile int16_t g_progCurBlock;
extern volatile int16_t g_progTotalBlocks;
extern volatile int8_t  g_progKeyType;
extern volatile uint8_t g_progPhase;
extern volatile bool    g_readCancel;

// ---------------------------------------------------------------------------
// CRC-16/ISO-IEC-13239 (used in ISO 14443A frames)
// ---------------------------------------------------------------------------

static const uint16_t CRC_PRESET = 0x6363;

static uint16_t crc16(uint8_t *data, uint8_t len) {
    uint16_t crc = CRC_PRESET;
    for (uint8_t i = 0; i < len; i++) {
        uint8_t b = data[i];
        b ^= (uint8_t)(crc & 0xFF);
        b ^= (b << 4);
        crc = (crc >> 8) ^ ((uint16_t)b << 8) ^ ((uint16_t)b << 3) ^ (b >> 4);
    }
    return crc;
}

void PN5180MIFARE::appendCRC16(uint8_t *data, uint8_t *len) {
    uint16_t c = crc16(data, *len);
    data[(*len)++] = c & 0xFF;
    data[(*len)++] = (c >> 8) & 0xFF;
}

bool PN5180MIFARE::checkCRC16(uint8_t *data, uint8_t len) {
    if (len < 3) return false;
    uint16_t calc  = crc16(data, len - 2);
    uint16_t rcvd  = (uint16_t)data[len - 2] | ((uint16_t)data[len - 1] << 8);
    return calc == rcvd;
}

// ---------------------------------------------------------------------------
// RF config for ISO 14443A
// ---------------------------------------------------------------------------

bool PN5180MIFARE::loadISO14443Config() {
    // PN5180 LOAD_RF_CONFIG: TX=0x00, RX=0x80 → ISO14443A 106 kbit/s
    uint8_t cmd[] = { PN5180_LOAD_RF_CONFIG, RF_TX_ISO14443A_106, RF_RX_ISO14443A_106 };
    if (!spiSend(cmd, sizeof(cmd))) return false;
    // Enable IDLE_IRQ and GENERAL_ERROR_IRQ to drive the IRQ pin.
    // LOAD_RF_CONFIG restores EEPROM defaults which may not include GENERAL_ERROR;
    // without this the IRQ pin never asserts on auth failure → ISR never fires.
    orRegister(REG_IRQ_ENABLE, IDLE_IRQ_STAT | GENERAL_ERROR_IRQ_STAT);
    return true;
}

// Dump key registers + EEPROM for both ISO14443A and ISO15693 configs to Serial
void PN5180MIFARE::dumpRFConfigs() {
    auto dump = [this](const char *label, uint8_t txConf, uint8_t rxConf) {
        uint8_t cmd[] = { PN5180_LOAD_RF_CONFIG, txConf, rxConf };
        spiSend(cmd, sizeof(cmd));
        delay(10);
        Serial.printf("[REGDUMP] === %s (LOAD_RF_CONFIG 0x%02X/0x%02X) ===\n", label, txConf, rxConf);
        // Dump all 64 PN5180 registers (0x00..0x3F)
        for (int r = 0; r < 64; r++) {
            uint32_t val = readRegister((uint8_t)r);
            Serial.printf("[REGDUMP]  R%02X=0x%08X%s", r, val, (r % 4 == 3) ? "\n" : "  ");
        }
        Serial.println();
    };
    dump("ISO14443A", 0x00, 0x80);
    dump("ISO15693 ", 0x0D, 0x8D);
}

// ---------------------------------------------------------------------------
// Low-level 14443A transceive
// ---------------------------------------------------------------------------

// Send cmd bytes and collect response. Returns true if response received.
bool PN5180MIFARE::transceive14443(uint8_t *data, uint8_t dataLen,
                                    uint8_t *resp, uint8_t *respLen, uint16_t timeoutMs) {
    clearIRQ();
    setIdle();
    activateTransceive();

    // SEND_DATA
    uint8_t cmd[64];
    cmd[0] = PN5180_SEND_DATA;
    cmd[1] = 0x00;  // number of valid bits in last byte (0 = full byte)
    memcpy(cmd + 2, data, dataLen);
    // spiSend() already waits for BUSY LOW (command complete).
    if (!spiSend(cmd, dataLen + 2)) return false;

    // Wait for RX_IRQ or timeout
    unsigned long t = millis();
    while (!(readRegister(REG_IRQ_STATUS) & RX_IRQ_STAT)) {
        if (millis() - t > timeoutMs) {
            clearIRQ();
            return false;
        }
        delay(1);
    }

    // READ_DATA
    uint32_t rxStatus = readRegister(REG_RX_STATUS);
    uint8_t len = (uint8_t)(rxStatus & 0x1FF);
    if (len == 0 || len > 64) {
        clearIRQ();
        return false;
    }

    uint8_t rcmd[2] = { PN5180_READ_DATA, 0x00 };
    spiSend(rcmd, sizeof(rcmd));
    uint8_t buf[64] = {};
    memset(buf, 0xFF, len);
    if (!spiReceive(buf, len)) {
        clearIRQ();
        return false;
    }

    memcpy(resp, buf, len);
    *respLen = len;
    clearIRQ();
    return true;
}

// During authenticated MIFARE operations the PN5180 must stay in active
// TRANSCEIVE + Crypto1 context; avoid setIdle()/activateTransceive().
bool PN5180MIFARE::transceiveInAuth(uint8_t *data, uint8_t dataLen,
                                    uint8_t *resp, uint8_t *respLen, uint16_t timeoutMs) {
    clearIRQ();

    uint8_t cmd[64];
    cmd[0] = PN5180_SEND_DATA;
    cmd[1] = 0x00;
    memcpy(cmd + 2, data, dataLen);
    if (!spiSend(cmd, dataLen + 2)) return false;

    unsigned long t = millis();
    while (!(readRegister(REG_IRQ_STATUS) & RX_IRQ_STAT)) {
        if (millis() - t > timeoutMs) {
            clearIRQ();
            return false;
        }
        delay(1);
    }

    uint32_t rxStatus = readRegister(REG_RX_STATUS);
    uint8_t len = (uint8_t)(rxStatus & 0x1FF);
    if (len == 0 || len > 64) {
        clearIRQ();
        return false;
    }

    uint8_t rcmd[2] = { PN5180_READ_DATA, 0x00 };
    spiSend(rcmd, sizeof(rcmd));
    uint8_t buf[64];
    memset(buf, 0xFF, len);
    if (!spiReceive(buf, len)) {
        clearIRQ();
        return false;
    }

    memcpy(resp, buf, len);
    *respLen = len;
    clearIRQ();
    return true;
}

// ---------------------------------------------------------------------------
// Live-debug helper — no reflash needed to test register variants
// Call via GET /api/test14443?sigpro=2&stop=select&tries=1
// ---------------------------------------------------------------------------

String PN5180MIFARE::debugDetect(uint8_t sigpro, const char *stop, uint8_t tries) {
    // Determine how far to run: 0=wupa only, 1=+anticoll, 2=+select
    uint8_t maxStep = 2;
    if (strcmp(stop, "wupa")     == 0) maxStep = 0;
    if (strcmp(stop, "anticoll") == 0) maxStep = 1;

    String out = "{\"sigpro\":" + String(sigpro) + ",\"tries\":" + String(tries) + ",\"runs\":[";

    for (uint8_t t = 0; t < tries; t++) {
        if (t) out += ",";
        out += "{";

        // ── Setup ──────────────────────────────────────────────────────────
        loadISO14443Config();
        activateRF();
        delay(50);
        writeRegister(0x1A, (uint32_t)sigpro);
        andRegister(REG_SYSTEM_CONFIG, 0xFFFFFFBFU);
        andRegister(REG_CRC_RX_CONFIG, 0xFFFFFFFEU);
        andRegister(REG_CRC_TX_CONFIG, 0xFFFFFFFEU);

        out += "\"regs\":{\"tx_cfg\":\"" + String(readRegister(REG_TX_CONFIG), HEX)
             + "\",\"crc_tx\":\"" + String(readRegister(REG_CRC_TX_CONFIG), HEX)
             + "\",\"crc_rx\":\"" + String(readRegister(REG_CRC_RX_CONFIG), HEX)
             + "\",\"sigpro\":\"" + String(readRegister(0x1A), HEX) + "\"}";

        // ── WUPA ───────────────────────────────────────────────────────────
        clearIRQ();
        setIdle();
        activateTransceive();
        uint8_t wupaBuf[3] = { PN5180_SEND_DATA, 0x07, WUPA };
        spiSend(wupaBuf, sizeof(wupaBuf));
        delay(5);
        uint32_t irq = readRegister(REG_IRQ_STATUS);
        uint32_t rxs = readRegister(REG_RX_STATUS);
        uint8_t rlen = (uint8_t)(rxs & 0x1FF);
        clearIRQ();

        out += ",\"wupa\":{\"irq\":\"" + String(irq, HEX)
             + "\",\"rx_status\":\"" + String(rxs, HEX)
             + "\",\"rlen\":" + String(rlen);

        uint8_t atqa[2] = {0, 0};
        if (rlen >= 2) {
            uint8_t rc[2] = { PN5180_READ_DATA, 0x00 };
            spiSend(rc, sizeof(rc));
            spiReceive(atqa, 2);
            out += ",\"atqa\":\"" + String(atqa[0], HEX) + " " + String(atqa[1], HEX) + "\"";
        }
        out += "}";

        if (maxStep == 0 || rlen < 2) { out += "}"; continue; }

        // ── ANTICOLL ───────────────────────────────────────────────────────
        uint8_t acCmd[2] = { ANTICOLL1, 0x20 };
        uint8_t acResp[5] = {0};
        uint8_t acLen = 0;
        bool acOk = transceive14443(acCmd, 2, acResp, &acLen, 50) && acLen >= 5;

        out += ",\"anticoll\":{\"ok\":" + String(acOk ? "true" : "false");
        if (acOk) {
            out += ",\"bytes\":\"";
            for (int i = 0; i < 5; i++) {
                if (i) out += " ";
                out += String(acResp[i], HEX);
            }
            out += "\"";
        }
        out += "}";

        if (maxStep == 1 || !acOk) { out += "}"; disableRF(); if (t + 1 < tries) delay(200); continue; }

        // ── SELECT ─────────────────────────────────────────────────────────
        uint8_t selCmd[9];
        uint8_t selLen = 0;
        selCmd[selLen++] = SELECT1;
        selCmd[selLen++] = 0x70;
        memcpy(selCmd + selLen, acResp, 5);
        selLen += 5;
        appendCRC16(selCmd, &selLen);

        uint8_t selResp[3] = {0};
        uint8_t selLen2 = 0;
        bool selOk = transceive14443(selCmd, selLen, selResp, &selLen2, 50) && selLen2 >= 1;

        out += ",\"select\":{\"ok\":" + String(selOk ? "true" : "false");
        if (selOk) out += ",\"sak\":\"" + String(selResp[0], HEX) + "\"";
        out += "}";

        if (!selOk) { out += "}"; disableRF(); if (t + 1 < tries) delay(200); continue; }

        // ── AUTH block 0 with default key FFFFFFFFFFFF ─────────────────────
        uint8_t uid4[4];
        memcpy(uid4, acResp + (acResp[0] == 0x88 ? 1 : 0), 4);
        MifareTagInfo tmp;
        memset(&tmp, 0, sizeof(tmp));
        memcpy(tmp.uid, uid4, 4);
        tmp.uidLen = 4;
        uint8_t defaultKey[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
        bool authOk = mfcAuthBlock(&tmp, 0, defaultKey, true);
        out += ",\"auth_b0_default\":" + String(authOk ? "true" : "false");
        if (authOk) {
            // Try reading block 0
            uint8_t blk[16] = {0};
            bool rdOk = mfcReadBlock(0, blk);
            out += ",\"read_b0\":{\"ok\":" + String(rdOk ? "true" : "false");
            if (rdOk) {
                out += ",\"data\":\"";
                for (int i = 0; i < 16; i++) {
                    if (i) out += " ";
                    out += String(blk[i] < 16 ? "0" : "") + String(blk[i], HEX);
                }
                out += "\"";
            }
            out += "}";
        }

        out += "}";   // end run

        disableRF();
        if (t + 1 < tries) delay(200);
    }  // end for tries
    out += "]}";

    Serial.printf("[test14443] sigpro=0x%02X stop=%s tries=%u\n%s\n",
        sigpro, stop, tries, out.c_str());
    return out;
}

// ---------------------------------------------------------------------------
// Live-debug: detect tag + try a specific key on a specific block.
// Dumps the full command bytes and the 1-byte status returned by the chip.
// ---------------------------------------------------------------------------

String PN5180MIFARE::debugAuth(const uint8_t key[6], uint8_t block, bool useKeyA) {
    String out = "{";

    loadISO14443Config();
    if (!activateRF()) { disableRF(); return "{\"err\":\"rf_on_fail\"}"; }
    delay(50);

    MifareTagInfo info;
    if (!detectTag(&info)) {
        disableRF();
        return "{\"err\":\"detect_fail\"}";
    }

    out += "\"uid\":\"";
    for (int i = 0; i < info.uidLen; i++) { if (i) out += " "; out += String(info.uid[i] < 16 ? "0" : "") + String(info.uid[i], HEX); }
    out += "\",\"sak\":\"" + String(info.sak, HEX) + "\"";

    // Build the command in the same order mfcAuthBlock does, print it, then send.
    uint8_t cmd[13];
    cmd[0] = 0x0C;
    memcpy(cmd + 1, key, 6);
    cmd[7] = useKeyA ? MFC_AUTH_KEY_A : MFC_AUTH_KEY_B;
    cmd[8] = block;
    memcpy(cmd + 9, info.uid, 4);

    out += ",\"cmd\":\"";
    for (int i = 0; i < 13; i++) { if (i) out += " "; out += String(cmd[i] < 16 ? "0" : "") + String(cmd[i], HEX); }
    out += "\"";

    // Re-enable hw CRC after detectTag disabled it (required for auth)
    orRegister(REG_CRC_TX_CONFIG, 0x01);
    orRegister(REG_CRC_RX_CONFIG, 0x01);
    out += ",\"crc_tx\":\"" + String(readRegister(REG_CRC_TX_CONFIG), HEX)
         + "\",\"crc_rx\":\"" + String(readRegister(REG_CRC_RX_CONFIG), HEX) + "\"";

    setIdle();
    clearIRQ();

    uint32_t syscfg_before = readRegister(REG_SYSTEM_CONFIG);
    bool sent = spiSend(cmd, sizeof(cmd));
    uint8_t status = 0xFF;
    bool got = false;
    if (sent) got = spiReceive(&status, 1);
    uint32_t syscfg_after = readRegister(REG_SYSTEM_CONFIG);
    uint32_t irq = readRegister(REG_IRQ_STATUS);

    out += ",\"sent\":" + String(sent ? "true" : "false")
         + ",\"got\":" + String(got ? "true" : "false")
         + ",\"status\":\"" + String(status, HEX) + "\""
         + ",\"syscfg_before\":\"" + String(syscfg_before, HEX) + "\""
         + ",\"syscfg_after\":\"" + String(syscfg_after, HEX) + "\""
         + ",\"crypto1_on\":" + String((syscfg_after & (1U << 6)) ? "true" : "false")
         + ",\"irq\":\"" + String(irq, HEX) + "\"";

    clearIRQ();
    disableRF();
    out += "}";
    Serial.println("[testauth] " + out);
    return out;
}

// ---------------------------------------------------------------------------
// ISO 14443A anti-collision + SELECT (single/double/triple cascade)
// Populates info->uid, info->uidLen, info->sak
// ---------------------------------------------------------------------------

bool PN5180MIFARE::detectTag(MifareTagInfo *info) {
    memset(info, 0, sizeof(MifareTagInfo));

    // Re-load ISO14443A config (resets CRC and all RX/TX parameters)
    loadISO14443Config();

    // SIGPRO_CONFIG (R1A): ISO14443A loads 0x04 (bit 2); ISO15693 loads 0x02 (bit 1).
    // This board has an inverted RF RX signal path (confirmed: ISO15693 requires bit 1 set).
    // Apply the same inversion to ISO14443A by replacing 0x04 with 0x02.
    writeRegister(0x1A, 0x02U);

    // Disable CRC for short frames / anticollision; clear any leftover Crypto1
    andRegister(REG_SYSTEM_CONFIG, 0xFFFFFFBFU); // clear CRYPTO1_ON (bit 6)
    andRegister(REG_CRC_RX_CONFIG, 0xFFFFFFFEU); // RX CRC off (bit 0)
    andRegister(REG_CRC_TX_CONFIG, 0xFFFFFFFEU); // TX CRC off (bit 0)

    Serial.printf("[14443] CRC_TX=0x%08X CRC_RX=0x%08X TX_CFG=0x%08X\n",
        readRegister(REG_CRC_TX_CONFIG), readRegister(REG_CRC_RX_CONFIG),
        readRegister(REG_TX_CONFIG));

    clearIRQ();         // flush any stale IRQ bits before starting transceive
    setIdle();
    activateTransceive();

    // WUPA: 7-bit short frame.  The SEND_DATA command's validBits byte (0x07)
    // specifies 7 valid bits in the last byte — no TX_CONFIG manipulation needed.
    uint8_t wupaBuf[3] = { PN5180_SEND_DATA, 0x07, WUPA };
    bool sent = spiSend(wupaBuf, sizeof(wupaBuf));
    if (!sent) { Serial.println("[14443] WUPA spiSend failed"); return false; }

    // Reference pattern: brief delay then check RX_STATUS (no IRQ poll)
    delay(5);
    uint32_t rxStatus = readRegister(REG_RX_STATUS);
    uint32_t irqVal   = readRegister(REG_IRQ_STATUS);
    uint8_t rlen = (uint8_t)(rxStatus & 0x1FF);
    Serial.printf("[14443] After WUPA: IRQ=0x%08X RX_STATUS=0x%08X rlen=%u\n",
        irqVal, rxStatus, rlen);
    clearIRQ();

    if (rlen < 2) {
        Serial.println("[14443] No ATQA received");
        return false;
    }

    uint8_t rdcmd[2] = { PN5180_READ_DATA, 0x00 };
    spiSend(rdcmd, sizeof(rdcmd));
    uint8_t atqa[2] = {0, 0};
    spiReceive(atqa, 2);

    info->atqa[0] = atqa[0];
    info->atqa[1] = atqa[1];
    Serial.printf("[14443] ATQA: %02X %02X\n", atqa[0], atqa[1]);

    uint8_t uidFull[10] = {0};
    uint8_t uidLen = 0;
    uint8_t sak = 0;
    uint8_t selCodes[] = { ANTICOLL1, ANTICOLL2, ANTICOLL3 };

    for (int level = 0; level < 3; level++) {
        // ANTICOLL: CRC is off (set at start, or disabled at bottom of previous iteration)
        uint8_t acCmd[2] = { selCodes[level], 0x20 };
        uint8_t acResp[5] = {0};
        uint8_t acRespLen = 0;
        if (!transceive14443(acCmd, 2, acResp, &acRespLen, 50)) {
            Serial.printf("[14443] ANTICOLL L%d failed\n", level);
            return false;
        }
        if (acRespLen < 5) {
            Serial.printf("[14443] ANTICOLL L%d short (%u)\n", level, acRespLen);
            return false;
        }

        bool hasCT = (acResp[0] == 0x88);
        Serial.printf("[14443] ANTICOLL L%d: %02X %02X %02X %02X %02X\n",
            level, acResp[0], acResp[1], acResp[2], acResp[3], acResp[4]);

        // SELECT requires CRC — appended manually (hardware CRC stays disabled)
        uint8_t selCmd[9];
        uint8_t selLen = 0;
        selCmd[selLen++] = selCodes[level];
        selCmd[selLen++] = 0x70;
        memcpy(selCmd + selLen, acResp, 5);
        selLen += 5;
        appendCRC16(selCmd, &selLen);

        uint8_t selResp[3] = {0};
        uint8_t selRespLen = 0;
        if (!transceive14443(selCmd, selLen, selResp, &selRespLen, 50)) {
            Serial.printf("[14443] SELECT L%d failed\n", level);
            return false;
        }
        if (selRespLen < 1) {
            Serial.printf("[14443] SELECT L%d empty response\n", level);
            return false;
        }

        sak = selResp[0];
        Serial.printf("[14443] SAK L%d: 0x%02X\n", level, sak);

        uint8_t *uidBytes = acResp + (hasCT ? 1 : 0);
        uint8_t copyCount = hasCT ? 3 : 4;
        memcpy(uidFull + uidLen, uidBytes, copyCount);
        uidLen += copyCount;

        if (!(sak & 0x04)) break; // No more cascade levels

    }
    // CRC_TX/RX remain disabled; all CRC is appended/verified manually below

    memcpy(info->uid, uidFull, uidLen);
    info->uidLen = uidLen;
    info->sak = sak;

    Serial.printf("[14443] UID (%uB):", uidLen);
    for (uint8_t i = 0; i < uidLen; i++) Serial.printf(" %02X", info->uid[i]);
    Serial.printf(" SAK=0x%02X\n", sak);

    // Per ISO/IEC 14443-3, bit 7 (0x80) of SAK is RFU/proprietary and must be
    // ignored for type discrimination. Some Infineon (SLE66) MIFARE Classic 1K
    // and many Chinese clones report SAK=0x88 instead of 0x08.
    uint8_t sakType = sak & 0x7F;
    if      (sakType == SAK_MFUL)          info->type = MIFARE_ULTRALIGHT;
    else if (sakType == SAK_MFC_MINI)      info->type = MIFARE_CLASSIC_MINI;
    else if (sakType == SAK_MFC_1K)        info->type = MIFARE_CLASSIC_1K;
    else if (sakType == SAK_MFC_4K)        info->type = MIFARE_CLASSIC_4K;
    else if (sakType == SAK_MFPLUS_SL1_2K) info->type = MIFARE_PLUS_SL1_2K;
    else if (sakType == SAK_MFPLUS_SL1_4K) info->type = MIFARE_PLUS_SL1_4K;
    else if (sakType == SAK_MFPLUS_SL2)    info->type = MIFARE_PLUS_SL2;
    else                                   info->type = MIFARE_UNKNOWN;

    switch (info->type) {
        case MIFARE_CLASSIC_1K:
        case MIFARE_PLUS_SL1_2K: info->blockCount = MFC_1K_BLOCKS; break;
        case MIFARE_CLASSIC_4K:
        case MIFARE_PLUS_SL1_4K: info->blockCount = MFC_4K_BLOCKS; break;
        case MIFARE_CLASSIC_MINI: info->blockCount = MFC_MINI_BLOCKS; break;
        case MIFARE_ULTRALIGHT: info->blockCount = MFUL_PAGES; break;
        default: info->blockCount = 0; break;
    }

    Serial.printf("[14443] Type: %s blocks: %u\n", typeString(info->type), info->blockCount);
    info->valid = true;
    return true;
}

bool PN5180MIFARE::reActivateCard(MifareTagInfo *info) {
    (void)info;

    disableRF();
    delay(15);
    if (!activateRF()) return false;
    delay(5);

    // Apply same SIGPRO_CONFIG inversion fix as detectTag()
    writeRegister(0x1A, 0x02U);

    // Disable CRC for WUPA + ANTICOLL, clear CRYPTO1
    andRegister(REG_CRC_TX_CONFIG, 0xFFFFFFFEU);
    andRegister(REG_CRC_RX_CONFIG, 0xFFFFFFFEU);
    andRegister(REG_SYSTEM_CONFIG, 0xFFFFFFBFU);

    clearIRQ();
    setIdle();
    activateTransceive();
    delay(2);

    uint8_t sendBuf[3] = { PN5180_SEND_DATA, 0x07, WUPA };
    bool raSent = spiSend(sendBuf, sizeof(sendBuf));
    if (!raSent) return false;

    unsigned long t = millis();
    while (!(readRegister(REG_IRQ_STATUS) & RX_IRQ_STAT)) {
        if (millis() - t > 30) {
            clearIRQ();
            Serial.println("[14443] reActivate: REQA timeout");
            return false;
        }
        delay(1);
    }

    uint32_t rxStatus = readRegister(REG_RX_STATUS);
    uint8_t rlen = (uint8_t)(rxStatus & 0x1FF);
    if (rlen >= 2) {
        uint8_t rcmd[2] = { PN5180_READ_DATA, 0x00 };
        spiSend(rcmd, sizeof(rcmd));
        uint8_t atqa[2];
        spiReceive(atqa, 2);
    }
    clearIRQ();

    uint8_t acCmd[2] = { ANTICOLL1, 0x20 };
    uint8_t acResp[5] = {0};
    uint8_t acRespLen = 0;
    if (!transceive14443(acCmd, 2, acResp, &acRespLen, 50) || acRespLen < 5) {
        Serial.println("[14443] reActivate: ANTICOLL failed");
        return false;
    }

    uint8_t selCmd[9];
    uint8_t selLen = 0;
    selCmd[selLen++] = SELECT1;
    selCmd[selLen++] = 0x70;
    memcpy(selCmd + selLen, acResp, 5);
    selLen += 5;
    appendCRC16(selCmd, &selLen);

    uint8_t selResp[3] = {0};
    uint8_t selRespLen = 0;
    bool ok = transceive14443(selCmd, selLen, selResp, &selRespLen, 50) && (selRespLen >= 1);
    Serial.printf("[14443] reActivate: %s\n", ok ? "OK" : "FAILED");
    return ok;
}

// After a failed auth the card goes to IDLE state but the RF field is still on.
// Skip the RF off/on cycle — just WUPA + ANTICOLL + SELECT (~30ms vs ~120ms).
bool PN5180MIFARE::reSelectCard(MifareTagInfo *info) {
    writeRegister(0x1A, 0x02U);
    andRegister(REG_CRC_TX_CONFIG, 0xFFFFFFFEU);
    andRegister(REG_CRC_RX_CONFIG, 0xFFFFFFFEU);
    andRegister(REG_SYSTEM_CONFIG, 0xFFFFFFBFU);  // CRYPTO1 off

    clearIRQ();
    setIdle();
    activateTransceive();
    delay(2);

    uint8_t sendBuf[3] = { PN5180_SEND_DATA, 0x07, WUPA };
    if (!spiSend(sendBuf, sizeof(sendBuf))) return false;

    unsigned long t = millis();
    while (!(readRegister(REG_IRQ_STATUS) & RX_IRQ_STAT)) {
        if (millis() - t > 20) {
            clearIRQ();
            // Card may have gone fully silent — fall back to RF cycle
            return reActivateCard(info);
        }
        delay(1);
    }

    uint32_t rxStatus = readRegister(REG_RX_STATUS);
    uint8_t rlen = (uint8_t)(rxStatus & 0x1FF);
    if (rlen >= 2) {
        uint8_t rcmd[2] = { PN5180_READ_DATA, 0x00 };
        spiSend(rcmd, sizeof(rcmd));
        uint8_t atqa[2];
        spiReceive(atqa, 2);
    }
    clearIRQ();

    uint8_t acCmd[2] = { ANTICOLL1, 0x20 };
    uint8_t acResp[5] = {0};
    uint8_t acRespLen = 0;
    if (!transceive14443(acCmd, 2, acResp, &acRespLen, 50) || acRespLen < 5) {
        return reActivateCard(info);  // fallback
    }

    uint8_t selCmd[9];
    uint8_t selLen = 0;
    selCmd[selLen++] = SELECT1;
    selCmd[selLen++] = 0x70;
    memcpy(selCmd + selLen, acResp, 5);
    selLen += 5;
    appendCRC16(selCmd, &selLen);

    uint8_t selResp[3] = {0};
    uint8_t selRespLen = 0;
    return transceive14443(selCmd, selLen, selResp, &selRespLen, 50) && (selRespLen >= 1);
}

// ---------------------------------------------------------------------------
// HALT
// ---------------------------------------------------------------------------

bool PN5180MIFARE::haltTag() {
    uint8_t cmd[4] = { HALT_CMD, 0x00 };
    uint8_t len = 2;
    appendCRC16(cmd, &len);
    uint8_t resp[4];
    uint8_t respLen = 0;
    transceive14443(cmd, len, resp, &respLen, 10);  // HALT gets no response — OK
    return true;
}

// ---------------------------------------------------------------------------
// MIFARE Classic authentication
// ---------------------------------------------------------------------------

bool PN5180MIFARE::mfcAuthBlock(MifareTagInfo *info, uint8_t block, uint8_t *key, bool useKeyA) {
    // PN5180 datasheet §11.4.3.13 Table 25 MIFARE_AUTHENTICATE payload:
    //   CMD(0x0C) | KEY[6] | KEY_TYPE(0x60/0x61) | BLOCK_ADDRESS | UID[4]
    // Return value is a single status byte:
    //   0x00 = authentication OK
    //   0x01 = authentication failed (wrong key / permission denied)
    //   0x02 = timeout (no card response)
    g_progPhase    = 2;          // authenticating
    g_progCurBlock = block;
    g_progKeyType  = useKeyA ? 0 : 1;

    uint8_t authCmd[13];
    authCmd[0] = 0x0C;
    memcpy(authCmd + 1, key, 6);
    authCmd[7] = useKeyA ? MFC_AUTH_KEY_A : MFC_AUTH_KEY_B;
    authCmd[8] = block;
    memcpy(authCmd + 9, info->uid, 4);

    // MIFARE_AUTHENTICATE runs the full auth protocol internally and expects
    // hardware CRC to be enabled. detectTag() disables CRC for REQA/anticoll
    // (short/bit-oriented frames) — turn it back on before auth or the card
    // will see a malformed frame and the chip reports status=0x02 (timeout).
    orRegister(REG_CRC_TX_CONFIG, 0x01);
    orRegister(REG_CRC_RX_CONFIG, 0x01);

    // Put the chip into a known IDLE state so any residual transceive /
    // Crypto1 context from a previous failed attempt doesn't taint this one.
    setIdle();
    clearIRQ();
    if (g_irqSem) xSemaphoreTake(g_irqSem, 0);  // drain any stale ISR signal

    // spiSend() waits for BUSY LOW after the command, so by the time it
    // returns, the chip has finished the auth cycle and the 1-byte status
    // is sitting in its response buffer.
    if (!spiSend(authCmd, sizeof(authCmd))) {
        Serial.printf("[MFC] Auth spiSend fail block=%u\n", block);
        return false;
    }

    // Read the 1-byte authentication status from the chip.
    uint8_t status = 0xFF;
    if (!spiReceive(&status, 1)) {
        Serial.printf("[MFC] Auth spiReceive fail block=%u\n", block);
        return false;
    }

    bool ok = (status == 0x00);
    if (ok) {
        Serial.printf("[MFC] Auth block=%u key=%c OK\n", block, useKeyA ? 'A' : 'B');
    } else {
        // status 0x01 = wrong key, 0x02 = card timeout
        Serial.printf("[MFC] Auth block=%u key=%c FAIL status=0x%02X\n",
            block, useKeyA ? 'A' : 'B', status);
    }
    return ok;
}

bool PN5180MIFARE::mfcReadBlock(uint8_t block, uint8_t *out16) {
    g_progPhase    = 3;          // reading
    g_progCurBlock = block;

    // HW CRC is enabled after mfcAuthBlock, so the chip appends CRC_A on TX
    // and validates + strips it on RX. We just send the 2-byte command and
    // expect 16 data bytes back (Crypto1 is transparent to the host).
    uint8_t cmd[2] = { MFC_READ, block };

    uint8_t resp[20];
    uint8_t respLen = 0;
    if (!transceiveInAuth(cmd, 2, resp, &respLen, 120)) {
        Serial.printf("[MFC] Read block %u: RX timeout/fail\n", block);
        return false;
    }
    if (respLen < 16) {
        Serial.printf("[MFC] Read block %u: short resp %u\n", block, respLen);
        return false;
    }
    memcpy(out16, resp, 16);
    return true;
}

// ---------------------------------------------------------------------------
// Dictionary loading
// ---------------------------------------------------------------------------

// static — pure SPIFFS parser, no hardware access
int PN5180MIFARE::loadKeysFromFile(const char *path, uint8_t (*keys)[6], int maxKeys) {
    if (!path) return 0;
    File f = SPIFFS.open(path, "r");
    if (!f) return 0;

    int count = 0;
    while (f.available() && count < maxKeys) {
        String line = f.readStringUntil('\n');
        line.trim();
        if (line.length() < 12) continue;
        // Parse 6 hex bytes
        bool ok = true;
        for (int i = 0; i < 6; i++) {
            char hex[3] = { line[i*2], line[i*2+1], 0 };
            char *end;
            keys[count][i] = (uint8_t)strtol(hex, &end, 16);
            if (*end != '\0') { ok = false; break; }
        }
        if (ok) count++;
    }
    f.close();
    return count;
}

// ---------------------------------------------------------------------------
// MIFARE Classic full read
// ---------------------------------------------------------------------------

// Default keys always tried first
static const uint8_t DEFAULT_KEYS[][6] = {
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
    { 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5 },
    { 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5 },
    { 0x4D, 0x3A, 0x99, 0xC3, 0x51, 0xDD },
    { 0x1A, 0x98, 0x2C, 0x7E, 0x45, 0x9A },
    { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    { 0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7 },
};
#define NUM_DEFAULT_KEYS (sizeof(DEFAULT_KEYS) / sizeof(DEFAULT_KEYS[0]))

// Max keys loaded from a single file — also defined in PN5180MIFARE.h as constexpr
#undef MAX_DICT_KEYS  // avoid duplicate if included transitively

bool PN5180MIFARE::mfcReadAllBlocks(MifareTagInfo *info,
                                     uint8_t (*keys1)[6], int n1,
                                     uint8_t (*keys2)[6], int n2) {
    uint8_t ns = totalSectors(info->type);
    Serial.printf("[MFC] Reading %u sectors (dict1=%d dict2=%d)\n", ns, n1, n2);
    bool anyRead = false;

    // Key reuse: track the key that last succeeded; try it first on each new sector.
    // Cards typically use the same key(s) for all sectors — this turns an O(keys×sectors)
    // worst-case into ~O(sectors) once the first sector key is found.
    uint8_t reuseKey[6] = {0};
    bool    reuseKeyA   = true;
    bool    hasReuseKey = false;

    // Helper: try one key (both A and B) against the sector trailer block.
    // Returns true and sets useA/goodKey on match; calls reSelectCard on fail.
    auto tryKey = [&](uint8_t *key, bool &authOk, bool &useA,
                      uint8_t *goodKey, bool &abort, uint8_t trailer) {
        for (int ab = 0; ab < 2 && !authOk && !abort; ab++) {
            if (g_readCancel) { abort = true; return; }
            if (mfcAuthBlock(info, trailer, key, ab == 0)) {
                authOk = true;
                useA = (ab == 0);
                memcpy(goodKey, key, 6);
            } else {
                if (!reSelectCard(info)) abort = true;
            }
        }
    };

    for (uint8_t s = 0; s < ns; s++) {
        if (g_readCancel) { Serial.println("[MFC] Cancelled"); break; }
        uint8_t trailerBlock = sectorTrailerBlock(info->type, s);
        bool authOk = false;
        bool useA   = true;
        bool abort  = false;
        uint8_t goodKey[6];

        // 1. Try the key that worked last time (very fast path for uniform-key cards)
        if (hasReuseKey && !authOk && !abort) {
            if (mfcAuthBlock(info, trailerBlock, reuseKey, reuseKeyA)) {
                authOk = true;
                useA = reuseKeyA;
                memcpy(goodKey, reuseKey, 6);
            } else {
                if (!reSelectCard(info)) abort = true;
                // also try the other key type
                if (!abort && !authOk) {
                    if (mfcAuthBlock(info, trailerBlock, reuseKey, !reuseKeyA)) {
                        authOk = true;
                        useA = !reuseKeyA;
                        memcpy(goodKey, reuseKey, 6);
                    } else {
                        if (!reSelectCard(info)) abort = true;
                    }
                }
            }
        }

        // 2. Default keys
        for (int ki = 0; ki < (int)NUM_DEFAULT_KEYS && !authOk && !abort; ki++)
            tryKey((uint8_t*)DEFAULT_KEYS[ki], authOk, useA, goodKey, abort, trailerBlock);

        // 3. Caller-supplied dict file 1
        for (int ki = 0; ki < n1 && !authOk && !abort; ki++)
            tryKey(keys1[ki], authOk, useA, goodKey, abort, trailerBlock);

        // 4. Caller-supplied dict file 2
        for (int ki = 0; ki < n2 && !authOk && !abort; ki++)
            tryKey(keys2[ki], authOk, useA, goodKey, abort, trailerBlock);

        if (abort) { info->keyUsed[s] = 0; continue; }
        if (!authOk) {
            Serial.printf("[MFC] Sector %u: no key found\n", s);
            info->keyUsed[s] = 0;
            continue;
        }

        // Cache for next sector
        memcpy(reuseKey, goodKey, 6);
        reuseKeyA   = useA;
        hasReuseKey = true;

        info->keyUsed[s] = useA ? 1 : 2;
        uint8_t first = sectorFirstBlock(info->type, s);
        uint8_t count = sectorBlockCount(info->type, s);
        Serial.printf("[MFC] Sector %u: auth OK key=%c blocks=%u..%u\n",
            s, useA ? 'A' : 'B', first, (uint8_t)(first + count - 1));

        for (uint8_t b = first; b < first + count; b++) {
            uint8_t tmp[16];
            if (mfcReadBlock(b, tmp)) {
                memcpy(info->data + b * 16, tmp, 16);
                info->blockRead[b] = true;
                anyRead = true;
            } else {
                // Transceive error mid-read: re-activate and retry once
                if (reActivateCard(info) && mfcAuthBlock(info, trailerBlock, goodKey, useA)) {
                    if (mfcReadBlock(b, tmp)) {
                        memcpy(info->data + b * 16, tmp, 16);
                        info->blockRead[b] = true;
                        anyRead = true;
                    }
                }
            }
        }
    }

    Serial.printf("[MFC] Read complete anyRead=%d\n", anyRead ? 1 : 0);
    return anyRead;
}

// ---------------------------------------------------------------------------
// MIFARE Ultralight read
// ---------------------------------------------------------------------------

bool PN5180MIFARE::mfulReadPage(uint8_t page, uint8_t *out4) {
    uint8_t cmd[4];
    uint8_t len = 0;
    cmd[len++] = MFUL_READ;
    cmd[len++] = page;
    appendCRC16(cmd, &len);

    uint8_t resp[18];
    uint8_t respLen = 0;
    if (!transceive14443(cmd, len, resp, &respLen)) return false;
    // MFUL READ returns 16 bytes (4 pages x 4 bytes) + 2 CRC
    if (respLen < 6) return false;
    if (!checkCRC16(resp, respLen)) return false;
    memcpy(out4, resp, 4);  // only first page requested
    return true;
}

bool PN5180MIFARE::mfulReadAllPages(MifareTagInfo *info) {
    bool anyRead = false;
    for (uint8_t p = 0; p < info->blockCount; p++) {
        uint8_t tmp[4];
        if (mfulReadPage(p, tmp)) {
            memcpy(info->data + p * 4, tmp, 4);
            info->blockRead[p] = true;
            anyRead = true;
        }
    }
    return anyRead;
}

// ---------------------------------------------------------------------------
// Top-level readTag
// ---------------------------------------------------------------------------

bool PN5180MIFARE::readTag(MifareTagInfo *info, const char *dictPath1, const char *dictPath2) {
    Serial.println("[14443] readTag start");
    if (!loadISO14443Config()) {
        Serial.println("[14443] loadISO14443Config FAILED");
        return false;
    }
    if (!activateRF()) {
        Serial.println("[14443] activateRF FAILED");
        return false;
    }
    delay(50);

    if (!detectTag(info)) {
        Serial.println("[14443] detectTag failed");
        disableRF();
        return false;
    }

    Serial.printf("[MFC] Detected %s UID:", typeString(info->type));
    for (int i = 0; i < info->uidLen; i++) Serial.printf(" %02X", info->uid[i]);
    Serial.printf(" SAK=0x%02X blocks=%d\n", info->sak, info->blockCount);

    bool ok = false;
    switch (info->type) {
        case MIFARE_CLASSIC_1K:
        case MIFARE_CLASSIC_4K:
        case MIFARE_CLASSIC_MINI:
        case MIFARE_PLUS_SL1_2K:
        case MIFARE_PLUS_SL1_4K: {
            static uint8_t dk1[MAX_DICT_KEYS][6];
            static uint8_t dk2[MAX_DICT_KEYS][6];
            // Keys should ideally be pre-loaded before RF activation; loading here is
            // a fallback for callers that use the single-call readTag() API.
            int n1 = loadKeysFromFile(dictPath1, dk1, MAX_DICT_KEYS);
            int n2 = loadKeysFromFile(dictPath2, dk2, MAX_DICT_KEYS);
            reActivateCard(info);  // card may have idled during SPIFFS load
            ok = mfcReadAllBlocks(info, dk1, n1, dk2, n2);
            break;
        }
        case MIFARE_ULTRALIGHT:
            ok = mfulReadAllPages(info);
            break;
        default:
            Serial.println("[MFC] Unknown/unsupported type");
            break;
    }

    haltTag();
    disableRF();
    return ok || info->valid;
}

// ---------------------------------------------------------------------------
// Sector layout helpers
// ---------------------------------------------------------------------------

uint8_t PN5180MIFARE::blockToSector(MifareType type, uint8_t block) {
    if (type == MIFARE_CLASSIC_4K || type == MIFARE_PLUS_SL1_4K) {
        if (block < 128) return block / 4;
        return 32 + (block - 128) / 16;
    }
    return block / 4;
}

uint8_t PN5180MIFARE::sectorFirstBlock(MifareType type, uint8_t sector) {
    if ((type == MIFARE_CLASSIC_4K || type == MIFARE_PLUS_SL1_4K) && sector >= 32) {
        return 128 + (sector - 32) * 16;
    }
    return sector * 4;
}

uint8_t PN5180MIFARE::sectorBlockCount(MifareType type, uint8_t sector) {
    if ((type == MIFARE_CLASSIC_4K || type == MIFARE_PLUS_SL1_4K) && sector >= 32) {
        return 16;
    }
    return 4;
}

uint8_t PN5180MIFARE::sectorTrailerBlock(MifareType type, uint8_t sector) {
    return sectorFirstBlock(type, sector) + sectorBlockCount(type, sector) - 1;
}

uint8_t PN5180MIFARE::totalSectors(MifareType type) {
    switch (type) {
        case MIFARE_CLASSIC_1K:
        case MIFARE_PLUS_SL1_2K:  return 16;
        case MIFARE_CLASSIC_4K:
        case MIFARE_PLUS_SL1_4K:  return 40;
        case MIFARE_CLASSIC_MINI: return 5;
        default: return 0;
    }
}

const char *PN5180MIFARE::typeString(MifareType t) {
    switch (t) {
        case MIFARE_CLASSIC_1K:   return "MFC1K";
        case MIFARE_CLASSIC_4K:   return "MFC4K";
        case MIFARE_CLASSIC_MINI: return "MFCMINI";
        case MIFARE_ULTRALIGHT:   return "MFUL";
        case MIFARE_PLUS_SL1_2K:  return "MFPLUS2K";
        case MIFARE_PLUS_SL1_4K:  return "MFPLUS4K";
        case MIFARE_PLUS_SL2:     return "MFPLUS_SL2";
        default:                  return "UNKNOWN";
    }
}

// ===========================================================================
// Card identification / clone fingerprinting
// ---------------------------------------------------------------------------
// Port of proxmark3's `hf mf info` (armsrc/mifarecmd.c::MifareCIdent and
// client/src/mifare/mifarehost.c::detect_mf_magic + cmdhfmf.c fingerprint
// table). PN5180 cannot expose the raw Crypto1 nonce stream, so static-nonce
// and PRNG-weakness checks are intentionally omitted.
// ===========================================================================

namespace {

// Append "0x" + uppercase hex bytes to a String, space-separated.
static void appendHexBytes(String &s, const uint8_t *p, uint8_t n, bool spaces = true) {
    char buf[4];
    for (uint8_t i = 0; i < n; i++) {
        if (spaces && i) s += ' ';
        snprintf(buf, sizeof(buf), "%02X", p[i]);
        s += buf;
    }
}

static String jsonHexBytes(const uint8_t *p, uint8_t n) {
    String s = "\"";
    appendHexBytes(s, p, n, true);
    s += "\"";
    return s;
}

// Backdoor keys discovered by the proxmark community (cmdhfmf.c).
struct BackdoorKey {
    uint8_t     key[6];
    const char *name;
};
static const BackdoorKey kBackdoorKeys[] = {
    { {0xA3, 0x96, 0xEF, 0xA4, 0xE2, 0x4F}, "RF08S"      },
    { {0xA3, 0x16, 0x67, 0xA8, 0xCE, 0xC1}, "RF08"       },
    { {0x51, 0x8B, 0x33, 0x54, 0xE7, 0x60}, "RF32N"      },
    { {0x73, 0xB9, 0x83, 0x6C, 0xF1, 0x68}, "RF32N-alt"  },
};

}  // namespace

String PN5180MIFARE::identCard() {
    String out = "{";

    // ── 1. RF up + initial detect ─────────────────────────────────────────
    loadISO14443Config();
    if (!activateRF()) {
        return "{\"err\":\"rf_on_fail\"}";
    }
    delay(50);

    MifareTagInfo info;
    if (!detectTag(&info)) {
        disableRF();
        return "{\"err\":\"no_tag\"}";
    }

    out += "\"uid\":\"";
    appendHexBytes(out, info.uid, info.uidLen, false);
    out += "\",\"sak\":\"";
    char sakStr[3];
    snprintf(sakStr, sizeof(sakStr), "%02X", info.sak);
    out += sakStr;
    out += "\",\"atqa\":\"";
    char atqaStr[5];
    snprintf(atqaStr, sizeof(atqaStr), "%02X%02X", info.atqa[1], info.atqa[0]);
    out += atqaStr;
    out += "\",\"type\":\"";
    out += typeString(info.type);
    out += "\"";

    // Helper lambdas for RF reset between probes
    auto resetField = [this]() {
        disableRF();
        delay(15);
        activateRF();
        delay(20);
        loadISO14443Config();
        writeRegister(0x1A, 0x02U);
    };
    auto resetAndSelect = [this, &resetField](MifareTagInfo *i) -> bool {
        resetField();
        return detectTag(i);
    };

    // Send a short frame (any bit count) on a fresh field, no SELECT.
    // Returns true and fills resp/respLen if the card replied.
    auto shortFrame = [this](uint8_t cmdByte, uint8_t bits,
                              uint8_t *resp, uint8_t *respLen) -> bool {
        andRegister(REG_CRC_TX_CONFIG, 0xFFFFFFFEU);
        andRegister(REG_CRC_RX_CONFIG, 0xFFFFFFFEU);
        andRegister(REG_SYSTEM_CONFIG, 0xFFFFFFBFU);
        clearIRQ();
        setIdle();
        activateTransceive();

        uint8_t buf[3] = { PN5180_SEND_DATA, bits, cmdByte };
        if (!spiSend(buf, sizeof(buf))) return false;

        delay(5);
        uint32_t rxStatus = readRegister(REG_RX_STATUS);
        uint8_t rlen = (uint8_t)(rxStatus & 0x1FF);
        clearIRQ();
        if (rlen == 0) { *respLen = 0; return false; }
        if (rlen > 32) rlen = 32;

        uint8_t rc[2] = { PN5180_READ_DATA, 0x00 };
        spiSend(rc, sizeof(rc));
        if (!spiReceive(resp, rlen)) { *respLen = 0; return false; }
        *respLen = rlen;
        return true;
    };

    String magic;     // comma-separated list, JSON-array assembled at end
    auto pushMagic = [&magic](const char *s) {
        if (magic.length()) magic += ',';
        magic += '"';
        magic += s;
        magic += '"';
    };

    // ── 2. Gen 1A / 1B magic wakeup ───────────────────────────────────────
    {
        resetField();
        uint8_t r[8] = {0};
        uint8_t rlen = 0;
        if (shortFrame(0x40, 0x07, r, &rlen) && rlen >= 1 && (r[0] & 0x0F) == 0x0A) {
            // Card answered the magic wakeup — send full-byte 0x43
            uint8_t r2[8] = {0};
            uint8_t rl2 = 0;
            bool ack2 = shortFrame(0x43, 0x00, r2, &rl2) && rl2 >= 1 && (r2[0] & 0x0F) == 0x0A;
            pushMagic(ack2 ? "Gen 1A" : "Gen 1B");
        }
    }

    // ── 3. Gen 3 magic (raw read block 0 without auth) ────────────────────
    {
        if (resetAndSelect(&info)) {
            uint8_t cmd[4] = { 0x30, 0x00, 0x02, 0xA8 };  // READ blk0 + CRC
            uint8_t resp[20] = {0};
            uint8_t rl = 0;
            if (transceive14443(cmd, 4, resp, &rl, 50) && rl == 18) {
                pushMagic("Gen 3 / APDU");
            }
        }
    }

    // ── 4. Gen 4 GTU (vendor get-config with default password 0) ──────────
    {
        if (resetAndSelect(&info)) {
            uint8_t cmd[8] = { 0xCF, 0x00, 0x00, 0x00, 0x00, 0xC6, 0x00, 0x00 };
            uint8_t l = 6;
            appendCRC16(cmd, &l);
            uint8_t resp[40] = {0};
            uint8_t rl = 0;
            if (transceive14443(cmd, 8, resp, &rl, 80) && (rl == 32 || rl == 34)) {
                pushMagic("Gen 4 GTU");
            }
        }
    }

    // ── 5. Gen 4 GDM / USCUID magic auth (80 00 6C 92) ────────────────────
    {
        if (resetAndSelect(&info)) {
            uint8_t cmd[4] = { 0x80, 0x00, 0x6C, 0x92 };
            uint8_t resp[8] = {0};
            uint8_t rl = 0;
            if (transceive14443(cmd, 4, resp, &rl, 50) && rl == 4) {
                pushMagic("Gen 4 GDM / USCUID");
            }
        }
    }

    // ── 6. Super Card Gen1/Gen2 ───────────────────────────────────────────
    {
        if (resetAndSelect(&info)) {
            uint8_t cmd[9] = { 0x0A, 0x00, 0x00, 0xA6, 0xB0, 0x00, 0x10, 0x14, 0x1D };
            uint8_t resp[32] = {0};
            uint8_t rl = 0;
            if (transceive14443(cmd, 9, resp, &rl, 80) && rl == 22) {
                pushMagic("Super Card Gen 1");
                // Optional Gen2 follow-up: read block 0 after re-select
                if (resetAndSelect(&info)) {
                    uint8_t rd[4] = { 0x30, 0x00, 0x02, 0xA8 };
                    uint8_t r2[20] = {0};
                    uint8_t rl2 = 0;
                    if (transceive14443(rd, 4, r2, &rl2, 50) && rl2 == 18) {
                        pushMagic("Super Card Gen 2");
                    }
                }
            }
        }
    }

    // ── 7. FUID (UID == AA 55 C3 96) ──────────────────────────────────────
    if (info.uidLen >= 4 &&
        info.uid[0] == 0xAA && info.uid[1] == 0x55 &&
        info.uid[2] == 0xC3 && info.uid[3] == 0x96) {
        pushMagic("FUID / Write Once");
    }

    // ── 8. Gen 2 / CUID — auth + WRITEBLOCK(0) ACK probe ──────────────────
    // Safe: we send only the 4-byte WRITE command. A magic Gen2 card returns
    // a 4-bit ACK (0x0A) before expecting 16 bytes of data. We immediately
    // power off the RF so no actual write can ever occur.
    {
        if (resetAndSelect(&info)) {
            uint8_t defKey[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
            if (mfcAuthBlock(&info, 0, defKey, true)) {
                uint8_t wcmd[2] = { MFC_WRITE, 0x00 };
                uint8_t wresp[8] = {0};
                uint8_t wrl = 0;
                bool ack = transceiveInAuth(wcmd, 2, wresp, &wrl, 80) &&
                           wrl >= 1 && (wresp[0] & 0x0F) == 0x0A;
                // Cut RF before any data phase can happen
                disableRF();
                delay(20);
                if (ack) pushMagic("Gen 2 / CUID");
            }
        }
    }

    // ── 9. Backdoor key auth (RF08/RF08S/RF32N) on sector 0 key B ─────────
    int  bdKeyIdx     = -1;
    bool bdBlock0Read = false;
    uint8_t bdBlock0[16] = {0};
    for (size_t k = 0; k < sizeof(kBackdoorKeys) / sizeof(kBackdoorKeys[0]); k++) {
        if (!resetAndSelect(&info)) break;
        uint8_t key[6];
        memcpy(key, kBackdoorKeys[k].key, 6);
        if (mfcAuthBlock(&info, 0, key, false)) {
            bdKeyIdx = (int)k;
            if (mfcReadBlock(0, bdBlock0)) bdBlock0Read = true;
            break;
        }
    }

    // If no backdoor matched, try a default-key read of block 0 for fingerprint
    bool block0Read = bdBlock0Read;
    uint8_t block0[16] = {0};
    if (bdBlock0Read) {
        memcpy(block0, bdBlock0, 16);
    } else if (resetAndSelect(&info)) {
        uint8_t defKey[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
        if (mfcAuthBlock(&info, 0, defKey, true) && mfcReadBlock(0, block0)) {
            block0Read = true;
        }
    }

    // ── 10. Block-0 + SAK fingerprint table (port of cmdhfmf.c) ───────────
    const char *fingerprint = nullptr;
    if (block0Read) {
        const uint8_t *b   = block0;
        uint8_t        sak = info.sak;

        bool isBdRF08S = (bdKeyIdx == 0);
        bool isBdRF08  = (bdKeyIdx == 1);
        bool isBdRF32  = (bdKeyIdx == 2);
        bool isBdRF32a = (bdKeyIdx == 3);

        if (sak != 0x20 && memcmp(b + 8, "\x62\x63\x64\x65\x66\x67\x68\x69", 8) == 0) {
            fingerprint = "Fudan-based clone";
        } else if (isBdRF08S && sak == 0x08 && memcmp(b + 5, "\x08\x04\x00", 3) == 0
                   && (b[8] == 0x03 || b[8] == 0x04 || b[8] == 0x05) && b[15] == 0x90) {
            fingerprint = "Fudan FM11RF08S";
        } else if (isBdRF08S && sak == 0x08 && memcmp(b + 5, "\x08\x04\x00", 3) == 0
                   && (b[8] == 0x03 || b[8] == 0x04) && b[15] == 0x91) {
            fingerprint = "Fudan FM11RF08 (advanced verification)";
        } else if (isBdRF08S && sak == 0x08 && memcmp(b + 5, "\x00\x03\x00\x10", 4) == 0
                   && b[15] == 0x90) {
            fingerprint = "Fudan FM11RF08S-7B";
        } else if (isBdRF08 && sak == 0x08 && memcmp(b + 5, "\x08\x04\x00", 3) == 0
                   && (b[8] == 0x04 || b[8] == 0x05) && b[15] == 0x98) {
            fingerprint = "Fudan FM11RF08S";
        } else if (isBdRF08 && sak == 0x08 && memcmp(b + 5, "\x08\x04\x00", 3) == 0
                   && (b[8] >= 0x01 && b[8] <= 0x03) && b[15] == 0x1D) {
            fingerprint = "Fudan FM11RF08";
        } else if (isBdRF08 && sak == 0x08 && memcmp(b + 5, "\x00\x01\x00\x10", 4) == 0
                   && b[15] == 0x1D) {
            fingerprint = "Fudan FM11RF08-7B";
        } else if (isBdRF32 && sak == 0x18
                   && memcmp(b + 5, "\x18\x02\x00\x46\x44\x53\x37\x30\x56\x30\x31", 11) == 0) {
            fingerprint = "Fudan FM11RF32N";
        } else if (isBdRF32a && sak == 0x18
                   && memcmp(b + 5, "\x18\x02\x00\x46\x44\x53\x37\x30\x56\x30\x31", 11) == 0) {
            fingerprint = "Fudan FM11RF32N (variant)";
        } else if (isBdRF08 && sak == 0x19
                   && memcmp(b + 8, "\x69\x44\x4C\x4B\x56\x32\x01\x92", 8) == 0) {
            fingerprint = "Fudan-based iDTRONICS IDT M1K (SAK=19)";
        } else if (isBdRF08 && sak == 0x20
                   && memcmp(b + 8, "\x62\x63\x64\x65\x66\x67\x68\x69", 8) == 0) {
            fingerprint = "Fudan FM11RF32 (SAK=20)";
        } else if (isBdRF08 && sak == 0x28
                   && ((memcmp(b + 5, "\x28\x04\x00\x90\x10\x15\x01\x00\x00\x00\x00", 11) == 0) ||
                       (memcmp(b + 5, "\x28\x04\x00\x90\x11\x15\x01\x00\x00\x00\x00", 11) == 0))) {
            fingerprint = "Fudan FM1208-10";
        } else if (isBdRF08 && sak == 0x28
                   && memcmp(b + 5, "\x28\x04\x00\x90\x93\x56\x09\x00\x00\x00\x00", 11) == 0) {
            fingerprint = "Fudan FM1216-110";
        } else if (isBdRF08 && sak == 0x28
                   && memcmp(b + 5, "\x28\x04\x00\x90\x53\xB7\x0C\x00\x00\x00\x00", 11) == 0) {
            fingerprint = "Fudan FM1216-137";
        } else if (isBdRF08 && sak == 0x88 && memcmp(b + 5, "\x88\x04\x00\x43", 4) == 0) {
            fingerprint = "Infineon SLE66R35";
        } else if (isBdRF08 && sak == 0x08 && memcmp(b + 5, "\x88\x04\x00\x44", 4) == 0) {
            fingerprint = "NXP MF1ICS5003";
        } else if (isBdRF08 && sak == 0x08 && memcmp(b + 5, "\x88\x04\x00\x45", 4) == 0) {
            fingerprint = "NXP MF1ICS5004";
        } else if (bdKeyIdx >= 0) {
            fingerprint = "Unknown card with backdoor (please report)";
        } else if (sak == 0x08 && memcmp(b + 5, "\x88\x04\x00\x46", 4) == 0) {
            fingerprint = "NXP MF1ICS5005";
        } else if (sak == 0x08 && memcmp(b + 5, "\x88\x04\x00\x47", 4) == 0) {
            fingerprint = "NXP MF1ICS5006";
        } else if (sak == 0x09 && memcmp(b + 5, "\x89\x04\x00\x47", 4) == 0) {
            fingerprint = "NXP MF1ICS2006";
        } else if (sak == 0x08 && memcmp(b + 5, "\x88\x04\x00\x48", 4) == 0) {
            fingerprint = "NXP MF1ICS5007";
        } else if (sak == 0x08 && memcmp(b + 5, "\x88\x04\x00\xC0", 4) == 0) {
            fingerprint = "NXP MF1ICS5035";
        }
    }

    // ── Assemble JSON ─────────────────────────────────────────────────────
    out += ",\"magic\":[" + magic + "]";

    if (bdKeyIdx >= 0) {
        out += ",\"backdoor\":{\"name\":\"";
        out += kBackdoorKeys[bdKeyIdx].name;
        out += "\",\"key\":\"";
        appendHexBytes(out, kBackdoorKeys[bdKeyIdx].key, 6, false);
        out += "\"}";
    }

    if (block0Read) {
        out += ",\"block0\":";
        out += jsonHexBytes(block0, 16);
    }

    if (fingerprint) {
        out += ",\"fingerprint\":\"";
        out += fingerprint;
        out += "\"";
    }

    haltTag();
    disableRF();
    out += "}";
    Serial.println("[ident] " + out);
    return out;
}

// ===========================================================================
// WRITE SUPPORT — standard MFC/MFUL + magic card variants
// ---------------------------------------------------------------------------
// Port of proxmark3 mifarecmd.c {MifareCSetBlock, MifareGen3UID/Blk/Freez,
// MifareG4WriteBlk, MifareCIdent} adapted to the PN5180 SPI primitives.
//
// Phase value 4 is reserved for "writing" so the web UI can distinguish
// auth (2) / read (3) / write (4) progress phases.
// ===========================================================================

// ---------------------------------------------------------------------------
// Standard MIFARE Classic WRITE (cmd 0xA0)
// ---------------------------------------------------------------------------
// 14443A WRITE is two-phase:
//   1. PCD → PICC: WRITE 0xA0 + blockNo + CRC (HW)   ← PICC ack 0x0A
//   2. PCD → PICC: 16 data bytes + CRC (HW)          ← PICC ack 0x0A
// HW CRC must be enabled (mfcAuthBlock leaves it on; for Gen1 path we enable
// it explicitly after the magic wakeup).
bool PN5180MIFARE::mfcWriteBlock(uint8_t block, const uint8_t *data16) {
    g_progPhase    = 4;          // writing
    g_progCurBlock = block;

    uint8_t cmd[2] = { MFC_WRITE, block };
    uint8_t resp[8] = {0};
    uint8_t rl = 0;

    if (!transceiveInAuth(cmd, 2, resp, &rl, 100)) {
        Serial.printf("[MFC] Write blk %u: cmd RX timeout\n", block);
        return false;
    }
    if (rl < 1 || (resp[0] & 0x0F) != 0x0A) {
        Serial.printf("[MFC] Write blk %u: cmd NAK 0x%02X\n", block, rl ? resp[0] : 0xFF);
        return false;
    }

    uint8_t dbuf[16];
    memcpy(dbuf, data16, 16);
    if (!transceiveInAuth(dbuf, 16, resp, &rl, 200)) {
        Serial.printf("[MFC] Write blk %u: data RX timeout\n", block);
        return false;
    }
    if (rl < 1 || (resp[0] & 0x0F) != 0x0A) {
        Serial.printf("[MFC] Write blk %u: data NAK 0x%02X\n", block, rl ? resp[0] : 0xFF);
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// MIFARE Ultralight WRITE (cmd 0xA2): single-phase, 4 data bytes
// ---------------------------------------------------------------------------
bool PN5180MIFARE::mfulWritePage(uint8_t page, const uint8_t *data4) {
    g_progPhase    = 4;
    g_progCurBlock = page;

    uint8_t cmd[8];
    uint8_t len = 0;
    cmd[len++] = MFUL_WRITE;
    cmd[len++] = page;
    memcpy(cmd + len, data4, 4);
    len += 4;
    appendCRC16(cmd, &len);

    uint8_t resp[8] = {0};
    uint8_t rl = 0;
    if (!transceive14443(cmd, len, resp, &rl, 200)) return false;
    return rl >= 1 && (resp[0] & 0x0F) == 0x0A;
}

bool PN5180MIFARE::mfulWriteAllPages(MifareTagInfo *dump, uint16_t *outWritten) {
    uint16_t w = 0;
    g_progTotalBlocks = dump->blockCount;
    // Skip pages 0..1 (UID/BCC, locked on factory UL) and lock pages 2..3 by
    // default — caller can override later if needed. Page 4+ is user memory.
    for (uint8_t p = 4; p < dump->blockCount; p++) {
        if (mfulWritePage(p, dump->data + p * 4)) w++;
    }
    if (outWritten) *outWritten = w;
    return true;
}

// ---------------------------------------------------------------------------
// Magic Gen 1A / 1B wakeup: short-frame 0x40, then full-byte 0x43
// ---------------------------------------------------------------------------
bool PN5180MIFARE::gen1Wakeup(bool *isGen1B) {
    if (isGen1B) *isGen1B = false;

    // Short-frame wakeup needs CRC OFF and Crypto1 OFF
    andRegister(REG_CRC_TX_CONFIG, 0xFFFFFFFEU);
    andRegister(REG_CRC_RX_CONFIG, 0xFFFFFFFEU);
    andRegister(REG_SYSTEM_CONFIG, 0xFFFFFFBFU);

    // ── 0x40 (7 bits) ───────────────────────────────────────────────────
    clearIRQ();
    setIdle();
    activateTransceive();
    uint8_t buf[3] = { PN5180_SEND_DATA, 0x07, 0x40 };
    if (!spiSend(buf, sizeof(buf))) return false;
    delay(5);
    uint32_t rxs  = readRegister(REG_RX_STATUS);
    uint8_t  rlen = (uint8_t)(rxs & 0x1FF);
    clearIRQ();
    if (rlen < 1) return false;

    uint8_t r[2] = {0};
    uint8_t rc[2] = { PN5180_READ_DATA, 0x00 };
    spiSend(rc, sizeof(rc));
    spiReceive(r, 1);
    if ((r[0] & 0x0F) != 0x0A) return false;

    // ── 0x43 (full byte) ────────────────────────────────────────────────
    clearIRQ();
    setIdle();
    activateTransceive();
    uint8_t buf2[3] = { PN5180_SEND_DATA, 0x00, 0x43 };
    if (!spiSend(buf2, sizeof(buf2))) return false;
    delay(5);
    rxs  = readRegister(REG_RX_STATUS);
    rlen = (uint8_t)(rxs & 0x1FF);
    clearIRQ();
    if (rlen < 1) {
        // Gen 1B: no ack on 0x43 but card is still in privileged mode
        if (isGen1B) *isGen1B = true;
        return true;
    }
    spiSend(rc, sizeof(rc));
    spiReceive(r, 1);
    if ((r[0] & 0x0F) != 0x0A) {
        if (isGen1B) *isGen1B = true;
    }
    return true;
}

bool PN5180MIFARE::gen1WriteBlock(uint8_t block, const uint8_t *data16) {
    // Re-enable HW CRC for the WRITE command + data frames
    orRegister(REG_CRC_TX_CONFIG, 0x01);
    orRegister(REG_CRC_RX_CONFIG, 0x01);

    g_progPhase    = 4;
    g_progCurBlock = block;

    uint8_t cmd[2] = { MFC_WRITE, block };
    uint8_t resp[8] = {0};
    uint8_t rl = 0;

    if (!transceiveInAuth(cmd, 2, resp, &rl, 100)) return false;
    if (rl < 1 || (resp[0] & 0x0F) != 0x0A) return false;

    uint8_t dbuf[16];
    memcpy(dbuf, data16, 16);
    if (!transceiveInAuth(dbuf, 16, resp, &rl, 300)) return false;
    return rl >= 1 && (resp[0] & 0x0F) == 0x0A;
}

// ---------------------------------------------------------------------------
// Magic Gen 3 (APDU) — caller must have selected the tag first
// ---------------------------------------------------------------------------
// Send one Gen3 APDU (CRC appended manually) and verify the "9000fd07" reply.
bool PN5180MIFARE::sendCmd14443(uint8_t *cmd, uint8_t cmdLen,
                                 uint8_t *resp, uint8_t *respLen, uint16_t timeoutMs) {
    // Gen3/Gen4 magic cards are slow — disable HW CRC (manual append on TX)
    // and call the regular transceiver. Returned data still includes the
    // chip's CRC bytes; we don't strip them since callers check leading bytes.
    andRegister(REG_CRC_TX_CONFIG, 0xFFFFFFFEU);
    andRegister(REG_CRC_RX_CONFIG, 0xFFFFFFFEU);
    return transceive14443(cmd, cmdLen, resp, respLen, timeoutMs);
}

bool PN5180MIFARE::gen3SetUID(const uint8_t *uid, uint8_t uidLen) {
    if (uidLen != 4 && uidLen != 7 && uidLen != 10) return false;
    uint8_t cmd[20];
    cmd[0] = 0x90; cmd[1] = 0xFB; cmd[2] = 0xCC; cmd[3] = 0xCC; cmd[4] = 0x07;
    memcpy(cmd + 5, uid, uidLen);
    uint8_t len = 5 + uidLen;
    appendCRC16(cmd, &len);
    uint8_t resp[16] = {0};
    uint8_t rl = 0;
    if (!sendCmd14443(cmd, len, resp, &rl, 2500)) return false;
    return rl >= 4 && resp[0] == 0x90 && resp[1] == 0x00;
}

bool PN5180MIFARE::gen3SetBlock0(const uint8_t *block16) {
    uint8_t cmd[24];
    cmd[0] = 0x90; cmd[1] = 0xF0; cmd[2] = 0xCC; cmd[3] = 0xCC; cmd[4] = 0x10;
    memcpy(cmd + 5, block16, 16);
    uint8_t len = 21;
    appendCRC16(cmd, &len);
    uint8_t resp[16] = {0};
    uint8_t rl = 0;
    if (!sendCmd14443(cmd, len, resp, &rl, 2500)) return false;
    return rl >= 4 && resp[0] == 0x90 && resp[1] == 0x00;
}

bool PN5180MIFARE::gen3Freeze() {
    uint8_t cmd[7] = { 0x90, 0xFD, 0x11, 0x11, 0x00, 0xE7, 0x91 };  // CRC pre-baked
    uint8_t resp[16] = {0};
    uint8_t rl = 0;
    if (!sendCmd14443(cmd, sizeof(cmd), resp, &rl, 2500)) return false;
    return rl >= 4 && resp[0] == 0x90 && resp[1] == 0x00;
}

// ---------------------------------------------------------------------------
// Magic Gen 4 GTU — backdoor read/write any block, any password
// ---------------------------------------------------------------------------
// Cmd format: 0xCF + pwd[4] + opcode + args + CRC (HW disabled, manual CRC).
// Opcodes: 0xCD = write 16B block, 0xCE = read 16B block.
// On success the card replies with the literal 4 bytes "90 00 fd 07".
bool PN5180MIFARE::gen4WriteBlock(uint8_t block, const uint8_t pwd[4], const uint8_t *data16) {
    uint8_t cmd[26];
    cmd[0] = 0xCF;
    memcpy(cmd + 1, pwd, 4);
    cmd[5] = 0xCD;        // write opcode
    cmd[6] = block;
    memcpy(cmd + 7, data16, 16);
    uint8_t len = 23;
    appendCRC16(cmd, &len);

    andRegister(REG_CRC_TX_CONFIG, 0xFFFFFFFEU);
    andRegister(REG_CRC_RX_CONFIG, 0xFFFFFFFEU);

    g_progPhase    = 4;
    g_progCurBlock = block;

    uint8_t resp[16] = {0};
    uint8_t rl = 0;
    if (!transceive14443(cmd, len, resp, &rl, 2500)) return false;
    return rl >= 4 && resp[0] == 0x90 && resp[1] == 0x00 &&
                      resp[2] == 0xFD && resp[3] == 0x07;
}

bool PN5180MIFARE::gen4ReadBlock(uint8_t block, const uint8_t pwd[4], uint8_t *out16) {
    uint8_t cmd[10];
    cmd[0] = 0xCF;
    memcpy(cmd + 1, pwd, 4);
    cmd[5] = 0xCE;
    cmd[6] = block;
    cmd[7] = 0x00;
    cmd[8] = 0x00;
    uint8_t len = 7;
    appendCRC16(cmd, &len);

    andRegister(REG_CRC_TX_CONFIG, 0xFFFFFFFEU);
    andRegister(REG_CRC_RX_CONFIG, 0xFFFFFFFEU);

    uint8_t resp[20] = {0};
    uint8_t rl = 0;
    if (!transceive14443(cmd, len, resp, &rl, 2500)) return false;
    if (rl < 16) return false;
    memcpy(out16, resp, 16);
    return true;
}

// ---------------------------------------------------------------------------
// GDM / USCUID magic
// ---------------------------------------------------------------------------
// GDM auth (0x80) uses the same Crypto1 protocol as standard auth but on cmd
// 0x80 instead of 0x60/0x61. After a successful GDM auth, GDM-write (0xA8)
// can write to any block — including normally-locked sector-trailer access bits.
bool PN5180MIFARE::gdmAuthBlock(MifareTagInfo *info, uint8_t block,
                                 const uint8_t key[6], bool useKeyA) {
    g_progPhase    = 2;
    g_progCurBlock = block;
    g_progKeyType  = useKeyA ? 0 : 1;

    // Same payload layout as MIFARE_AUTHENTICATE but key_type byte is the
    // GDM auth opcode 0x80 (0x60-style A-equivalent) — proxmark uses the
    // same 0x80 regardless of A/B for GDM.
    uint8_t cmd[13];
    cmd[0] = 0x0C;
    memcpy(cmd + 1, key, 6);
    cmd[7] = 0x80;                              // GDM AUTH
    cmd[8] = block;
    memcpy(cmd + 9, info->uid, 4);

    orRegister(REG_CRC_TX_CONFIG, 0x01);
    orRegister(REG_CRC_RX_CONFIG, 0x01);
    setIdle();
    clearIRQ();
    if (g_irqSem) xSemaphoreTake(g_irqSem, 0);

    if (!spiSend(cmd, sizeof(cmd))) return false;
    uint8_t status = 0xFF;
    if (!spiReceive(&status, 1)) return false;
    return status == 0x00;
}

bool PN5180MIFARE::gdmWriteBlock(uint8_t block, const uint8_t *data16) {
    g_progPhase    = 4;
    g_progCurBlock = block;

    // GDM write uses cmd byte 0xA8 (instead of 0xA0). Two-phase like normal WRITE.
    uint8_t cmd[2] = { 0xA8, block };
    uint8_t resp[8] = {0};
    uint8_t rl = 0;
    if (!transceiveInAuth(cmd, 2, resp, &rl, 100)) return false;
    if (rl < 1 || (resp[0] & 0x0F) != 0x0A) return false;

    uint8_t dbuf[16];
    memcpy(dbuf, data16, 16);
    if (!transceiveInAuth(dbuf, 16, resp, &rl, 300)) return false;
    return rl >= 1 && (resp[0] & 0x0F) == 0x0A;
}

// ---------------------------------------------------------------------------
// Auto-detect magic-card flavour
// ---------------------------------------------------------------------------
// Order:
//   1. Gen 1A/1B (cheap: short-frame 0x40, no select needed)
//   2. Gen 4 GTU backdoor get-config with default pwd 0
//   3. Gen 3 APDU read-block-0-without-auth probe
//   4. Gen 4 GDM hidden-block read probe (uses the GDM ReadCfg cmd)
//   5. Gen 2 / CUID — last (we authenticate + try to write block 0; if it
//      ACKs, the card is CUID. We detect this lazily later in writeTagFromDump
//      to avoid actually writing during detection.)
// Each probe powers down the field briefly to reset card state.
uint16_t PN5180MIFARE::detectMagicType(MifareTagInfo *info) {
    uint16_t flags = 0;

    auto rfReset = [this]() {
        disableRF();
        delay(15);
        activateRF();
        delay(20);
        loadISO14443Config();
        writeRegister(0x1A, 0x02U);
    };

    // ── 1. Gen 1A / 1B ──────────────────────────────────────────────────
    rfReset();
    {
        bool isGen1B = false;
        if (gen1Wakeup(&isGen1B)) {
            flags |= isGen1B ? MAGIC_GEN1B : MAGIC_GEN1A;
            haltTag();
        }
    }

    // ── 2. Gen 4 GTU (backdoor get-config) ──────────────────────────────
    rfReset();
    {
        MifareTagInfo tmp;
        if (detectTag(&tmp)) {
            uint8_t cmd[8] = { 0xCF, 0x00, 0x00, 0x00, 0x00, 0xC6, 0x00, 0x00 };
            uint8_t l = 6;
            appendCRC16(cmd, &l);
            uint8_t resp[40] = {0};
            uint8_t rl = 0;
            if (transceive14443(cmd, 8, resp, &rl, 200) && (rl == 32 || rl == 34)) {
                flags |= MAGIC_GEN4_GTU;
            }
        }
    }

    // ── 3. Gen 3 APDU (read block 0 without auth — Gen3 magic responds) ─
    rfReset();
    {
        MifareTagInfo tmp;
        if (detectTag(&tmp)) {
            uint8_t cmd[4] = { 0x30, 0x00, 0x02, 0xA8 };
            uint8_t resp[20] = {0};
            uint8_t rl = 0;
            if (transceive14443(cmd, 4, resp, &rl, 50) && rl == 18) {
                flags |= MAGIC_GEN3;
            }
        }
    }

    // ── 4. GDM (USCUID) — magic auth probe ───────────────────────────────
    rfReset();
    {
        MifareTagInfo tmp;
        if (detectTag(&tmp)) {
            uint8_t cmd[4] = { 0x80, 0x00, 0x6C, 0x92 };
            uint8_t resp[8] = {0};
            uint8_t rl = 0;
            if (transceive14443(cmd, 4, resp, &rl, 50) && rl == 4) {
                flags |= MAGIC_GDM;
            }
        }
    }

    // Re-detect the live tag for the caller (so info->uid is fresh).
    rfReset();
    detectTag(info);

    Serial.printf("[magic] detected flags=0x%04X\n", flags);
    return flags;
}

// ---------------------------------------------------------------------------
// High-level: write a dump back to a tag with auto magic detection
// ---------------------------------------------------------------------------
// Strategy:
//   • Detect tag + magic capabilities up front (~200ms).
//   • Block 0 (UID): use whichever magic op the card supports. Fall back to
//     standard auth+WRITE (works on Gen 2 / CUID), otherwise skip.
//   • Other blocks:
//       - Gen 1A/1B  → unauth WRITE per block (haltTag + gen1Wakeup each time)
//       - Gen 4 GTU  → backdoor write (no auth, any block)
//       - else       → standard auth (try keys from the dump trailer first,
//                      then defaults, then dict) + WRITE
//   • Sector trailers are skipped unless writeTrailers is true.
bool PN5180MIFARE::writeTagFromDump(MifareTagInfo *dump,
                                     uint8_t (*keys1)[6], int n1,
                                     uint8_t (*keys2)[6], int n2,
                                     bool writeBlock0,
                                     bool writeTrailers,
                                     uint16_t *outMagic,
                                     uint16_t *outWritten) {
    if (outMagic)   *outMagic   = 0;
    if (outWritten) *outWritten = 0;
    g_progPhase       = 1;
    g_progTotalBlocks = dump->blockCount;
    g_progCurBlock    = -1;

    // Bring the field up and detect the live card
    if (!loadISO14443Config()) return false;
    if (!activateRF()) return false;
    delay(50);

    // Heap-allocated — sizeof(MifareTagInfo) is ~4.4 KB and we're called
    // from the 8 KB Arduino loopTask via the WebServer chain. Putting two of
    // these on the stack (one here + one in detectMagicType) overflows it.
    auto livePtr = std::unique_ptr<MifareTagInfo>(new MifareTagInfo);
    MifareTagInfo &live = *livePtr;
    if (!detectTag(&live)) {
        Serial.println("[write] No tag detected");
        disableRF();
        return false;
    }

    // Probe magic-card capabilities (does its own RF cycles internally; leaves
    // the card detected and selected at the end).
    uint16_t magic = detectMagicType(&live);
    if (outMagic) *outMagic = magic;

    uint16_t written = 0;
    auto isTrailer = [&](uint8_t b) -> bool {
        uint8_t s = blockToSector(dump->type, b);
        return b == sectorTrailerBlock(dump->type, s);
    };

    // ── Path A: Gen 4 GTU backdoor — fastest, no auth, any block ────────
    if (magic & MAGIC_GEN4_GTU) {
        uint8_t pwd[4] = {0, 0, 0, 0};
        // Re-select after the magic detection
        if (!reActivateCard(&live)) {
            disableRF();
            return false;
        }
        for (uint16_t b = 0; b < dump->blockCount; b++) {
            if (b == 0 && !writeBlock0) continue;
            if (isTrailer(b) && !writeTrailers) continue;
            if (gen4WriteBlock(b, pwd, dump->data + b * 16)) written++;
        }
        haltTag();
        disableRF();
        if (outWritten) *outWritten = written;
        g_progPhase = 0;
        return true;
    }

    // ── Path B: Gen 1A/1B — per-block wakeup + unauth WRITE ─────────────
    if (magic & (MAGIC_GEN1A | MAGIC_GEN1B)) {
        for (uint16_t b = 0; b < dump->blockCount; b++) {
            if (b == 0 && !writeBlock0) continue;
            if (isTrailer(b) && !writeTrailers) continue;

            // Each write needs its own wakeup (card halts between ops)
            bool ok = false;
            for (int retry = 0; retry < 2 && !ok; retry++) {
                disableRF(); delay(10);
                activateRF(); delay(15);
                loadISO14443Config();
                writeRegister(0x1A, 0x02U);
                if (gen1Wakeup(nullptr) && gen1WriteBlock(b, dump->data + b * 16)) {
                    ok = true;
                }
            }
            if (ok) written++;
        }
        haltTag();
        disableRF();
        if (outWritten) *outWritten = written;
        g_progPhase = 0;
        return true;
    }

    // ── Path C: Standard MFC auth + WRITE per sector ────────────────────
    // (also handles Gen 2 / CUID for block 0 — standard auth + WRITE just works)
    // (Gen 3 would only help for block 0; we use it lazily below.)
    if (!reActivateCard(&live)) {
        disableRF();
        return false;
    }

    uint8_t ns = totalSectors(dump->type);
    uint8_t reuseKey[6] = {0};
    bool    reuseKeyA   = true;
    bool    hasReuse    = false;

    // Helper: try one key (both A and B) on the trailer.
    auto trySectorKey = [&](uint8_t *key, bool &authOk, bool &useA,
                             uint8_t *goodKey, bool &abortF, uint8_t trailer) {
        for (int ab = 0; ab < 2 && !authOk && !abortF; ab++) {
            if (mfcAuthBlock(&live, trailer, key, ab == 0)) {
                authOk = true;
                useA = (ab == 0);
                memcpy(goodKey, key, 6);
            } else {
                if (!reSelectCard(&live)) abortF = true;
            }
        }
    };

    for (uint8_t s = 0; s < ns; s++) {
        uint8_t trailer = sectorTrailerBlock(dump->type, s);
        bool authOk = false, useA = true, abortF = false;
        uint8_t goodKey[6];

        // 1) Reuse key from previous sector
        if (hasReuse) trySectorKey(reuseKey, authOk, useA, goodKey, abortF, trailer);

        // 2) Keys baked into the dump's own sector trailer
        if (!authOk && !abortF) {
            uint8_t trA[6], trB[6];
            memcpy(trA, dump->data + trailer * 16,      6);
            memcpy(trB, dump->data + trailer * 16 + 10, 6);
            trySectorKey(trA, authOk, useA, goodKey, abortF, trailer);
            if (!authOk && !abortF)
                trySectorKey(trB, authOk, useA, goodKey, abortF, trailer);
        }

        // 3) Default keys
        for (int ki = 0; ki < (int)NUM_DEFAULT_KEYS && !authOk && !abortF; ki++)
            trySectorKey((uint8_t*)DEFAULT_KEYS[ki], authOk, useA, goodKey, abortF, trailer);

        // 4) Dict files
        for (int ki = 0; ki < n1 && !authOk && !abortF; ki++)
            trySectorKey(keys1[ki], authOk, useA, goodKey, abortF, trailer);
        for (int ki = 0; ki < n2 && !authOk && !abortF; ki++)
            trySectorKey(keys2[ki], authOk, useA, goodKey, abortF, trailer);

        if (!authOk) {
            Serial.printf("[write] Sector %u: no key found, skipping\n", s);
            continue;
        }
        memcpy(reuseKey, goodKey, 6);
        reuseKeyA = useA;
        hasReuse  = true;

        uint8_t first = sectorFirstBlock(dump->type, s);
        uint8_t cnt   = sectorBlockCount(dump->type, s);
        Serial.printf("[write] Sector %u: auth OK key=%c, writing blocks %u..%u\n",
            s, useA ? 'A' : 'B', first, (uint8_t)(first + cnt - 1));

        for (uint8_t b = first; b < first + cnt; b++) {
            // Skip block 0 here — handled separately via magic / lazy-CUID below
            if (b == 0) continue;
            // Skip sector trailer unless explicitly requested
            if (b == trailer && !writeTrailers) continue;

            bool wOk = mfcWriteBlock(b, dump->data + b * 16);
            if (!wOk) {
                // Re-select + re-auth and retry once
                if (reSelectCard(&live) && mfcAuthBlock(&live, trailer, goodKey, useA)) {
                    wOk = mfcWriteBlock(b, dump->data + b * 16);
                }
            }
            if (wOk) written++;
        }
    }

    // ── Block 0 handling ────────────────────────────────────────────────
    // Standard MFC auth+WRITE on block 0 only succeeds on CUID/Gen2 cards.
    // Gen 3 path is also handled here.
    if (writeBlock0) {
        bool b0ok = false;

        // Try Gen 3 APDU first (cheap if Gen3 was detected)
        if (magic & MAGIC_GEN3) {
            if (reActivateCard(&live)) {
                if (gen3SetBlock0(dump->data)) {
                    b0ok = true;
                    Serial.println("[write] block 0 via Gen3 APDU OK");
                }
            }
        }

        // Otherwise (or as fallback): authenticate sector 0 and try a normal WRITE.
        // This succeeds on Gen 2 / CUID magic cards; fails on plain MIFARE Classic.
        if (!b0ok) {
            uint8_t defKey[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
            uint8_t key[6];
            // Prefer dict + dump-trailer key A for sector 0
            if (reActivateCard(&live)) {
                bool authed = false;
                memcpy(key, dump->data + 0 + 3*16, 6);     // sector 0 trailer key A (block 3)
                if (mfcAuthBlock(&live, 0, key, true))     authed = true;
                if (!authed && reSelectCard(&live) && mfcAuthBlock(&live, 0, defKey, true)) authed = true;
                for (int ki = 0; ki < n1 && !authed; ki++) {
                    if (reSelectCard(&live) && mfcAuthBlock(&live, 0, keys1[ki], true)) { memcpy(key, keys1[ki], 6); authed = true; break; }
                }
                for (int ki = 0; ki < n2 && !authed; ki++) {
                    if (reSelectCard(&live) && mfcAuthBlock(&live, 0, keys2[ki], true)) { memcpy(key, keys2[ki], 6); authed = true; break; }
                }
                if (authed && mfcWriteBlock(0, dump->data)) {
                    b0ok = true;
                    if (!(magic & MAGIC_GEN3)) magic |= MAGIC_GEN2_CUID;
                    Serial.println("[write] block 0 via standard WRITE OK (CUID)");
                }
            }
        }

        if (b0ok) written++;
        else      Serial.println("[write] block 0 write FAILED — non-magic card?");
        if (outMagic) *outMagic = magic;
    }

    haltTag();
    disableRF();
    if (outWritten) *outWritten = written;
    g_progPhase = 0;
    return true;
}


