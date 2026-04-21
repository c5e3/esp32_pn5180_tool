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

// Signalled by pn5180IrqISR() in main.cpp whenever PN5180 asserts its IRQ pin.
extern SemaphoreHandle_t g_irqSem;

// Progress state owned by main.cpp — updated here so the web UI can poll it.
extern volatile int16_t g_progCurBlock;
extern volatile int16_t g_progTotalBlocks;
extern volatile int8_t  g_progKeyType;
extern volatile uint8_t g_progPhase;

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

    if      (sak == SAK_MFUL)          info->type = MIFARE_ULTRALIGHT;
    else if (sak == SAK_MFC_MINI)      info->type = MIFARE_CLASSIC_MINI;
    else if (sak == SAK_MFC_1K)        info->type = MIFARE_CLASSIC_1K;
    else if (sak == SAK_MFC_4K)        info->type = MIFARE_CLASSIC_4K;
    else if (sak == SAK_MFPLUS_SL1_2K) info->type = MIFARE_PLUS_SL1_2K;
    else if (sak == SAK_MFPLUS_SL1_4K) info->type = MIFARE_PLUS_SL1_4K;
    else if (sak == SAK_MFPLUS_SL2)    info->type = MIFARE_PLUS_SL2;
    else                               info->type = MIFARE_UNKNOWN;

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
