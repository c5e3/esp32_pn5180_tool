#include "PN5180ISO15693.h"
#include "config.h"

// Cooperative cancel flag from main.cpp; checked in long-running loops.
extern volatile bool g_readCancel;

PN5180ISO15693::PN5180ISO15693(uint8_t nssPin, uint8_t busyPin, uint8_t rstPin)
    : _nss(nssPin), _busy(busyPin), _rst(rstPin),
      _spiSettings(PN5180_SPI_CLOCK, MSBFIRST, SPI_MODE0) {}

void PN5180ISO15693::begin() {
    pinMode(_nss, OUTPUT);
    digitalWrite(_nss, HIGH);
    pinMode(_rst, OUTPUT);
    digitalWrite(_rst, HIGH);
    pinMode(_busy, INPUT);
    SPI.begin();
    hardReset();
    printFirmwareVersion();
}

void PN5180ISO15693::hardReset() {
    digitalWrite(_rst, LOW);
    delay(10);
    digitalWrite(_rst, HIGH);
    delay(50);
}

// ============================================================
// SPI Communication (NXP PN5180 Datasheet §11.4.1)
// ============================================================

bool PN5180ISO15693::waitReady() {
    unsigned long t = millis();
    while (digitalRead(_busy) != LOW) {
        if (millis() - t > _timeout) return false;
    }
    return true;
}

bool PN5180ISO15693::waitBusy() {
    unsigned long t = millis();
    while (digitalRead(_busy) != HIGH) {
        if (millis() - t > _timeout) return false;
    }
    return true;
}

bool PN5180ISO15693::spiSend(uint8_t *buf, size_t len) {
    if (!waitReady()) return false;
    SPI.beginTransaction(_spiSettings);
    digitalWrite(_nss, LOW);
    delayMicroseconds(2);
    SPI.transfer(buf, len);
    // PN5180 SPI protocol (section 11.4.1): NSS must stay LOW until BUSY goes HIGH.
    // For short commands (e.g. 3-byte SEND_DATA), BUSY may not go HIGH before NSS
    // if we deassert immediately — causing the command to be aborted (GENERAL_ERROR).
    waitBusy();                  // wait BUSY=HIGH (chip has accepted command)
    digitalWrite(_nss, HIGH);
    SPI.endTransaction();
    delayMicroseconds(200);      // PN5180 min NSS-high recovery; 200µs >> 100ns spec, safe on any wiring
    if (!waitReady()) return false;  // wait for BUSY LOW (command processed)
    return true;
}

bool PN5180ISO15693::spiReceive(uint8_t *buf, size_t len) {
    memset(buf, 0xFF, len);
    if (!waitReady()) return false;
    SPI.beginTransaction(_spiSettings);
    digitalWrite(_nss, LOW);
    delayMicroseconds(2);
    SPI.transfer(buf, len);
    waitBusy();                  // wait BUSY=HIGH before NSS deassert (same protocol as spiSend)
    digitalWrite(_nss, HIGH);
    SPI.endTransaction();
    delayMicroseconds(200);
    if (!waitReady()) return false;
    return true;
}

// ============================================================
// Register Operations
// ============================================================

uint32_t PN5180ISO15693::readRegister(uint8_t reg) {
    uint8_t cmd[] = { PN5180_READ_REGISTER, reg };
    spiSend(cmd, sizeof(cmd));
    uint32_t val = 0;
    spiReceive((uint8_t *)&val, 4);
    return val;
}

void PN5180ISO15693::writeRegister(uint8_t reg, uint32_t val) {
    uint8_t cmd[6] = { PN5180_WRITE_REGISTER, reg,
        (uint8_t)(val & 0xFF), (uint8_t)((val >> 8) & 0xFF),
        (uint8_t)((val >> 16) & 0xFF), (uint8_t)((val >> 24) & 0xFF) };
    spiSend(cmd, sizeof(cmd));
}

void PN5180ISO15693::orRegister(uint8_t reg, uint32_t mask) {
    uint8_t cmd[6] = { PN5180_WRITE_REGISTER_OR_MASK, reg,
        (uint8_t)(mask & 0xFF), (uint8_t)((mask >> 8) & 0xFF),
        (uint8_t)((mask >> 16) & 0xFF), (uint8_t)((mask >> 24) & 0xFF) };
    spiSend(cmd, sizeof(cmd));
}

void PN5180ISO15693::andRegister(uint8_t reg, uint32_t mask) {
    uint8_t cmd[6] = { PN5180_WRITE_REGISTER_AND_MASK, reg,
        (uint8_t)(mask & 0xFF), (uint8_t)((mask >> 8) & 0xFF),
        (uint8_t)((mask >> 16) & 0xFF), (uint8_t)((mask >> 24) & 0xFF) };
    spiSend(cmd, sizeof(cmd));
}

void PN5180ISO15693::clearIRQ() {
    writeRegister(REG_IRQ_CLEAR, 0x000FFFFF);
}

// ============================================================
// RF Field Control
// ============================================================

void PN5180ISO15693::loadISO15693Config() {
    uint8_t cmd[] = { PN5180_LOAD_RF_CONFIG, 0x0D, 0x8D };
    spiSend(cmd, sizeof(cmd));
}

void PN5180ISO15693::setIdle() {
    andRegister(REG_SYSTEM_CONFIG, 0xFFFFFFF8);
}

void PN5180ISO15693::activateTransceive() {
    orRegister(REG_SYSTEM_CONFIG, 0x00000003);
}

bool PN5180ISO15693::activateRF() {
    uint8_t cmd[] = { PN5180_RF_ON, 0x00 };
    spiSend(cmd, sizeof(cmd));
    unsigned long t = millis();
    while (!(readRegister(REG_IRQ_STATUS) & TX_RFON_IRQ_STAT)) {
        if (millis() - t > 500) return false;
    }
    clearIRQ();
    return true;
}

bool PN5180ISO15693::disableRF() {
    uint8_t cmd[] = { PN5180_RF_OFF, 0x00 };
    spiSend(cmd, sizeof(cmd));
    unsigned long t = millis();
    while (!(readRegister(REG_IRQ_STATUS) & TX_RFOFF_IRQ_STAT)) {
        if (millis() - t > 500) return false;
    }
    clearIRQ();
    return true;
}

void PN5180ISO15693::sendEndOfFrame() {
    // Clear TX_DATA_ENABLE (bit 10) and bits 6,7 so only EOF symbol is sent
    // AND mask: 0xFFFFFB3F (same as reference PN5180 library)
    andRegister(REG_TX_CONFIG, 0xFFFFFB3F);
    // SEND_DATA with no payload = EOF only
    // Must use fresh buffer each call because SPI.transfer overwrites it
    uint8_t cmd[] = { PN5180_SEND_DATA, 0x00 };
    spiSend(cmd, sizeof(cmd));
}

bool PN5180ISO15693::readEEPROM(uint8_t addr, uint8_t *buf, uint8_t len) {
    uint8_t cmd[] = { PN5180_READ_EEPROM, addr, len };
    if (!spiSend(cmd, sizeof(cmd))) return false;
    return spiReceive(buf, len);
}

void PN5180ISO15693::printFirmwareVersion() {
    uint8_t prodVer[2], fwVer[2], eepromVer[2];
    if (readEEPROM(0x10, prodVer, 2)) {
        Serial.printf("Product version: %d.%d\n", prodVer[1], prodVer[0]);
    }
    if (readEEPROM(0x12, fwVer, 2)) {
        Serial.printf("Firmware version: %d.%d\n", fwVer[1], fwVer[0]);
    }
    if (readEEPROM(0x14, eepromVer, 2)) {
        Serial.printf("EEPROM version: %d.%d\n", eepromVer[1], eepromVer[0]);
    }
}

// ============================================================
// ISO 15693 Transceive
// ============================================================

bool PN5180ISO15693::transceive(uint8_t *txData, uint8_t txLen,
                                 uint8_t *rxBuf, uint8_t rxBufSize,
                                 uint16_t *rxLen, uint16_t timeoutMs) {
    if (txLen > MAX_CMD_FRAME_SIZE) return false;

    clearIRQ();
    setIdle();
    activateTransceive();

    // Prefix with SEND_DATA command + valid-bits byte
    uint8_t sendBuf[MAX_CMD_FRAME_SIZE + 2];
    sendBuf[0] = PN5180_SEND_DATA;
    sendBuf[1] = 0x00; // all bits valid
    memcpy(&sendBuf[2], txData, txLen);
    if (!spiSend(sendBuf, txLen + 2)) return false;

    // Wait for RX_IRQ (response received)
    unsigned long t = millis();
    while (millis() - t < timeoutMs) {
        uint32_t irq = readRegister(REG_IRQ_STATUS);
        if (irq & RX_IRQ_STAT) {
            uint32_t rxStatus = readRegister(REG_RX_STATUS);
            uint16_t len = (uint16_t)(rxStatus & 0x000001FF);
            if (len == 0) return false;
            if (len > rxBufSize) len = rxBufSize;

            uint8_t readCmd[] = { PN5180_READ_DATA, 0x00 };
            spiSend(readCmd, sizeof(readCmd));
            spiReceive(rxBuf, len);

            if (rxLen) *rxLen = len;
            return true;
        }
        yield();
    }
    return false; // timeout
}

// ============================================================
// ISO 15693 Inventory (16-slot anti-collision)
// ============================================================

bool PN5180ISO15693::inventory(uint8_t *uid) {
    Serial.println("[INV] start");
    loadISO15693Config();
    if (!activateRF()) { Serial.println("[INV] RF fail"); return false; }

    // Single-slot inventory: flags=0x26 (high rate + inventory + 1-slot), cmd=0x01, mask=0x00
    uint8_t cmd[] = { 0x26, ISO15693_INVENTORY, 0x00 };
    uint16_t rxLen = 0;

    bool ok = transceive(cmd, 3, _rxBuf, RX_BUFFER_SIZE, &rxLen, 500);
    Serial.printf("[INV] transceive=%d rxLen=%d\n", ok, rxLen);

    if (ok && rxLen >= 10) {
        Serial.printf("[INV] flags=0x%02X\n", _rxBuf[0]);
        if ((_rxBuf[0] & 0x01) == 0) {
            memcpy(uid, &_rxBuf[2], 8);
            Serial.printf("[INV] UID=%02X%02X%02X%02X%02X%02X%02X%02X\n",
                uid[7],uid[6],uid[5],uid[4],uid[3],uid[2],uid[1],uid[0]);
            disableRF();
            return true;
        }
    }

    disableRF();
    Serial.println("[INV] no tag");
    return false;
}

// ============================================================
// ISO 15693 Get System Info
// ============================================================

bool PN5180ISO15693::getSystemInfo(uint8_t *uid, ISO15693TagInfo *info) {
    // Addressed Get System Info: [flags=0x22] [cmd=0x2B] [UID 8 bytes]
    uint8_t cmd[10];
    cmd[0] = ISO15_REQ_DATARATE_HIGH | ISO15_REQ_ADDRESS;
    cmd[1] = ISO15693_GET_SYSTEM_INFO;
    memcpy(&cmd[2], uid, 8);

    uint16_t rxLen = 0;
    if (!transceive(cmd, 10, _rxBuf, RX_BUFFER_SIZE, &rxLen, 500)) return false;

    // Check error flag
    if (_rxBuf[0] & 0x01) return false;

    // Parse response: flags(1) + info_flags(1) + UID(8) + optional fields
    if (rxLen < 10) return false;

    uint8_t infoFlags = _rxBuf[1];
    memcpy(info->uid, &_rxBuf[2], 8);

    uint8_t pos = 10;
    info->dsfid = 0;
    info->afi = 0;
    info->blockCount = 0;
    info->blockSize = 4;
    info->icRef = 0;

    if (infoFlags & 0x01) { // DSFID present
        if (pos < rxLen) info->dsfid = _rxBuf[pos++];
    }
    if (infoFlags & 0x02) { // AFI present
        if (pos < rxLen) info->afi = _rxBuf[pos++];
    }
    if (infoFlags & 0x04) { // Memory size present
        if (pos + 1 < rxLen) {
            info->blockCount = _rxBuf[pos] + 1;
            info->blockSize = (_rxBuf[pos + 1] & 0x1F) + 1;
            pos += 2;
        }
    }
    if (infoFlags & 0x08) { // IC reference present
        if (pos < rxLen) info->icRef = _rxBuf[pos++];
    }

    info->valid = true;
    return true;
}

// ============================================================
// ISO 15693 Read/Write Single Block
// ============================================================

bool PN5180ISO15693::readSingleBlock(uint8_t *uid, uint8_t blockNo,
                                      uint8_t *data, uint8_t blockSize) {
    // Addressed Read Single Block: [0x22] [0x20] [UID 8B] [blockNo]
    uint8_t cmd[11];
    cmd[0] = ISO15_REQ_DATARATE_HIGH | ISO15_REQ_ADDRESS;
    cmd[1] = ISO15693_READ_SINGLE_BLOCK;
    memcpy(&cmd[2], uid, 8);
    cmd[10] = blockNo;

    uint16_t rxLen = 0;
    if (!transceive(cmd, 11, _rxBuf, RX_BUFFER_SIZE, &rxLen, 500)) return false;
    if (_rxBuf[0] & 0x01) return false; // error flag
    if (rxLen < 1 + blockSize) return false;

    memcpy(data, &_rxBuf[1], blockSize);
    return true;
}

bool PN5180ISO15693::writeSingleBlock(uint8_t *uid, uint8_t blockNo,
                                       uint8_t *data, uint8_t blockSize) {
    // Addressed Write with OPTION flag + EOF (required for TI/E007 tags)
    // ISO 15693-3 §11.2.6: With OPTION flag, VICC writes data then waits
    // for EOF before sending response.
    uint8_t cmd[11 + ISO15693_MAX_BLOCK_SIZE];
    cmd[0] = ISO15_REQ_DATARATE_HIGH | ISO15_REQ_ADDRESS | ISO15_REQ_OPTION;
    cmd[1] = ISO15693_WRITE_SINGLE_BLOCK;
    memcpy(&cmd[2], uid, 8);
    cmd[10] = blockNo;
    memcpy(&cmd[11], data, blockSize);

    // Reload RF config to restore TX_CONFIG (sendEndOfFrame clears TX_DATA_ENABLE)
    loadISO15693Config();
    clearIRQ();
    setIdle();
    activateTransceive();

    // Send write command via SEND_DATA
    uint8_t sendBuf[MAX_CMD_FRAME_SIZE + 2];
    sendBuf[0] = PN5180_SEND_DATA;
    sendBuf[1] = 0x00;
    uint8_t txLen = 11 + blockSize;
    memcpy(&sendBuf[2], cmd, txLen);
    if (!spiSend(sendBuf, txLen + 2)) {
        Serial.printf("[WR%d] spiSend fail\n", blockNo);
        return false;
    }

    // Wait for TX_IRQ (command transmitted over RF)
    unsigned long t = millis();
    while (millis() - t < 200) {
        if (readRegister(REG_IRQ_STATUS) & TX_IRQ_STAT) break;
        yield();
    }

    // Wait for tag to program EEPROM (~20ms per ISO 15693)
    delay(20);

    // Send EOF: reset state machine and send end-of-frame
    // Exact sequence from reference PN5180 library (multi-slot inventory):
    //   setIdle → activateTransceive → clearIRQ → sendEndOfFrame
    setIdle();
    activateTransceive();
    clearIRQ();
    sendEndOfFrame();

    // Wait for RX_IRQ — tag response to EOF
    // Note: TX_IRQ may or may not fire for zero-length EOF;
    //       just wait for the RX response directly.
    t = millis();
    while (millis() - t < 200) {
        uint32_t irq = readRegister(REG_IRQ_STATUS);
        if (irq & RX_IRQ_STAT) {
            uint32_t rxStatus = readRegister(REG_RX_STATUS);
            uint16_t len = (uint16_t)(rxStatus & 0x000001FF);
            if (len > 0 && len <= RX_BUFFER_SIZE) {
                uint8_t readCmd[] = { PN5180_READ_DATA, 0x00 };
                spiSend(readCmd, sizeof(readCmd));
                spiReceive(_rxBuf, len);
                Serial.printf("[WR%d] resp: flags=0x%02X\n", blockNo, _rxBuf[0]);
                if ((_rxBuf[0] & 0x01) == 0) {
                    return true;
                }
                // Error response — report code
                Serial.printf("[WR%d] error code=0x%02X\n", blockNo,
                               len > 1 ? _rxBuf[1] : 0xFF);
                return false;
            }
            break;
        }
        yield();
    }

    // No RX response — verify by read-back as last resort
    Serial.printf("[WR%d] no EOF response, verifying...\n", blockNo);
    delay(5);
    uint8_t verify[ISO15693_MAX_BLOCK_SIZE];
    if (readSingleBlock(uid, blockNo, verify, blockSize)) {
        if (memcmp(data, verify, blockSize) == 0) {
            Serial.printf("[WR%d] OK (verified)\n", blockNo);
            return true;
        }
    }
    Serial.printf("[WR%d] FAILED\n", blockNo);
    return false;
}

// ============================================================
// Full Tag Read (inventory + sysinfo + all blocks)
// ============================================================

bool PN5180ISO15693::readTag(ISO15693TagInfo *info, uint8_t *data, uint16_t maxDataLen) {
    info->valid = false;

    loadISO15693Config();
    if (!activateRF()) return false;

    // Step 1: Single-slot inventory to get UID
    uint8_t invCmd[] = { 0x26, ISO15693_INVENTORY, 0x00 };
    uint16_t invRxLen = 0;
    if (!transceive(invCmd, 3, _rxBuf, RX_BUFFER_SIZE, &invRxLen, 500)
        || invRxLen < 10 || (_rxBuf[0] & 0x01)) {
        disableRF();
        return false;
    }
    memcpy(info->uid, &_rxBuf[2], 8);

    // Step 2: Get System Info
    if (!getSystemInfo(info->uid, info)) {
        disableRF();
        return false;
    }

    // Step 3: Read all blocks
    uint16_t totalBytes = (uint16_t)info->blockCount * info->blockSize;
    if (totalBytes > maxDataLen) { disableRF(); return false; }

    for (uint8_t b = 0; b < info->blockCount; b++) {
        yield();
        if (g_readCancel) { disableRF(); return false; }
        if (!readSingleBlock(info->uid, b, &data[b * info->blockSize], info->blockSize)) {
            Serial.printf("Read block %d failed\n", b);
            disableRF();
            return false;
        }
    }

    disableRF();
    return true;
}

// ============================================================
// Write All Blocks
// ============================================================

bool PN5180ISO15693::writeTag(uint8_t blockCount, uint8_t blockSize,
                               uint8_t *data, uint8_t *writtenCount,
                               uint8_t *actualBlockCount) {
    *writtenCount = 0;
    *actualBlockCount = 0;

    loadISO15693Config();
    if (!activateRF()) return false;

    // Inventory to get actual tag UID
    uint8_t invCmd[] = { 0x26, ISO15693_INVENTORY, 0x00 };
    uint16_t invRxLen = 0;
    if (!transceive(invCmd, 3, _rxBuf, RX_BUFFER_SIZE, &invRxLen, 500)
        || invRxLen < 10 || (_rxBuf[0] & 0x01)) {
        Serial.println("Write: no tag found");
        disableRF();
        return false;
    }
    uint8_t tagUid[8];
    memcpy(tagUid, &_rxBuf[2], 8);

    // Get system info to determine actual block count
    ISO15693TagInfo tagInfo;
    if (!getSystemInfo(tagUid, &tagInfo)) {
        Serial.println("Write: getSystemInfo failed");
        disableRF();
        return false;
    }
    *actualBlockCount = tagInfo.blockCount;

    // Clamp to actual tag capacity
    uint8_t toWrite = (blockCount <= tagInfo.blockCount) ? blockCount : tagInfo.blockCount;
    Serial.printf("Write: dump has %d blocks, tag has %d blocks, writing %d\n",
                  blockCount, tagInfo.blockCount, toWrite);

    bool success = true;
    for (uint8_t b = 0; b < toWrite; b++) {
        yield();
        bool blockOk = false;
        for (int retry = 0; retry < 3; retry++) {
            if (retry > 0) {
                Serial.printf("Write block %d retry %d\n", b, retry);
                delay(20);
                loadISO15693Config();
                clearIRQ();
                setIdle();
                activateTransceive();
            }
            if (writeSingleBlock(tagUid, b, &data[b * blockSize], blockSize)) {
                blockOk = true;
                break;
            }
        }
        if (!blockOk) {
            Serial.printf("Write block %d failed after retries\n", b);
            success = false;
            break;
        }
        *writtenCount = b + 1;
        delay(5);
    }

    disableRF();
    return success;
}

// ============================================================
// Magic Card UID Set — Gen1 (v1)
// Uses standard WRITE_SINGLE_BLOCK (0x21) to hidden magic blocks
// Derived from proxmark3 SetTag15693Uid()
// ============================================================

bool PN5180ISO15693::setUID_v1(uint8_t *uid) {
    // uid[] is LSB-first: uid[0]=LSB, uid[7]=MSB(0xE0)
    // Proxmark3 uid[] is MSB-first, indexes uid[7..4] and uid[3..0]
    // With our LSB-first array, we use uid[0..3] and uid[4..7]

    uint8_t cmds[4][7] = {
        // Unlock part 1: block 0x3E = 00 00 00 00
        { ISO15_REQ_DATARATE_HIGH, ISO15693_WRITE_SINGLE_BLOCK, 0x3E,
          0x00, 0x00, 0x00, 0x00 },
        // Unlock part 2: block 0x3F = 69 96 00 00
        { ISO15_REQ_DATARATE_HIGH, ISO15693_WRITE_SINGLE_BLOCK, 0x3F,
          0x69, 0x96, 0x00, 0x00 },
        // UID part 1: block 0x38 = LSB half (uid[0..3])
        { ISO15_REQ_DATARATE_HIGH, ISO15693_WRITE_SINGLE_BLOCK, 0x38,
          uid[0], uid[1], uid[2], uid[3] },
        // UID part 2: block 0x39 = MSB half (uid[4..7])
        { ISO15_REQ_DATARATE_HIGH, ISO15693_WRITE_SINGLE_BLOCK, 0x39,
          uid[4], uid[5], uid[6], uid[7] }
    };

    loadISO15693Config();
    if (!activateRF()) return false;

    bool ok = true;
    for (int i = 0; i < 4; i++) {
        uint16_t rxLen = 0;
        // Use short timeout — magic tags may or may not respond
        bool resp = transceive(cmds[i], 7, _rxBuf, RX_BUFFER_SIZE, &rxLen, 200);
        if (i >= 2 && (!resp || (_rxBuf[0] & 0x01))) {
            ok = false; // UID write commands must succeed
        }
        delay(10);
    }

    disableRF();
    return ok;
}

// ============================================================
// Magic Card UID Set — Gen2 (v2)
// Uses custom MAGIC_WRITE (0xE0) command
// Derived from proxmark3 SetTag15693Uid_v2()
// ============================================================

bool PN5180ISO15693::setUID_v2(uint8_t *uid) {
    // uid[] is LSB-first: uid[0]=LSB, uid[7]=MSB(0xE0)
    // Proxmark3 uid[] is MSB-first: uid[0]=MSB(0xE0), uid[7]=LSB
    // Proxmark3 sends uid[7],uid[6],uid[5],uid[4] to reg 0x40 (LSB bytes first)
    // So with our LSB-first array, we send uid[0],uid[1],uid[2],uid[3] to reg 0x40
    uint8_t cmds[4][8] = {
        // Unlock part 1
        { ISO15_REQ_DATARATE_HIGH, ISO15693_MAGIC_WRITE, 0x09,
          0x47, 0x3F, 0x03, 0x8B, 0x00 },
        // Unlock part 2
        { ISO15_REQ_DATARATE_HIGH, ISO15693_MAGIC_WRITE, 0x09,
          0x52, 0x00, 0x00, 0x00, 0x00 },
        // UID part 1: register 0x40 = LSB half (uid[0..3])
        { ISO15_REQ_DATARATE_HIGH, ISO15693_MAGIC_WRITE, 0x09,
          0x40, uid[0], uid[1], uid[2], uid[3] },
        // UID part 2: register 0x41 = MSB half (uid[4..7])
        { ISO15_REQ_DATARATE_HIGH, ISO15693_MAGIC_WRITE, 0x09,
          0x41, uid[4], uid[5], uid[6], uid[7] }
    };

    loadISO15693Config();
    if (!activateRF()) return false;

    bool ok = true;
    for (int i = 0; i < 4; i++) {
        uint16_t rxLen = 0;
        bool resp = transceive(cmds[i], 8, _rxBuf, RX_BUFFER_SIZE, &rxLen, 200);
        Serial.printf("[CSET2] cmd %d: resp=%d rxLen=%d flags=0x%02X\n", i, resp, rxLen, resp ? _rxBuf[0] : 0xFF);
        // Only check UID write commands (2,3) for success
        // Unlock commands (0,1) may timeout or return error — that's OK
        if (i >= 2) {
            if (!resp) { ok = false; break; }
            // Some magic cards return 0x00 (success), some return error on flag — 
            // accept any response for UID writes as long as transceive succeeded
        }
        delay(10);
    }

    disableRF();
    return ok;
}

// ============================================================
// Card Emulation
// ============================================================

void PN5180ISO15693::setupEmulation(ISO15693TagInfo *info, uint8_t *blockData) {
    _emuInfo = info;
    _emuData = blockData;
    memset(&emuState, 0, sizeof(emuState));
    emuState.active = true;

    hardReset();
    delay(10);

    // Load ISO 15693 RF config (configures analog frontend for 13.56 MHz)
    loadISO15693Config();

    // Do NOT activate RF — we want to listen, not generate our own field
    // Clear all IRQs
    clearIRQ();

    // Enter transceive state so the receiver is armed
    setIdle();
    activateTransceive();

    // Send zero-length data to advance state machine from "wait TX" to RX mode
    uint8_t sendCmd[] = { PN5180_SEND_DATA, 0x00 };
    spiSend(sendCmd, sizeof(sendCmd));
    waitBusy();
    delay(1);
    clearIRQ();

    // Check transceive state
    uint32_t rfStatus = readRegister(REG_RF_STATUS);
    uint8_t txState = (rfStatus >> 24) & 0x07;
    Serial.printf("[EMU] Setup done, transceive state=%d, RF_STATUS=0x%08X\n", txState, rfStatus);
    Serial.printf("[EMU] Emulating UID: ");
    for (int i = 7; i >= 0; i--) Serial.printf("%02X", _emuInfo->uid[i]);
    Serial.printf(", %d blocks x %d bytes\n", _emuInfo->blockCount, _emuInfo->blockSize);
}

void PN5180ISO15693::teardownEmulation() {
    emuState.active = false;
    emuState.fieldDetected = false;
    hardReset();
    delay(10);
    Serial.println("[EMU] Emulation stopped");
}

void PN5180ISO15693::emulationLoop() {
    uint32_t irq = readRegister(REG_IRQ_STATUS);

    // Track external RF field via edge-triggered IRQs
    if (irq & RFON_DET_IRQ_STAT) {
        if (!emuState.fieldDetected) {
            emuState.fieldDetected = true;
            Serial.println("[EMU] External RF field ON");

            // Re-arm receiver when field appears
            clearIRQ();
            setIdle();
            activateTransceive();

            // Trigger RX mode
            uint8_t sendCmd[] = { PN5180_SEND_DATA, 0x00 };
            spiSend(sendCmd, sizeof(sendCmd));
            waitBusy();
            clearIRQ();
        }
        writeRegister(REG_IRQ_CLEAR, RFON_DET_IRQ_STAT);
    }

    if (irq & RFOFF_DET_IRQ_STAT) {
        if (emuState.fieldDetected) {
            emuState.fieldDetected = false;
            Serial.println("[EMU] External RF field OFF");
        }
        writeRegister(REG_IRQ_CLEAR, RFOFF_DET_IRQ_STAT);
    }

    // Check for received data
    if (irq & RX_IRQ_STAT) {
        uint32_t rxStatus = readRegister(REG_RX_STATUS);
        uint16_t len = (uint16_t)(rxStatus & 0x1FF);
        if (len > 0 && len <= RX_BUFFER_SIZE) {
            uint8_t readCmd[] = { PN5180_READ_DATA, 0x00 };
            spiSend(readCmd, sizeof(readCmd));
            spiReceive(_rxBuf, len);

            Serial.printf("[EMU] RX %d bytes: ", len);
            for (uint16_t i = 0; i < len; i++) Serial.printf("%02X ", _rxBuf[i]);
            Serial.println();

            emuState.cmdCount++;
            handleEmulationCmd(_rxBuf, len);
        }
        writeRegister(REG_IRQ_CLEAR, RX_IRQ_STAT);

        // Re-arm receiver
        setIdle();
        activateTransceive();
        uint8_t sendCmd[] = { PN5180_SEND_DATA, 0x00 };
        spiSend(sendCmd, sizeof(sendCmd));
        waitBusy();
        clearIRQ();
    }
}

void PN5180ISO15693::handleEmulationCmd(uint8_t *cmd, uint8_t len) {
    if (len < 2) return;

    uint8_t flags = cmd[0];
    uint8_t command = cmd[1];
    bool addressed = (flags & ISO15_REQ_ADDRESS) != 0;

    // For addressed non-inventory commands, check UID match
    if (addressed && !(flags & ISO15_REQ_INVENTORY) && len >= 10) {
        if (memcmp(&cmd[2], _emuInfo->uid, 8) != 0) {
            Serial.println("[EMU] Addressed cmd, UID mismatch — ignoring");
            return;
        }
    }

    switch (command) {
        case ISO15693_INVENTORY: {
            // Response: [flags=0x00] [DSFID] [UID 8 bytes]
            uint8_t resp[10];
            resp[0] = 0x00;
            resp[1] = _emuInfo->dsfid;
            memcpy(&resp[2], _emuInfo->uid, 8);
            emuSendResponse(resp, 10);
            Serial.println("[EMU] -> INVENTORY response sent");
            break;
        }
        case ISO15693_READ_SINGLE_BLOCK: {
            uint8_t blockNo = addressed ? cmd[10] : cmd[2];
            if (blockNo >= _emuInfo->blockCount) {
                uint8_t err[] = { 0x01, 0x10 }; // error + block not available
                emuSendResponse(err, 2);
                break;
            }
            uint8_t resp[1 + 32]; // flags + max block size
            resp[0] = 0x00;
            memcpy(&resp[1], &_emuData[blockNo * _emuInfo->blockSize], _emuInfo->blockSize);
            emuSendResponse(resp, 1 + _emuInfo->blockSize);
            Serial.printf("[EMU] -> READ block %d\n", blockNo);
            break;
        }
        case ISO15693_GET_SYSTEM_INFO: {
            uint8_t resp[15];
            resp[0] = 0x00;
            resp[1] = 0x0F; // DSFID, AFI, VICC mem size, IC ref all present
            memcpy(&resp[2], _emuInfo->uid, 8);
            resp[10] = _emuInfo->dsfid;
            resp[11] = _emuInfo->afi;
            resp[12] = _emuInfo->blockCount - 1;
            resp[13] = _emuInfo->blockSize - 1;
            resp[14] = _emuInfo->icRef;
            emuSendResponse(resp, 15);
            Serial.println("[EMU] -> SYSTEM INFO response sent");
            break;
        }
        default:
            Serial.printf("[EMU] Unhandled cmd: 0x%02X (flags=0x%02X)\n", command, flags);
            break;
    }
}

bool PN5180ISO15693::emuSendResponse(uint8_t *data, uint8_t len) {
    // PN5180 SEND_DATA — auto-appends CRC with ISO 15693 config loaded
    clearIRQ();
    setIdle();
    activateTransceive();

    uint8_t sendBuf[2 + 64];
    sendBuf[0] = PN5180_SEND_DATA;
    sendBuf[1] = 0x00;
    memcpy(&sendBuf[2], data, len);
    bool ok = spiSend(sendBuf, len + 2);

    // Wait briefly for TX to complete
    unsigned long t = millis();
    while (millis() - t < 50) {
        if (readRegister(REG_IRQ_STATUS) & TX_IRQ_STAT) break;
        yield();
    }

    return ok;
}
