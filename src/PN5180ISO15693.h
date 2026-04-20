#ifndef PN5180ISO15693_H
#define PN5180ISO15693_H

#include <Arduino.h>
#include <SPI.h>

// PN5180 SPI Host Interface Commands (NXP PN5180 Datasheet §11.4.3.3)
#define PN5180_WRITE_REGISTER           0x00
#define PN5180_WRITE_REGISTER_OR_MASK   0x01
#define PN5180_WRITE_REGISTER_AND_MASK  0x02
#define PN5180_READ_REGISTER            0x04
#define PN5180_SEND_DATA                0x09
#define PN5180_READ_DATA                0x0A
#define PN5180_LOAD_RF_CONFIG           0x11
#define PN5180_READ_EEPROM              0x07
#define PN5180_RF_ON                    0x16
#define PN5180_RF_OFF                   0x17

// PN5180 Register Addresses (§11.9.1 Table 73)
#define REG_SYSTEM_CONFIG   0x00
#define REG_IRQ_ENABLE      0x01
#define REG_IRQ_STATUS      0x02
#define REG_IRQ_CLEAR       0x03
#define REG_RX_STATUS       0x13
#define REG_TX_CONFIG        0x18
#define REG_RF_STATUS       0x1D

// IRQ Status bits (§11.9.1 Table 76)
#define RX_IRQ_STAT         (1U << 0)
#define TX_IRQ_STAT         (1U << 1)
#define IDLE_IRQ_STAT       (1U << 2)
#define RFOFF_DET_IRQ_STAT  (1U << 6)
#define RFON_DET_IRQ_STAT   (1U << 7)
#define TX_RFOFF_IRQ_STAT   (1U << 8)
#define TX_RFON_IRQ_STAT    (1U << 9)

// ISO 15693 Command Codes
#define ISO15693_INVENTORY          0x01
#define ISO15693_READ_SINGLE_BLOCK  0x20
#define ISO15693_WRITE_SINGLE_BLOCK 0x21
#define ISO15693_GET_SYSTEM_INFO    0x2B
#define ISO15693_MAGIC_WRITE        0xE0

// ISO 15693 Request Flags
#define ISO15_REQ_DATARATE_HIGH 0x02
#define ISO15_REQ_INVENTORY     0x04
#define ISO15_REQ_ADDRESS       0x20
#define ISO15_REQ_OPTION        0x40

// Receive buffer for PN5180 responses
#define RX_BUFFER_SIZE 64

// Max ISO 15693 command frame (before PN5180 SEND_DATA prefix)
#define MAX_CMD_FRAME_SIZE 32

struct ISO15693TagInfo {
    uint8_t uid[8];       // UID in LSB-first order (as received from air)
    uint8_t dsfid;
    uint8_t afi;
    uint8_t blockSize;    // bytes per block (typically 4)
    uint8_t blockCount;   // number of blocks
    uint8_t icRef;
    bool valid;
};

enum ISO15693ErrorCode {
    EC_NO_CARD = -1,
    ISO15693_EC_OK = 0,
    ISO15693_EC_NOT_SUPPORTED = 0x01,
    ISO15693_EC_NOT_RECOGNIZED = 0x02,
    ISO15693_EC_OPTION_NOT_SUPPORTED = 0x03,
    ISO15693_EC_UNKNOWN_ERROR = 0x0F,
    ISO15693_EC_BLOCK_NOT_AVAILABLE = 0x10,
    ISO15693_EC_BLOCK_ALREADY_LOCKED = 0x11,
    ISO15693_EC_BLOCK_IS_LOCKED = 0x12,
    ISO15693_EC_BLOCK_NOT_PROGRAMMED = 0x13,
    ISO15693_EC_BLOCK_NOT_LOCKED = 0x14,
    ISO15693_EC_CUSTOM_CMD_ERROR = 0xA0
};

struct EmulationState {
    volatile bool active;
    volatile bool fieldDetected;
    volatile uint32_t cmdCount;
};

class PN5180ISO15693 {
public:
    PN5180ISO15693(uint8_t nssPin, uint8_t busyPin, uint8_t rstPin);
    void begin();
    void hardReset();

    // High-level tag operations (manages RF field on/off)
    // All UIDs are in LSB-first format (uid[0]=LSB, uid[7]=MSB=0xE0)
    bool inventory(uint8_t *uid);
    bool readTag(ISO15693TagInfo *info, uint8_t *data, uint16_t maxDataLen);
    bool writeTag(uint8_t blockCount, uint8_t blockSize, uint8_t *data,
                  uint8_t *writtenCount, uint8_t *actualBlockCount);
    bool setUID_v1(uint8_t *uid);
    bool setUID_v2(uint8_t *uid);

    // Diagnostics
    void printFirmwareVersion();

    // Emulation
    EmulationState emuState;
    void setupEmulation(ISO15693TagInfo *info, uint8_t *blockData);
    void teardownEmulation();
    void emulationLoop();

private:
    uint8_t _nss, _busy, _rst;
    SPISettings _spiSettings;
    uint8_t _rxBuf[RX_BUFFER_SIZE];
    uint16_t _timeout = 1000;

    // SPI communication (NXP §11.4.1)
    bool spiSend(uint8_t *buf, size_t len);
    bool spiReceive(uint8_t *buf, size_t len);
    bool waitBusy();
    bool waitReady();

    // Register operations
    uint32_t readRegister(uint8_t reg);
    void writeRegister(uint8_t reg, uint32_t val);
    void orRegister(uint8_t reg, uint32_t mask);
    void andRegister(uint8_t reg, uint32_t mask);
    void clearIRQ();

    // RF field control
    void loadISO15693Config();
    bool activateRF();
    bool disableRF();
    void setIdle();
    void activateTransceive();
    void sendEndOfFrame();
    bool readEEPROM(uint8_t addr, uint8_t *buf, uint8_t len);

    // ISO 15693 transceive: send command, wait for response, read response
    bool transceive(uint8_t *txData, uint8_t txLen,
                    uint8_t *rxBuf, uint8_t rxBufSize,
                    uint16_t *rxLen, uint16_t timeoutMs = 500);

    // Mid-level ISO 15693 commands (RF must already be on)
    bool getSystemInfo(uint8_t *uid, ISO15693TagInfo *info);
    bool readSingleBlock(uint8_t *uid, uint8_t blockNo, uint8_t *data, uint8_t blockSize);
    bool writeSingleBlock(uint8_t *uid, uint8_t blockNo, uint8_t *data, uint8_t blockSize);

    // Emulation internals
    ISO15693TagInfo *_emuInfo;
    uint8_t *_emuData;
    void handleEmulationCmd(uint8_t *cmd, uint8_t len);
    bool emuSendResponse(uint8_t *data, uint8_t len);
};

#endif
