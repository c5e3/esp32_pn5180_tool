# ESP32 PN5180 NFC Tool

A web-based NFC tag tool running on an ESP32 with an NXP PN5180 RF frontend.  
Connect to it over WiFi, then read, write, clone, and emulate ISO 15693 tags from any browser — no app required.

---

## Hardware

| Component | Details |
|-----------|---------|
| MCU | ESP32 (38-pin DevKit / esp32dev) |
| RF Frontend | NXP PN5180 (ISO 15693 / ISO 14443-A/B capable) |
| Interface | SPI (VSPI) |
| Power | 3.3 V logic; PN5180 antenna powered from 5 V |

### Pinout

| PN5180 Pin | ESP32 Pin | Notes |
|------------|-----------|-------|
| NSS (CS) | GPIO 5 | Chip select |
| MOSI | GPIO 23 | VSPI default |
| MISO | GPIO 19 | VSPI default |
| SCK | GPIO 18 | VSPI default |
| BUSY | GPIO 16 | Ready/Busy signal |
| RST | GPIO 17 | Hardware reset |
| 3.3 V | 3V3 | Logic supply |
| GND | GND | |
| 5 V (TVDD) | 5 V | RF power supply |

Configurable in `src/config.h` (`PN5180_NSS`, `PN5180_BUSY`, `PN5180_RST`).

---

## Features

### Current (ISO 15693 only)

- **Read tag** — inventory, Get System Info, read all blocks
- **Write tag** — write all blocks to a compatible tag (with 3× retry per block)
- **Magic card UID set** — Gen1 (v1) and Gen2 (v2) magic card support
- **Tag emulation** — emulate an ISO 15693 dump; UID and block data are editable before starting
- **File Manager** — save, load, rename, delete, upload, and download files stored in SPIFFS; any file type is supported
- **Chunked file upload** — large files uploaded via multipart streaming directly to SPIFFS (tested up to 500 KB); SPIFFS-full errors are detected and reported
- **Web UI** — single-page app served from the ESP32 itself; status bar shows connection state and live SPIFFS usage

### Data model

One dump is held in memory at a time. Loading or reading a tag in any tab updates all three tabs (Read / Write / Emulate) simultaneously — no reload required when switching tabs.

### WiFi Modes

Set `CFG_WIFI_MODE` in `src/config.h`:

| Mode | Description |
|------|-------------|
| `CFG_WIFI_STA` | Connect to existing network (credentials in `config.h`) |
| `CFG_WIFI_AP` | Host its own AP — SSID `NFC-Tool`, password `nfc12345`, IP `192.168.4.1` |

If STA connection fails the firmware automatically falls back to AP mode.

---

## Build & Flash

### Requirements

- [PlatformIO](https://platformio.org/) (CLI or VS Code extension)
- ESP32 Arduino platform (`espressif32`)
- `bblanchon/ArduinoJson ^6.21.0` (installed automatically by PlatformIO)

### Configuration

Copy the example config and fill in your WiFi credentials:

```sh
cp src/config.h.example src/config.h
# then edit src/config.h — config.h is in .gitignore
```

### Build & Upload Firmware

```sh
pio run --target upload
```

### Build & Upload Filesystem Image (SPIFFS)

The web UI (`src/web_ui.h`) is compiled into the firmware, so the SPIFFS filesystem is only used for storing files.  
You still need to create an empty filesystem on first flash:

```sh
pio run --target uploadfs
```

> If you skip this step, SPIFFS will fail to mount and file save/load will not work.

### Monitor Serial Output

```sh
pio device monitor
```

Default baud: `115200`.  
The ESP32 prints its IP address on successful WiFi connection.

---

## REST API

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/read` | Read tag (inventory + sysinfo + all blocks) |
| POST | `/api/write` | Write all blocks to tag |
| POST | `/api/csetuid` | Set UID on magic card |
| GET | `/api/dumps` | List files (`[{name, size}, ...]`) |
| GET | `/api/dump?name=xxx` | Load a dump (JSON) |
| POST | `/api/dump?name=xxx` | Save a dump (JSON) |
| DELETE | `/api/dump?name=xxx` | Delete a file |
| POST | `/api/dump/rename` | Rename a file (`{oldName, newName}`) |
| GET | `/api/rawfile?name=xxx` | Download raw file bytes |
| POST | `/api/upload?name=xxx` | Upload a file (multipart/form-data, chunked) |
| GET | `/api/spiffs` | SPIFFS usage (`{used, total}`) |
| POST | `/api/emulate/start` | Start emulation from a saved dump |
| POST | `/api/emulate/stop` | Stop emulation |
| GET | `/api/emulate/status` | Emulation status (`active`, `fieldDetected`, `cmdCount`) |

---

## Planned / WIP / TODO

### Major feature upgrade (next)
- **Multi-standard support** — implement read & write for all RF standards the PN5180 hardware supports:
  - ISO 14443-A (MIFARE Classic, MIFARE Ultralight, NTAG)
  - ISO 14443-B
  - ISO 15693 (current)
  - FeliCa (JIS X 6319-4)
  - ISO 18092 (NFC-IP1)
- **Emulation for supported standards** — extend the emulation engine beyond ISO 15693
- Unified tag abstraction so the web UI and dump format remain standard-agnostic

---

## Project Structure

```
platformio.ini          PlatformIO build config
src/
  config.h              Local config (WiFi creds, pins) — gitignored
  config.h.example      Template for config.h
  main.cpp              WiFi setup, web server routes, upload/SPIFFS handlers
  PN5180ISO15693.h/.cpp PN5180 SPI driver + ISO 15693 protocol
  DumpManager.h/.cpp    SPIFFS file management, JSON serialisation, usedBytes()
  web_ui.h              Embedded single-page web application (PROGMEM)
data/                   SPIFFS filesystem root (used for stored dumps/files)
```
