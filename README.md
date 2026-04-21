# ESP32 PN5180 RFID Tool

A web-based RFID/NFC tag tool running on an ESP32 with an NXP PN5180 RF frontend.
Connect to it over WiFi, then read, write, clone, and emulate ISO 15693 and
ISO 14443-A / MIFARE tags from any browser — no app required.

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
| IRQ | GPIO 4 | IRQ — fast wake from auth/read polling |
| 3.3 V | 3V3 | Logic supply |
| GND | GND | |
| 5 V (TVDD) | 5 V | RF power supply |

Configurable in `src/config.h` (`PN5180_NSS`, `PN5180_BUSY`, `PN5180_RST`, `PN5180_IRQ`).

---

## Features

### ISO 15693 (Vicinity / NFC-V)

- **Read tag** — inventory, Get System Info, read all blocks
- **Write tag** — write all blocks to a compatible tag (3× retry per block)
- **Magic card UID set** — Gen1 (v1) and Gen2 (v2) magic card support
- **Tag emulation** — emulate an ISO 15693 dump; UID and block data are
  editable before starting

### ISO 14443-A / MIFARE

- **Auto-detect protocol** — `/api/read` first probes ISO 14443-A (WUPA), then
  falls back to ISO 15693, so the user just clicks *Read Tag*
- **Read MIFARE Classic** (1K / 4K / Mini, plus MIFARE Plus SL1) with a
  **dictionary attack**:
  - Files in `/dicts/mfc_*.txt` are loaded automatically (one 12-hex-char key
    per line)
  - Default well-known keys (`FFFFFFFFFFFF`, `A0A1A2A3A4A5`, …) tried first
  - Per-sector key reuse + IRQ-driven auth (~5 ms wrong-key reject)
  - Per-sector trailer key A/B tracked in the dump (`keyUsed`) and visualised
    in the UI
- **Read MIFARE Ultralight** — plain page read
- **Write MIFARE Classic / Ultralight** — `/api/write` dispatches on the
  dump's `type` field. For MFC, sector keys are looked up from:
  1. The dump's own sector trailers
  2. Default keys
  3. The user's enabled `mfc_*.txt` dictionaries
- **Magic card write — auto-detected, no UI choice required**. The firmware
  probes the live card before writing and uses whichever backdoor it supports:

  | Type | Mechanism | Block 0 (UID) | Sector trailers |
  |------|-----------|---------------|-----------------|
  | **Gen 1A / 1B** | `0x40` + `0x43` magic wakeup, unauth WRITE | ✓ | ✓ |
  | **Gen 2 / CUID** | Standard auth, but block 0 is writeable | ✓ | ✓ (with key) |
  | **Gen 3** | `0x90 0xFB/0xF0 0xCC 0xCC` APDU | ✓ | – |
  | **Gen 4 GTU** | `0xCF` backdoor read/write any block | ✓ | ✓ |
  | **GDM / USCUID** | Magic auth `0x80` + GDM-write `0xA8` | ✓ | ✓ |

  Detected magic flags are reported back in the `/api/write` response and
  shown in the toast (e.g. *"Wrote 63 blocks (Gen 4 GTU)"*).
- **Optional toggles** in the Write tab:
  - *Write block 0 (UID via magic backdoor)* — uses Gen 4 → Gen 3 → CUID
    fallback, in that order
  - *Write sector trailers* — disabled by default; trailers can permanently
    brick a sector if the access bits are wrong
- **Card fingerprinting** (`/api/cident`, port of proxmark3 `hf mf info`):
  Gen 1A/1B, Gen 2 / CUID, Gen 3, Gen 4 GTU, Gen 4 GDM / USCUID, FUID,
  Super Card, Fudan / Infineon backdoor key match + block-0 fingerprint table

### Common

- **File Manager** — save, load, rename, delete, upload, and download files
  stored in SPIFFS; any file type is supported
- **Dictionary manager** — toggle, reorder, upload, download, delete
  `mfc_*.txt` keyfiles in `/dicts/`
- **Chunked file upload** — large files uploaded via multipart streaming
  directly to SPIFFS (tested up to 500 KB); SPIFFS-full errors detected and
  reported
- **OTA firmware update** — `POST /api/ota` with the raw `firmware.bin`
- **Web UI** — single-page app served from the ESP32; status bar shows
  connection state and live SPIFFS usage

### Data model

One dump is held in memory at a time. Loading or reading a tag in any tab
updates all three tabs (Read / Write / Emulate) simultaneously — no reload
required when switching tabs. The dump JSON carries `type`, `uid`, `sak`,
`atqa`, `blockSize`, `blockCount`, `data` (concatenated hex), `blockRead`
bitmask, and per-sector `keyUsed`.

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

The web UI (`src/web_ui.h`) is compiled into the firmware, so the SPIFFS
filesystem is only used for storing files (dumps + dictionaries).
You still need to flash the filesystem on first install — the bundled
`data/dicts/mfc_std.txt` and `mfc_user.txt` ship with it:

```sh
pio run --target uploadfs
```

> If you skip this step, SPIFFS will fail to mount and dictionary attacks +
> dump save/load will not work.

### OTA updates

After the first USB flash, subsequent updates can be pushed over WiFi:

```powershell
Invoke-WebRequest http://<device-ip>/api/ota -Method POST `
    -InFile .pio\build\esp32dev\firmware.bin
```

### Monitor Serial Output

```sh
pio device monitor
```

Default baud: `115200`. The ESP32 prints its IP address on successful WiFi
connection.

---

## REST API

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/read` | Auto-detect (ISO 14443-A → ISO 15693) + full read. Async: returns 202 with `phase`/`block`/`totalBlocks`/`keyType` while running |
| POST | `/api/write` | Write all blocks. Body: `{type, uid, blockSize, blockCount, data, setUid?, writeTrailers?}` — `type` is the dump's tag type (e.g. `MFC1K`, `ISO15693`) |
| POST | `/api/csetuid` | ISO 15693 magic-card UID set (`{uid, version: "v1"\|"v2"}`) |
| GET | `/api/cident` | MIFARE Classic clone fingerprint (magic probes + backdoor keys) |
| GET | `/api/dumps?folder=dumps\|dicts` | List files |
| GET | `/api/dump?name=xxx` | Load a dump (JSON) |
| POST | `/api/dump?name=xxx` | Save a dump (JSON) |
| DELETE | `/api/dump?name=xxx[&folder=dumps\|dicts]` | Delete a file |
| POST | `/api/dump/rename` | Rename a file (`{oldName, newName}`) |
| POST | `/api/dicts/toggle` | Enable/disable a dictionary (`{name, enabled}`) |
| POST | `/api/dicts/order` | Reorder dictionaries (JSON array of names) |
| GET | `/api/rawfile?name=xxx[&folder=…]` | Download raw file bytes |
| POST | `/api/upload?name=xxx[&folder=…]` | Upload a file (multipart, chunked) |
| GET | `/api/spiffs` | SPIFFS usage (`{used, total}`) |
| POST | `/api/emulate/start` | Start emulation from a saved dump (ISO 15693 only) |
| POST | `/api/emulate/stop` | Stop emulation |
| GET | `/api/emulate/status` | Emulation status (`active`, `fieldDetected`, `cmdCount`) |
| POST | `/api/ota` | OTA firmware update (raw `firmware.bin` body) |

### `/api/write` magic flags

The `magic` field in the response is a bitmask:

| Bit | Value | Meaning |
|-----|-------|---------|
| 0 | 0x01 | Gen 1A |
| 1 | 0x02 | Gen 1B |
| 2 | 0x04 | Gen 2 / CUID |
| 3 | 0x08 | Gen 3 |
| 4 | 0x10 | Gen 4 GTU |
| 5 | 0x20 | GDM / USCUID |

---

## Planned / WIP / TODO

- **More 14443-A targets** — NTAG21x (read, write, password auth, NDEF helpers),
  MIFARE DESFire, MIFARE Plus SL3 (AES)
- **Other RF standards** — ISO 14443-B, FeliCa (JIS X 6319-4), ISO 18092 (NFC-IP1)
- **Emulation for ISO 14443-A** — currently only ISO 15693 is emulated
- **MFC nested attack** — recover unknown keys when at least one is known
- Unified tag abstraction so the web UI and dump format remain
  standard-agnostic

---

## Project Structure

```
platformio.ini          PlatformIO build config
src/
  config.h              Local config (WiFi creds, pins) — gitignored
  config.h.example      Template for config.h
  main.cpp              WiFi setup, web server routes, async read task
  PN5180ISO15693.h/.cpp PN5180 SPI driver + ISO 15693 protocol + emulation
  PN5180MIFARE.h/.cpp   ISO 14443-A + MIFARE Classic/Ultralight read/write,
                        magic-card detection + write (Gen 1/2/3/4/GDM),
                        clone fingerprinting
  FileManager.h/.cpp    SPIFFS file management, JSON (de)serialisation,
                        dictionary loading
  web_ui.h              Embedded single-page web application (PROGMEM)
data/
  dicts/                Default MFC key dictionaries (mfc_std.txt, mfc_user.txt)
```
