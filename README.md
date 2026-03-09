# Xiaomi ADB Sideload Flash Tool

A native Windows GUI tool for flashing official Xiaomi firmware via ADB sideload — no ADB/Fastboot command-line tools required. Built in Delphi (Object Pascal).

---

## What It Does

This tool replicates the full Xiaomi ADB sideload workflow in a single click:

1. **Connects** to a Xiaomi device in sideload/recovery mode via USB
2. **Reads device info** (codename, version, serial, codebase, branch, region, romzone)
3. **Generates a firmware signature** by communicating with Xiaomi's update server (`update.miui.com`)


### Firmware Sign Generation

The tool communicates with Xiaomi's official update validation server:

1. Computes MD5 hash of the firmware `.zip` file
2. Builds a JSON request with device info + firmware hash
3. Encrypts the JSON with AES-128-CBC (key: `miuiotavalided11`, IV: `0102030405060708`)
4. Base64-encodes the ciphertext (no line breaks)
5. URL-encodes matching `curl_easy_escape` behavior (only `A-Za-z0-9-_.~` left unencoded)
6. POSTs to `http://update.miui.com/updates/miotaV3.php` with `User-Agent: MiTunes_UserAgent_v3.0`
7. Decrypts the server response (URL-decode → Base64-decode → AES-CBC decrypt → PKCS7 unpad)
8. Extracts the `Validate` key from the `PkgRom` JSON field
9. Saves to `validate.key`

### ADB Sideload Protocol

The sideload uses the standard Android ADB protocol over USB bulk transfers:

1. Sends `ADB_CONNECT` with `host::` payload
2. Waits for `sideload::` response from recovery
3. Opens `sideload-host:{filesize}:{chunksize}:{validate_key}:0` channel
4. Device requests blocks by number via `ADB_WRTE`
5. Tool reads the requested 64KB chunk from the firmware file and sends it back
6. Repeats until all blocks are transferred

### USB Connection Strategy

The tool tries three connection methods in order:

1. **WinUSB direct** — SetupAPI device enumeration → registry `DeviceInterfaceGUIDs` → `CreateFile` → `WinUsb_Initialize`. If init fails, auto-installs WinUSB driver via `.inf` + `pnputil`
2. **libusb + UsbDk** — `libusb_init` → `libusb_set_option(LIBUSB_OPTION_USE_USBDK)` → device list scan
3. **libusb default** — Standard libusb backend, scans device list + tries known VID:PID pairs

## Requirements

- **DCPcrypt2** — for AES-128 (Rijndael) and MD5 hashing
- **Indy** (TIdHTTP) — for HTTP POST to Xiaomi server
- **WinUSB driver** — installed on the Xiaomi device (tool auto-installs if missing)
- Optional: **libusb-1.0.dll** in app folder for fallback connection

### Device Requirements

- Xiaomi device booted into **sideload mode** (Mi Recovery → "Install update via USB")
- Official firmware `.zip` matching your device region (e.g., `UNFMIXM` for Global)



### Unit1.pas Key Functions

| Function | Description |
|----------|-------------|
| `TryWinUSBDirect` | WinUSB device connection with auto driver install |
| `FindXiaomiDevicePath` | SetupAPI device enumeration via registry GUIDs |
| `TryAutoInstallWinUSBDriver` | Creates `.inf` + runs `pnputil` as admin |
| `scan_for_device` | Tries WinUSB → libusb+UsbDk → libusb default |
| `connect_device_read_info` | ADB handshake + reads device properties |
| `generate_md5_hash` | Chunked MD5 for files >4GB with progress |
| `generate_firmware_sign` | Full sign pipeline: hash → encrypt → POST → decrypt → save |
| `start_sideload` | ADB sideload protocol with progress bar |
| `AES_CBC_Encrypt` / `Decrypt` | Manual CBC using ECB (matches C tiny-aes) |
| `CurlEscape` | URL encoding matching `curl_easy_escape` (RFC 3986) |

---

## Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `WinUSB init failed (error 122)` | WinUSB driver not installed for device | Tool auto-installs. If fails, use [Zadig](https://zadig.akeo.ie/) to install WinUSB driver for your Xiaomi device |
| `Device not found` | Device not in sideload mode | Boot to Mi Recovery → "Install update via USB" |
| `Server code 2001: Can't install unofficial ROM` | Wrong firmware region or corrupted file | Use official firmware matching your device region (e.g., Global = `MIXM`) |
| `MD5 mismatch` | Firmware file corrupted during download | Re-download and verify MD5 matches the official hash |

## License

MIT
