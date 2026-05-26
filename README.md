# ESPHome WireGuard – RP2040 / Pico W Port

This is a modified version of the official ESPHome `wireguard` component that
adds support for the **Raspberry Pi Pico W** (and Pico 2W) running on the
`rp2040` platform with the CYW43 WiFi chip.

---

## How it works

The official component uses Espressif's `esp_wireguard` IDF library which
only compiles for ESP32/ESP8266/BK72xx.

This port swaps in **[WireGuard-ESP32-Arduino](https://github.com/ciniml/WireGuard-ESP32-Arduino)**
by Kenta Ida (`ciniml`), which is a pure C++ WireGuard implementation built on
top of **lwIP** — the same TCP/IP stack that the `arduino-pico` framework uses
for the Pico W's CYW43 chip. No IDF, no platform-specific hardware crypto — it
runs on any lwIP host.

The ESPHome component interface (`setup`, `loop`, `update`, sensors, actions,
conditions) is **100% identical** to the upstream component, so your existing
YAML configs work without changes.

---

## Files

```
esphome/components/wireguard/
├── __init__.py     # Python config validator – adds rp2040 to allowed platforms
├── wireguard.h     # C++ header – #ifdef USE_RP2040 selects the lwIP backend
└── wireguard.cpp   # C++ implementation – dual-path (IDF or lwIP)

pico_w_wireguard_example.yaml   # Ready-to-use example config
```

---

## Installation

### 1. Copy the component

Place the `esphome/components/wireguard/` folder into your ESPHome config
directory (next to your `.yaml` files):

```
config/
├── esphome/
│   └── components/
│       └── wireguard/
│           ├── __init__.py
│           ├── wireguard.h
│           └── wireguard.cpp
├── pico_w_wireguard_example.yaml
└── secrets.yaml
```

### 2. Reference the component in your YAML

```yaml
external_components:
  - source:
      type: local
      path: esphome/components
    components: [wireguard]
```

### 3. Secrets

Add these to your `secrets.yaml`:

```yaml
wifi_ssid: "YourSSID"
wifi_password: "YourPassword"
wg_private_key: "YOUR_BASE64_PRIVATE_KEY="
wg_server_host: "your.ddns.hostname.com"
wg_server_pubkey: "YOUR_SERVER_BASE64_PUBLIC_KEY="
api_key: "YOUR_API_KEY"
ota_password: "YOUR_OTA_PASSWORD"
```

Generate WireGuard keys:
```bash
# On Linux/Mac:
wg genkey | tee privatekey | wg pubkey > publickey
cat privatekey   # paste as wg_private_key
cat publickey    # register with your WireGuard server
```

### 4. WireGuard server side

On your Home Assistant machine (or router), add a peer for the Pico W:

```ini
[Peer]
# Pico W
PublicKey = <contents of publickey file>
AllowedIPs = 10.6.0.2/32
```

---

## Known limitations on RP2040

| Feature | Status |
|---------|--------|
| Basic tunnel (full or split) | ✅ Works |
| Preshared key | ✅ Works |
| Persistent keepalive | ✅ Works |
| Multiple `allowed_ips` entries | ⚠️ Only first entry reliable; use `0.0.0.0/0` for full tunnel |
| Hardware crypto acceleration | ❌ Software only (CYW43 has no WireGuard offload) |
| Handshake timestamp sensor | ⚠️ Approximate (captured at connect time, not from the protocol) |
| OTA updates over tunnel | ✅ Works – set `wifi.use_address` to the WireGuard IP |

### RAM budget

WireGuard crypto (ChaCha20-Poly1305, Curve25519, BLAKE2s) needs ~40–50 KB of
heap. The Pico W has 264 KB total. A minimal ESPHome firmware with WiFi,
WireGuard, and a few sensors typically sits around 160–180 KB of heap usage.
**Leave `logger` at `WARNING` or `ERROR` in production to save RAM.**

---

## Tested with

- Raspberry Pi Pico W (`rpipicow`)
- arduino-pico 4.x
- ESPHome 2026.x
- WireGuard-ESP32-Arduino 0.3.1
- wg-easy server on Home Assistant OS

---

## Credits

- Original ESPHome WireGuard component: [@droscy](https://github.com/droscy)
- WireGuard-ESP32-Arduino library: [@ciniml](https://github.com/ciniml)
- WireGuard protocol: Jason A. Donenfeld
