# WiFi Security Audit Tool — Full Documentation

Complete technical documentation for developers and collaborators. Covers installation, architecture, every file, every API endpoint, every function, and the design decisions behind them.

---

## Table of Contents

1. [Installation](#1-installation)
2. [Running the Tool](#2-running-the-tool)
3. [Architecture Overview](#3-architecture-overview)
4. [File Structure](#4-file-structure)
5. [wifisecaudit.py — Web Server](#5-wifisecauditpy--web-server)
6. [modules/pmkid_capture.py — WiFi Engine](#6-modulespmkid_capturepy--wifi-engine)
7. [templates/index.html — Frontend Dashboard](#7-templatesindexhtml--frontend-dashboard)
8. [API Reference](#8-api-reference)
9. [Deauthentication — How It Works](#9-deauthentication--how-it-works)
10. [PMKID Capture — How It Works](#10-pmkid-capture--how-it-works)
11. [Passive Sniffer & Handshake Capture](#11-passive-sniffer--handshake-capture)
12. [Hidden SSID Reveal](#12-hidden-ssid-reveal)
13. [Handshake Export & Cracking](#13-handshake-export--cracking)
14. [External Tool Dependencies](#14-external-tool-dependencies)
15. [New Modules Reference](#15-new-modules-reference)
16. [Design Decisions](#16-design-decisions)
17. [Common Workflows](#17-common-workflows)
18. [Troubleshooting](#18-troubleshooting)

---

## 1. Installation

### System Requirements

- **OS**: Linux (Kali Linux recommended, Ubuntu/Debian also work)
- **Python**: 3.10 or newer
- **Privileges**: Root (sudo) — required for monitor mode and packet injection
- **WiFi adapter**: Must support monitor mode and packet injection (e.g., Alfa AWUS036ACH, TP-Link TL-WN722N v1)

### Install Dependencies

```bash
# System packages
sudo apt update
sudo apt install -y aircrack-ng python3 python3-pip

# Python packages
cd wifisecaudit/
pip3 install -r requirements.txt
```

### requirements.txt

```
flask>=3.0.0    — Web server framework
scapy>=2.5.0    — Packet crafting/capture library
```

### Verify Installation

```bash
# Check aircrack-ng suite
which aireplay-ng airmon-ng airodump-ng

# Check Python deps
python3 -c "import flask; import scapy; print('OK')"

# Check WiFi adapter supports monitor mode
iw phy | grep -A 5 "monitor"
```

---

## 2. Running the Tool

### Basic Usage

```bash
sudo python3 wifisecaudit.py
```

Open http://localhost:8080 in your browser.

### Command-Line Flags

| Flag | Description |
|------|-------------|
| `--public` | Bind to 0.0.0.0 instead of 127.0.0.1 (accessible from other machines) |
| `--verbose` | Enable Flask/Werkzeug HTTP request logging (off by default to reduce noise) |
| `--no-root-check` | Skip the root privilege warning prompt |

### Examples

```bash
# Standard usage
sudo python3 wifisecaudit.py

# Accessible from other machines on your network
sudo python3 wifisecaudit.py --public

# Debug mode with request logging
sudo python3 wifisecaudit.py --verbose

# Non-interactive (scripts/automation)
sudo python3 wifisecaudit.py --no-root-check
```

---

## 3. Architecture Overview

```
Browser (index.html + cracking.js + eviltwin.js + recon.js)
  │  HTTP fetch() calls
  ▼
Flask routes (wifisecaudit.py + routes/*.py Blueprints)
  │  Python method calls
  ▼
Modules (modules/*.py)
  │  subprocess / scapy / threading
  ▼
OS tools (aircrack-ng, hostapd, dnsmasq, reaver, nmap, hcxdumptool, tshark, wash, ...)
  │
  ▼
WiFi radio (monitor / managed / AP mode)
```

The tool is a modular web app:
- **Frontend**: Single HTML page with 4 tabs, vanilla JavaScript, no frameworks. New tab JS in separate files.
- **Backend**: Flask web server with 4 Blueprints (cracking, mac, eviltwin, recon) + core routes in wifisecaudit.py
- **Core Engine**: `PMKIDCapture` class (untouched) for scanning, capture, deauth, clients
- **Extension Modules**: 14 new modules for cracking, evil twin, MITM, WPA3, WPS, nmap, IDS, etc.
- **Integration Pattern**: All modules accept `log_fn=pmkid._log` to write to the shared log

All WiFi operations happen server-side. The browser is just a control panel.

**Constraint**: Single WiFi adapter — only one mode at a time (monitor / managed / AP). `ModeManager` serializes transitions. Optional dual adapter mode uses two adapters simultaneously.

---

## 4. File Structure

```
wifisecaudit/
├── wifisecaudit.py              ← Flask web server, core routes, module init
├── modules/
│   ├── __init__.py               ← Package init
│   ├── pmkid_capture.py          ← Core WiFi engine (scan, capture, deauth, clients)
│   ├── aircrack_runner.py        ← Aircrack-ng cracking subprocess wrapper
│   ├── wordlist_manager.py       ← Wordlist listing/upload/management
│   ├── mode_manager.py           ← Central adapter mode controller (managed/monitor/AP)
│   ├── mac_spoofer.py            ← MAC address spoofing (macchanger)
│   ├── evil_twin.py              ← Rogue AP (hostapd + dnsmasq), driver reload on cleanup
│   ├── captive_portal.py         ← Fake login HTTP server (port 80, 3 templates)
│   ├── arp_spoofer.py            ← Bidirectional ARP spoofing (dsniff)
│   ├── traffic_sniffer.py        ← HTTP traffic capture (tshark)
│   ├── nmap_scanner.py           ← Nmap wrapper with XML result parsing
│   ├── wps_attack.py             ← WPS pixie-dust + brute-force (reaver/bully)
│   ├── wps_scanner.py            ← WPS network detection (wash)
│   ├── wpa3_attack.py            ← WPA3-SAE attacks + Dragonblood vulnerability scanner
│   ├── dual_interface.py         ← Dual WiFi adapter management
│   ├── handshake_validator.py    ← Handshake validation (aircrack-ng + tshark)
│   ├── attack_monitor.py         ← Wireless IDS (deauth/disassoc/evil twin detection)
│   └── report_generator.py       ← PDF audit report generation (fpdf2)
├── routes/
│   ├── __init__.py               ← Package init
│   ├── cracking.py               ← Cracking & wordlist API routes (Blueprint)
│   ├── mac.py                    ← MAC spoofing & interface reset routes (Blueprint)
│   ├── eviltwin.py               ← Evil twin, ARP spoof, traffic, host discovery (Blueprint)
│   └── recon.py                  ← Nmap, WPS, WPA3, dual adapter, IDS, reports (Blueprint)
├── templates/
│   ├── index.html                ← Single-page web dashboard (4 tabs)
│   └── captive/
│       ├── wifi_login.html       ← Generic WiFi login captive portal
│       ├── router_update.html    ← Fake router firmware update page
│       └── hotel_login.html      ← Hotel/cafe WiFi login page
├── static/
│   ├── cracking.js               ← Cracking tab JavaScript
│   ├── eviltwin.js               ← Evil Twin tab JavaScript
│   └── recon.js                  ← Recon tab JavaScript
├── data/
│   ├── wordlists/                ← User-uploaded wordlists
│   └── reports/                  ← Generated PDF reports
├── requirements.txt
├── README.md
└── DOCUMENTATION.md              ← This file
```

---

## 5. wifisecaudit.py — Web Server

### Purpose

Minimal Flask app that exposes the `PMKIDCapture` engine as a REST API.

### Global State

```python
pmkid = None  # PMKIDCapture instance, set in main()
```

Single global instance shared across all request handlers. Thread-safe because `PMKIDCapture` uses internal locks.

### main() Function

1. Checks for root privileges (WiFi tools need root)
2. Creates `data/` directory for exports
3. Initializes `PMKIDCapture(interface="wlan0")`
4. Suppresses Werkzeug request logging (unless `--verbose`)
5. Registers SIGINT/SIGTERM handlers for clean shutdown
6. Starts Flask on port 8080

### Route Organization

Core routes in `wifisecaudit.py`:

| Section | Routes | Purpose |
|---------|--------|---------|
| UI | `GET /` | Serve index.html |
| Interfaces & Monitor | `GET /api/pmkid/interfaces`, `POST /api/pmkid/monitor` | List WiFi interfaces, toggle monitor mode |
| Network Scanning | `POST /api/pmkid/scan`, `POST /api/pmkid/scan/stop`, `GET /api/pmkid/networks` | Discover nearby WiFi APs |
| PMKID Capture | `POST /api/pmkid/capture`, `POST /api/pmkid/stop`, `GET /api/pmkid/status`, `GET /api/pmkid/results`, `POST /api/pmkid/export`, `GET /api/pmkid/log` | Capture and export PMKIDs |
| Handshake Export | `POST /api/handshake/export` | Export handshakes as .cap or .hc22000 |
| Passive Sniffer | `POST /api/sniffer/start`, `POST /api/sniffer/stop`, `GET /api/sniffer/status` | Background EAPOL handshake sniffer |
| Client Scanning | `POST /api/clients/scan`, `POST /api/clients/scan/stop`, `GET /api/clients` | Discover clients on selected APs |
| Deauthentication | `POST /api/deauth/start`, `POST /api/deauth/stop`, `GET /api/deauth/status` | Deauth APs or specific clients |
| Debug | `POST /api/debug/scan-test` | Diagnostic: test scapy sniff on the interface |

Blueprint routes (registered from `routes/`):

| Blueprint | Routes | Purpose |
|-----------|--------|---------|
| **cracking** | `POST /api/crack/start`, `POST /api/crack/stop`, `GET /api/crack/status`, `GET /api/crack/files`, `GET /api/wordlists`, `POST /api/wordlists/upload`, `DELETE /api/wordlists/<name>`, `POST /api/wordlists/decompress-rockyou` | Aircrack-ng cracking, wordlist management |
| **mac** | `POST /api/mac/change`, `POST /api/mac/restore`, `GET /api/mac/current`, `POST /api/interface/reset` | MAC spoofing, adapter reset |
| **eviltwin** | `POST /api/eviltwin/start`, `POST /api/eviltwin/stop`, `GET /api/eviltwin/status`, `GET /api/eviltwin/clients`, `POST /api/arpspoof/start`, `POST /api/arpspoof/stop`, `GET /api/arpspoof/status`, `POST /api/traffic/start`, `POST /api/traffic/stop`, `GET /api/traffic/captured`, `GET /api/captive/credentials`, `POST /api/hosts/discover` | Evil twin, ARP spoof, traffic sniffer, host discovery |
| **recon** | `POST /api/nmap/scan`, `POST /api/nmap/stop`, `GET /api/nmap/results`, `POST /api/wps/start`, `POST /api/wps/stop`, `GET /api/wps/status`, `POST /api/wps/scan`, `POST /api/wps/scan/stop`, `GET /api/wps/scan/results`, `POST /api/handshake/validate`, `POST /api/ids/start`, `POST /api/ids/stop`, `GET /api/ids/status`, `POST /api/ids/clear`, `POST /api/wpa3/dragonblood`, `POST /api/wpa3/start`, `POST /api/wpa3/stop`, `GET /api/wpa3/status`, `GET /api/dual/detect`, `POST /api/dual/auto`, `POST /api/dual/assign`, `POST /api/dual/monitor`, `POST /api/report/generate` | Nmap, WPS, WPA3, dual adapter, IDS, reports |

### Pattern

Every route follows the same pattern:
1. Parse JSON request body
2. Auto-detect WiFi interface if not provided
3. Call the corresponding `pmkid.*` method
4. Return JSON response

Long-running operations (scan, capture) are launched in daemon threads so the HTTP response returns immediately.

---

## 6. modules/pmkid_capture.py — WiFi Engine

This is the core of the tool. All WiFi operations happen here.

### Class: WiFiNetwork (line 41)

Represents a discovered WiFi access point.

| Attribute | Type | Description |
|-----------|------|-------------|
| `ssid` | str | Network name |
| `bssid` | str | AP MAC address |
| `channel` | int | WiFi channel (1-165) |
| `signal` | int | Signal strength in dBm |
| `encryption` | str | "WPA2/PSK", "WPA3", "Open", etc. |
| `clients` | set | MAC addresses of known connected clients |
| `beacon_count` | int | Number of beacon frames seen |
| `first_seen` | str | ISO timestamp |
| `last_seen` | str | ISO timestamp |

### Class: PMKIDCapture (line 68)

Main engine class. One instance handles everything.

#### Key Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `interface` | str | Default WiFi interface name |
| `running` | bool | PMKID capture in progress |
| `scanning` | bool | Network scan in progress |
| `monitor_mode_active` | bool | Monitor mode enabled |
| `monitor_interface` | str | Actual monitor interface name (e.g. "wlan0mon") |
| `networks` | dict | BSSID -> WiFiNetwork mapping |
| `captured_pmkids` | list | Captured PMKID dicts |
| `captured_handshakes` | list | Captured handshake dicts |
| `client_scanning` | bool | Client scan in progress |
| `discovered_clients` | list | Client dicts from airodump-ng |
| `sniffer_active` | bool | Passive EAPOL sniffer running |
| `sniffer_thread` | Thread | Background sniffer thread |
| `sniffer_interface` | str | Interface the sniffer is using |
| `deauth_running` | bool | Deauth attack in progress |
| `deauth_count` | int | Total deauth frames sent |
| `_deauth_processes` | list | Running aireplay-ng subprocess.Popen objects |

### Section: Interface Detection (line 127)

**`_detect_wifi_interfaces()`**
- Reads `/sys/class/net/` to find all network interfaces
- Checks `/sys/class/net/<iface>/wireless` to identify WiFi adapters
- Returns list of `{name, description, is_wifi, mode}` dicts

**`get_wifi_interfaces()`**
- Calls `_detect_wifi_interfaces()` fresh each time
- Returns only WiFi-capable interfaces

### Section: Monitor Mode (line 225)

**`enable_monitor_mode(interface)`** → `(success, interface_name)`

On Linux, tries in order:
1. `airmon-ng check kill` + `airmon-ng start <interface>` — kills interfering processes, creates monitor interface (e.g. wlan0mon)
2. `iw dev <interface> set type monitor` — fallback if airmon-ng not installed

Stores the actual monitor interface name in `self.monitor_interface`. This is critical because when airmon-ng creates `wlan0mon`, all subsequent operations must use that name, not the original `wlan0`.

**`disable_monitor_mode(interface)`**
1. `airmon-ng stop` or `iw set type managed`
2. `systemctl start NetworkManager` — restart networking
3. Clears `self.monitor_interface`

**`set_channel(interface, channel)`**
- `iw dev <interface> set channel <N>`
- Used before deauth/capture to lock to the target AP's channel

### Section: Network Scanning (line 414)

**`scan_networks(interface, duration)`**

1. Sets `self.scanning = True`
2. Starts `_channel_hopper` thread — cycles through 2.4GHz channels (1-13) and 5GHz channels (36-165) with different dwell times
3. Runs Scapy `sniff()` with `stop_filter=lambda pkt: not self.scanning` — this is how `stop_scan()` works instantly
4. Each captured beacon frame is processed by `_process_beacon()` which extracts SSID, BSSID, channel, encryption, signal
5. Falls back to OS-level scan (`iw scan`) if Scapy fails

**`stop_scan()`**
- Sets `self.scanning = False`
- Scapy sniff stops on the next received packet due to `stop_filter`

**`_channel_hopper(interface)`**
- Cycles through channels: 2.4GHz (200ms dwell) → 5GHz (300ms dwell)
- Runs in a daemon thread alongside sniff

### Section: Client Scanning (line 604)

**`_resolve_mac_vendor(mac)`**
- Resolves MAC address to manufacturer name
- Uses Scapy's built-in manufacturer database first
- Falls back to `/usr/share/nmap/nmap-mac-prefixes`

**`start_client_scan(interface, targets, duration)`**
- `targets` is a list of `{bssid, channel, ssid}` dicts — the APs to scan
- Launches `_client_scan_loop` in a daemon thread
- Duration 0 = scan until `stop_client_scan()` is called

**`_client_scan_loop(interface, targets, duration)`**

1. Builds airodump-ng command with BSSID and channel filters
2. Runs `airodump-ng --write <prefix> --output-format csv --write-interval 3`
3. Every 3 seconds, parses the CSV output with `_parse_airodump_clients()`
4. Updates `self.discovered_clients` with results
5. On stop: final parse, cleanup temp files, save clients to network objects

**`_parse_airodump_clients(csv_file, target_lookup)`**

Parses airodump-ng's CSV format which has two sections:
- Section 1: APs (BSSID, channel, encryption, etc.)
- Section 2: Clients (Station MAC, power, packets, associated BSSID, probed SSIDs)

For each client:
- Checks if associated with one of our target APs
- Resolves MAC vendor
- Returns `{mac, bssid, ssid, channel, signal, packets, vendor, probed, associated}`

### Section: Deauthentication (line 892)

This is the most important section. The design mirrors the Flipper Zero `deauther.c` which delegates to ESP32 Marauder firmware.

**Design principle**: Don't build 802.11 frames manually with Scapy for deauth. Delegate to `aireplay-ng` which handles driver quirks, RadioTap headers, and injection rate control.

**`_find_deauth_tool()`**
- Checks if `aireplay-ng` is installed
- Returns the tool name or None

**`start_deauth(interface, target_bssid, channel, count, targets, clients)`**

Three modes:
1. **AP broadcast**: `targets=[{bssid, channel}]` — deauth all clients on AP
2. **Targeted client**: `clients=[{mac, bssid, channel}]` — deauth specific client only
3. **Both**: targets + clients simultaneously

Resolves `self.monitor_interface`, auto-detects channels from scanned networks, spawns `_deauth_loop_multi` in a daemon thread.

**`_deauth_loop_multi(interface, target_list, count, client_list)`**

For AP targets:
- Calls `_launch_broadcast_deauth()` for each AP — spawns 2x aireplay-ng per AP

For client targets:
- Calls `_launch_client_deauth()` for each client — spawns 2x aireplay-ng with `-c CLIENT_MAC`

Then starts `_disassoc_loop` in parallel and waits until `deauth_running` is set to False.

**`_launch_broadcast_deauth(interface, bssid, count)`**

Spawns 2 `aireplay-ng` processes per AP:
```
aireplay-ng --deauth 0 -a <BSSID> --ignore-negative-one -D <interface>
```
- `--deauth 0` — continuous until killed
- `-a <BSSID>` — target AP
- `--ignore-negative-one` — skip channel mismatch checks (faster)
- `-D` — disable AP detection (attack immediately, no waiting)

Two processes = double the frame rate.

**`_launch_client_deauth(interface, bssid, client_mac, count)`**

Same as broadcast but with `-c CLIENT_MAC`:
```
aireplay-ng --deauth 0 -a <BSSID> -c <CLIENT_MAC> --ignore-negative-one -D <interface>
```
This sends deauth frames only to the specific client, not broadcast.

**`_disassoc_loop(interface, bssid_list, clients, targeted_only)`**

Runs alongside aireplay-ng. Sends 802.11 disassociation frames via Scapy raw socket.

Why both deauth AND disassoc?
- **Deauth** (subtype 0xC0): "You are not authenticated" — client can silently re-auth
- **Disassoc** (subtype 0xA0): "You are not associated" — forces full reassociation

When `targeted_only=True` (client deauth): only sends per-client disassoc frames.
When `targeted_only=False` (AP deauth): also sends broadcast disassoc `ff:ff:ff:ff:ff:ff`.

Uses a persistent `conf.L2socket` for speed. 32 frames per burst, 0.05s between bursts.

**`_monitor_aireplay(proc, label)`**
- Reads aireplay-ng stdout line by line
- Parses "Sending 64 directed DeAuth" to count frames
- Updates `self.deauth_count`

**`stop_deauth()`**
- Sets `self.deauth_running = False`
- Terminates all aireplay-ng processes (`.terminate()` then `.kill()` if needed)

### Section: PMKID Capture (line 1364)

**`start_capture(interface, target_bssid, duration)`**

In monitor mode:
1. Gets interface MAC address
2. For each WPA2 network found (or specific target):
   - Opens raw L2 socket
   - Injects authentication frame (triggers AP response)
   - Injects association request
   - Listens for EAPOL response containing PMKID
3. Also runs passive Scapy sniff for any EAPOL frames

**`_process_eapol(packet)`**
- Processes captured EAPOL frames
- Extracts PMKID from EAPOL Message 1 (Key Data field)
- PMKID location: Type 0xdd, OUI 00:0f:ac, Data Type 0x04, followed by 16 bytes
- Detects 4-way handshake messages for handshake capture

**`export_hashcat(filepath)`**
- Exports all captured PMKIDs in hashcat mode 22000 format
- Format: `WPA*01*PMKID*MAC_AP*MAC_CLIENT*ESSID_HEX***`
- Saves to `data/pmkid_<timestamp>.22000`

### Section: Status & Results (line 1924)

**`get_status()`** — returns running state, packet counts, PMKID/handshake counts, monitor mode state, scanning state

**`get_results()`** — returns captured PMKIDs and handshakes with full details

**`get_log(n)`** — returns last N log entries from the internal log

---

## 7. templates/index.html — Frontend Dashboard

Single-page web application. No build tools, no frameworks — just vanilla HTML/CSS/JS.

### Layout

```
┌─────────────────────────────────────────────────┐
│  WIFI SECURITY AUDIT          [interface ▼] [⟳] │  ← Header
├─────────────────────────────────────────────────┤
│  Status │ Packets │ EAPOL │ PMKIDs │ Handshakes │  ← Status bar
│         │         │       │        │ Sniffer    │
│         │         │       │        │  [Monitor] │
├────────────────────┬────────────────────────────┤
│  Networks          │  Clients                   │  ← Scan results
│  [Scan] [Stop]     │  [Scan Clients] [Stop]     │
│  ☑ SSID BSSID ...  │  ☑ MAC Vendor AP ...       │
│  [Deauth Selected] │  [Deauth Selected Clients] │
├────────────────────┼────────────────────────────┤
│  PMKID Capture     │  Captured PMKIDs           │  ← Capture
│  [BSSID] [60s ▼]   │  [Export Hashcat]          │
│  [Capture] [Stop]  │                            │
│  [Start Sniffer]   │                            │
├────────────────────┼────────────────────────────┤
│  Handshakes        │  Log                       │  ← Results
│  [.cap▼] [Export]  │                            │
│  ☑ Handshake 1     │                            │
└────────────────────┴────────────────────────────┘
│  Deauth Active: Target | Frames | Clients [Stop]│  ← Deauth panel
└─────────────────────────────────────────────────┘     (shown when active)
```

### CSS

- Dark theme using CSS custom properties (`--bg-primary`, `--accent-red`, etc.)
- Monospace font throughout
- Responsive 2-column grid that collapses to 1 on mobile
- Sticky table headers
- Color-coded badges (green=WPA2, red=Open, yellow=other)

### JavaScript Sections

**Helpers**
- `api(url, opts)` — fetch wrapper that returns parsed JSON or null on error
- `escapeHtml(s)` — XSS prevention for dynamic content
- `numberFmt(n)` — locale-formatted numbers
- `openModal(title, body)` / `closeModal()` — modal dialog
- `renderEvents(id, events)` — renders log entries with color-coded levels

**WiFi Status**
- `loadWifiInterfaces()` — populates the interface dropdown from `/api/pmkid/interfaces`
- `loadWifiStatus()` / `loadWifiStatusFromData(s)` — updates status bar counters and monitor mode badge

**Network Scanning**
- `wifiScan()` — starts scan, shows stop button, polls every 3s
- `wifiStopScan()` — calls stop API, resets UI
- `loadWifiNetworks()` — fetches and renders network table with checkboxes

**Deauth (AP broadcast)**
- `startDeauthSelected()` — collects checked AP BSSIDs, sends `{targets: [...]}` to API
- `startDeauth(bssid, channel)` — single AP deauth from the per-row button
- `showDeauthPanel(target)` — shows the red deauth panel and starts status polling
- `stopDeauth()` — calls stop API, hides panel

**Client Scanning**
- `startClientScan()` — collects checked APs, sends to `/api/clients/scan`, polls every 3s
- `stopClientScan()` — stops scan, does final fetch
- `renderClients(clients)` — renders client table grouped by AP, with vendor and signal info

**Client Deauth (targeted)**
- `startDeauthClients()` — collects checked client MACs, sends `{clients: [...]}` to API
- Uses same `showDeauthPanel()` for the active deauth display

**Capture**
- `wifiStartCapture()` / `wifiStopCapture()` — start/stop PMKID capture
- `wifiEnableMonitor()` / `wifiDisableMonitor()` — toggle monitor mode
- `loadWifiResults()` — renders captured PMKIDs and handshakes (with checkboxes)
- `wifiExport()` — triggers hashcat PMKID export, shows file path in modal

**Passive Sniffer**
- `startSniffer()` — starts background EAPOL sniffer on the monitor interface, optionally locked to a BSSID's channel
- `stopSniffer()` — stops the sniffer

**Handshake Export**
- `exportSelectedHandshakes()` — exports checked handshakes in selected format
- `exportAllHandshakes()` — exports all handshakes
- Format dropdown: `.cap` (aircrack-ng) or `.hc22000` (hashcat)
- `updateHsSelectedCount()` — updates "Export Selected (N)" button state

**Polling**
- Status checked every 5s (lightweight, 1 request)
- Results + log fetched when `status.running`, `status.scanning`, or `status.sniffer_active` is true
- Deauth status polled every 3s while active
- Network list polled every 3s during scan

---

## 8. API Reference

### Interfaces & Monitor Mode

#### GET /api/pmkid/interfaces
Returns list of WiFi interfaces.
```json
[{"name": "wlan0", "description": "Realtek RTL8812AU", "is_wifi": true, "mode": "managed"}]
```

#### POST /api/pmkid/monitor
Enable or disable monitor mode.
```json
// Request
{"interface": "wlan0", "enable": true}

// Response
{"success": true, "message": "wlan0mon"}
```

### Network Scanning

#### POST /api/pmkid/scan
Start scanning for WiFi networks.
```json
{"interface": "wlan0mon", "duration": 120}
```

#### POST /api/pmkid/scan/stop
Stop active scan immediately.

#### GET /api/pmkid/networks
Get discovered networks, sorted by signal strength.
```json
[{"ssid": "MyNetwork", "bssid": "aa:bb:cc:dd:ee:ff", "channel": 6, "signal": -45, "encryption": "WPA2/PSK", "clients": [], "beacon_count": 42}]
```

### Client Scanning

#### POST /api/clients/scan
Start client discovery on selected APs.
```json
{"targets": [{"bssid": "aa:bb:cc:dd:ee:ff", "channel": 6, "ssid": "MyNetwork"}], "duration": 0}
```
Duration 0 = scan until stopped.

#### POST /api/clients/scan/stop
Stop client scan.

#### GET /api/clients
Get scan status and discovered clients.
```json
{
  "scanning": true,
  "count": 3,
  "clients": [
    {"mac": "11:22:33:44:55:66", "bssid": "AA:BB:CC:DD:EE:FF", "ssid": "MyNetwork", "channel": 6, "signal": -38, "packets": 139, "vendor": "Apple", "associated": true}
  ]
}
```

### Deauthentication

#### POST /api/deauth/start
Start deauth attack.

AP broadcast (deauth all clients on AP):
```json
{"targets": [{"bssid": "aa:bb:cc:dd:ee:ff", "channel": 6}]}
```

Single AP shorthand:
```json
{"bssid": "aa:bb:cc:dd:ee:ff", "channel": 6}
```

Targeted client (deauth specific client only):
```json
{"clients": [{"mac": "11:22:33:44:55:66", "bssid": "aa:bb:cc:dd:ee:ff", "channel": 6}]}
```

#### POST /api/deauth/stop
Stop all deauth processes.

#### GET /api/deauth/status
```json
{"running": true, "target": "aa:bb:cc:dd:ee:ff", "targets": [...], "frames_sent": 5120, "clients": ["11:22:33:44:55:66"], "interface": "wlan0mon"}
```

### PMKID Capture

#### POST /api/pmkid/capture
```json
{"interface": "wlan0mon", "bssid": "aa:bb:cc:dd:ee:ff", "duration": 60}
```
BSSID is optional — leave null to target all WPA2 APs.

#### POST /api/pmkid/stop
Stop capture.

#### GET /api/pmkid/status
```json
{"running": false, "scanning": false, "monitor_mode": true, "sniffer_active": false, "packets": 1234, "eapol_frames": 5, "pmkids_captured": 1, "handshakes_captured": 0, "networks_seen": 8}
```

#### GET /api/pmkid/results
```json
{
  "pmkids": [{"timestamp": "...", "ssid": "MyNetwork", "bssid": "...", "mac_ap": "...", "mac_client": "...", "pmkid": "abcdef...", "hashcat_line": "WPA*01*..."}],
  "handshakes": [{"timestamp": "...", "ssid": "MyNetwork", "bssid": "...", "mac_ap": "...", "mac_client": "...", "messages": [1, 2], "hashcat_line": "WPA*02*..."}]
}
```

#### POST /api/pmkid/export
Export PMKIDs in hashcat mode 22000 format. Returns `{"success": true, "file": "data/pmkid_20260321_1234.22000"}`.

#### GET /api/pmkid/log?n=50
Returns last N log entries from the WiFi engine.

### Passive Sniffer

#### POST /api/sniffer/start
Start passive EAPOL sniffer. Captures handshakes from client reconnections.
```json
{"interface": "wlan0mon", "bssid": "aa:bb:cc:dd:ee:ff"}
```
BSSID is optional — if provided, locks the interface to that AP's channel. Without BSSID, listens on current channel. Multiple APs on the same channel are captured simultaneously.

#### POST /api/sniffer/stop
Stop the passive sniffer.

#### GET /api/sniffer/status
```json
{"active": true, "interface": "wlan0mon"}
```

### Handshake Export

#### POST /api/handshake/export
Export captured handshakes as individual files.
```json
// Export all as .cap (aircrack-ng compatible)
{"format": "pcap"}

// Export specific handshakes as .hc22000 (hashcat)
{"indices": [0, 2], "format": "hc22000"}
```
Returns `{"success": true, "files": ["data/handshake_MyNetwork_aabbccddeeff_20260322_1234_0.cap"], "count": 1}`.

---

## 9. Deauthentication — How It Works

### The Problem

WiFi deauthentication works by sending 802.11 management frames that tell clients or APs to disconnect. There are two frame types:

| Frame | Subtype | Effect |
|-------|---------|--------|
| Deauthentication (0xC0) | 12 | "You are not authenticated" |
| Disassociation (0xA0) | 10 | "You are not associated" |

Both are needed for reliable disconnection. Deauth alone lets clients silently re-authenticate.

### Our Approach

We delegate to `aireplay-ng` for deauth injection (proven reliable across drivers) and supplement with Scapy disassoc frames:

```
aireplay-ng --deauth 0 -a BSSID [--ignore-negative-one] [-D] [-c CLIENT] interface
    │
    ├─ Sends deauth frames (0xC0) — handles driver quirks
    │
    └─ 2 processes per target — double frame rate

Scapy _disassoc_loop (parallel thread)
    │
    ├─ Sends disassoc frames (0xA0) — supplements aireplay-ng
    ├─ Broadcast (AP deauth) or targeted (client deauth)
    └─ Raw L2 socket, 32 frames/burst, 0.05s interval
```

### AP Broadcast vs Client Targeted

| Mode | aireplay-ng flags | Disassoc loop | Effect |
|------|------------------|---------------|--------|
| AP broadcast | `-a BSSID` | Broadcast + per-client | Kicks ALL clients on AP |
| Client targeted | `-a BSSID -c CLIENT` | Per-client only, NO broadcast | Kicks ONLY that client |

### Design Origin

This approach mirrors the Flipper Zero `deauther.c` which sends UART commands to ESP32 Marauder firmware:
```
Flipper: uart_tx("attack -t deauth")  →  Marauder handles radio
Our tool: subprocess(aireplay-ng)      →  aireplay-ng handles radio
```

The key insight: don't reimplement frame injection in Python. Delegate to battle-tested tools.

---

## 10. PMKID Capture — How It Works

### What is PMKID?

When a client connects to a WPA2 AP, the AP sends EAPOL Message 1 containing the PMKID:
```
PMKID = HMAC-SHA1-128(PMK, "PMK Name" || MAC_AP || MAC_Client)
```

The PMKID can be used for offline password testing without needing a full 4-way handshake.

### Capture Process

1. Enable monitor mode on WiFi interface
2. For each target WPA2 AP:
   - Open raw L2 socket
   - Inject 802.11 authentication frame (Open System)
   - Inject 802.11 association request
   - AP responds with EAPOL Message 1
3. Parse EAPOL response:
   - Look for RSN Key Data field
   - Find PMKID KDE: Type 0xdd, Length 0x14, OUI 00:0f:ac, Type 0x04
   - Extract 16-byte PMKID
4. Format for hashcat: `WPA*01*PMKID*MAC_AP*MAC_CLIENT*ESSID_HEX***`

### Hashcat Cracking

```bash
# After exporting
hashcat -m 22000 data/pmkid_*.22000 /path/to/wordlist.txt
```

---

## 11. Passive Sniffer & Handshake Capture

### What is a WPA2 Handshake?

The WPA2 4-way handshake occurs when a client connects (or reconnects) to an AP:

| Message | Direction | Contains |
|---------|-----------|----------|
| 1 | AP -> Client | ANonce (AP's random nonce) |
| 2 | Client -> AP | SNonce (client's nonce) + MIC |
| 3 | AP -> Client | GTK (group key) + MIC |
| 4 | Client -> AP | ACK confirmation |

**Messages 1 + 2 are the minimum needed for cracking.** They contain both nonces and the MIC, which is enough to test passwords offline.

### How the Passive Sniffer Works

The sniffer runs a Scapy `sniff()` in a background daemon thread with `_process_capture_packet` as the callback:

1. **Start sniffer** — optionally locks to a target AP's channel via `set_channel()`
2. **Scapy sniff loop** — captures all frames on the channel, passes each to `_process_capture_packet`
3. **EAPOL detection** — `_process_eapol()` parses the EAPOL Key Information field (bytes 5-6) to identify message number:
   - Bit 7 (ACK) + no Bit 8 (MIC) = Message 1
   - No Bit 7 + Bit 8 = Message 2
   - Bit 7 + Bit 8 = Message 3
4. **Handshake match** — when both Message 1 and Message 2 are stored for the same BSSID, a handshake is recorded
5. **Stop** — setting `sniffer_active = False` triggers Scapy's `stop_filter` on the next packet

### Independence from Other Features

The sniffer uses `self.sniffer_active` — completely independent from `self.running` (PMKID capture) and `self.deauth_running`. All three can run simultaneously:

- Start sniffer (listens for EAPOL)
- Start deauth (kicks clients off)
- Clients reconnect, sniffer captures the handshake

### Multi-AP Capture

The sniffer captures ALL traffic on the channel it's listening on. If multiple APs share the same channel, all their handshakes are captured simultaneously. Only limitation: a single WiFi adapter can only listen on one channel at a time.

---

## 12. Hidden SSID Reveal

### How Hidden SSIDs Work

APs with "SSID broadcast" disabled send beacons with an empty or null SSID field. The tool stores these as `<Hidden>`. However, the SSID is transmitted in cleartext in:

- **Probe responses** — when the AP responds to a client probe
- **Probe requests** — when a client probes for the hidden network

### How the Tool Reveals Hidden SSIDs

Three paths in `_process_beacon()`:

1. **Probe response parsing** — extracts SSID from `Dot11ProbeResp` elements (Dot11Elt ID=0). If the BSSID matches a `<Hidden>` entry, the SSID is updated.

2. **Probe request matching** — extracts SSID from `Dot11ProbeReq`. If the sending client MAC is known to be associated with a hidden AP (in `net.clients`), the AP's SSID is updated.

3. **SSID update on existing entries** — any time a real SSID is found for a BSSID that currently shows `<Hidden>`, it's replaced. A log message is generated: `"Hidden SSID revealed: <bssid> -> '<ssid>'"`.

### Workflow

1. Scan networks — hidden APs appear as `<Hidden>`
2. Start sniffer on the hidden AP's channel
3. Deauth the AP — clients reconnect and send probe requests revealing the SSID
4. The `<Hidden>` entry updates to the real name in the networks table

---

## 13. Handshake Export & Cracking

### Export Formats

| Format | Extension | Tool | Command |
|--------|-----------|------|---------|
| pcap | `.cap` | aircrack-ng | `aircrack-ng -w wordlist.txt file.cap` |
| hc22000 | `.hc22000` | hashcat | `hashcat -m 22000 file.hc22000 wordlist.txt` |

### pcap Export (`.cap`)

The `_build_pcap()` method constructs a minimal pcap file using Scapy's `wrpcap()`:

1. **Beacon frame** — includes SSID and RSN IE so aircrack-ng identifies the network as WPA2
2. **EAPOL Message 1** — AP -> Client, plain Data frame (type=2, subtype=0, FCfield=From-DS), LLC/SNAP/EAPOL
3. **EAPOL Message 2** — Client -> AP, plain Data frame (type=2, subtype=0, FCfield=To-DS), LLC/SNAP/EAPOL

Uses `subtype=0` (plain Data) instead of `subtype=8` (QoS Data) to avoid the 2-byte QoS Control header that would shift all subsequent bytes and corrupt the frame structure.

### hc22000 Export (`.hc22000`)

Format: `WPA*02*MIC*MAC_AP*MAC_CLIENT*ESSID_HEX*ANONCE*EAPOL_M2_ZEROED*00`

- MIC: extracted from Message 2 (bytes 81-97 of raw EAPOL)
- ANonce: extracted from Message 1 (bytes 17-49 of raw EAPOL)
- EAPOL_M2_ZEROED: full Message 2 with MIC field replaced by zeros

### Per-Handshake Files

Each handshake is exported to its own file, named: `data/handshake_<SSID>_<BSSID>_<timestamp>_<index>.<ext>`

This allows selecting specific handshakes to crack, rather than processing all of them.

### Cracking Notes

- **aircrack-ng** works on CPU, reliable in VMs — recommended for VM environments
- **hashcat** requires GPU or working OpenCL runtime — may segfault in VirtualBox VMs due to PoCL issues
- The password must be in your wordlist — try `rockyou.txt` or generate custom wordlists with `crunch`

---

## 14. External Tool Dependencies

| Tool | Package | Used For | Required? |
|------|---------|----------|-----------|
| `aireplay-ng` | aircrack-ng | Deauth frame injection, WPA3 downgrade | Yes |
| `airmon-ng` | aircrack-ng | Enable/disable monitor mode | Yes (or use iw) |
| `airodump-ng` | aircrack-ng | Client discovery, WPA3 transition detection | Yes |
| `aircrack-ng` | aircrack-ng | WPA/WPA2 cracking, handshake validation | Yes |
| `iw` | iw | Channel setting, fallback monitor mode, interface info | Recommended |
| Scapy | python scapy | Packet capture, beacon parsing, disassoc, PMKID extraction, IDS | Yes |
| `hostapd` | hostapd | Evil twin rogue AP | For evil twin |
| `dnsmasq` | dnsmasq | DHCP/DNS for evil twin | For evil twin |
| `macchanger` | macchanger | MAC address spoofing | For MAC spoof |
| `arpspoof` | dsniff | ARP spoofing MITM | For ARP spoof |
| `tshark` | tshark/wireshark | HTTP traffic capture, handshake validation | Recommended |
| `reaver` | reaver | WPS pixie-dust + brute-force, wash (WPS scanning) | For WPS attacks |
| `bully` | bully | Alternative WPS tool | Optional |
| `wash` | reaver | WPS network detection | For WPS scanning |
| `nmap` | nmap | Network scanning, host discovery | For nmap/recon |
| `arp-scan` | arp-scan | Fast local host discovery | Optional (nmap fallback) |
| `hcxdumptool` | hcxdumptool | WPA3 SAE handshake capture (v7, manages monitor mode itself) | For WPA3 attacks |
| `hcxpcapngtool` | hcxtools | Convert pcapng to hashcat `.22000` format | For WPA3 attacks |
| `ethtool` | ethtool | Driver detection for adapter reset | Recommended |
| `fpdf2` | pip fpdf2 | PDF report generation | For reports |

---

## 15. New Modules Reference

### modules/aircrack_runner.py — Cracking
Runs `aircrack-ng -w <wordlist> <cap_file>` in subprocess, parses stdout for `KEY FOUND!` pattern and progress. Uses `SIGKILL` for reliable stop (avoids deadlock with stdout reader thread).

### modules/wordlist_manager.py — Wordlists
Lists system wordlists (`/usr/share/wordlists/`), manages user uploads to `data/wordlists/`, decompresses `rockyou.txt.gz`.

### modules/mode_manager.py — Adapter Mode Control
Central controller for adapter mode transitions (managed/monitor/AP). Wraps pmkid's `enable_monitor_mode`/`disable_monitor_mode`. Stops all operations before switching. `reset_interface()` does full driver reload via `rmmod`/`modprobe`.

### modules/mac_spoofer.py — MAC Spoofing
Wraps `macchanger`. Saves original MAC on first call. Flow: save mode → managed → interface down → macchanger → interface up → restore previous mode.

### modules/evil_twin.py — Rogue AP
Creates AP with `hostapd` + `dnsmasq`. Start: stop NetworkManager → configure IP → write configs → start hostapd/dnsmasq → iptables NAT. Stop: kill processes → flush iptables → reload WiFi driver → restart NetworkManager. Monitors connected clients via ARP table.

### modules/captive_portal.py — Fake Login Server
Runs `http.server.HTTPServer` on port 80 (separate from Flask). Serves selected template on all GET requests. Captures POST form data (username/password). 3 templates: wifi_login, router_update, hotel_login.

### modules/arp_spoofer.py — ARP Spoofing
Runs two `arpspoof` processes for bidirectional MITM (target→gateway and gateway→target). Enables IP forwarding.

### modules/traffic_sniffer.py — HTTP Traffic Capture
Runs `tshark` with HTTP request filter, extracts URLs, cookies, form data. Only captures unencrypted HTTP.

### modules/wps_attack.py — WPS Attacks
Wraps `reaver` and `bully`. Pixie-dust mode: reaver `-K` / bully `-d` (offline, fast). Brute-force: standard PIN iteration. Parses output for WPS PIN and WPA PSK.

### modules/wps_scanner.py — WPS Detection
Runs `wash -i <interface> -s` to detect WPS-enabled networks. Parses output for BSSID, channel, WPS version, lock status.

### modules/wpa3_attack.py — WPA3-SAE Attacks
4 strategies: (1) Auto — detects transition mode, picks best approach. (2) Transition mode downgrade — 2x continuous broadcast deauth + per-client targeted deauth + Scapy disassoc loop (mirrors Monitor tab's proven deauth method), captures WPA2 handshake via airodump-ng. (3) SAE capture — hcxdumptool v7 with BPF filters, `--exitoneapol=6` for auto-exit on capture, channel format `13a`/`36b`. (4) Passive — hcxdumptool with `--disable_disassociation --associationmax=0`, no transmit. Dragonblood scanner: passive vulnerability assessment via beacon RSN IE parsing, detects transition mode and PMF status. Risk: HIGH (PMF optional or transition mode), NONE (PMF required, WPA3-only). **Important:** hcxdumptool v7 manages monitor mode itself — interface must be in managed mode before starting. Output saved to `data/` as `.pcapng`, converted to `.22000` via `hcxpcapngtool` (requires `hcxtools` package).

### modules/dual_interface.py — Dual Adapter
Manages two WiFi adapters. Auto-detects via `iw dev`, assigns primary (capture) and secondary (injection). Prefers known-good injection drivers. Both can be put in monitor mode simultaneously.

### modules/handshake_validator.py — Handshake Validation
Validates `.cap`, `.pcap`, `.pcapng` files using `aircrack-ng` (checks handshake count per network), falls back to `tshark` EAPOL frame count. Minimum 2 EAPOL frames required for cracking. `.22000` files are validated by checking for `WPA*` hash lines — they're already in crackable format.

### modules/aircrack_runner.py — Capture File Support
Lists all capture files from `data/`: `.cap`, `.pcap`, `.pcapng`, `.hc22000`, `.22000`. The `.22000` format is used by hcxdumptool captures converted via `hcxpcapngtool`.

### modules/attack_monitor.py — Wireless IDS
Uses scapy to passively monitor for: deauth floods (>10 frames in 10s from same source), disassoc floods, evil twin detection (same SSID from multiple BSSIDs). Color-coded severity alerts.

### modules/nmap_scanner.py — Nmap Wrapper
6 scan types (quick/standard/full/stealth/udp/vuln). Outputs XML, parsed into structured host/port/service/version/OS data.

### modules/report_generator.py — PDF Reports
Uses fpdf2 to generate PDF with: networks table, PMKIDs, handshakes, cracked keys, nmap results. Saved to `data/reports/`.

---

## 16. Design Decisions

### Why aireplay-ng instead of Scapy for deauth?
Scapy's `sendp()` is unreliable across WiFi drivers. Different drivers need different RadioTap headers, socket types, and injection methods. `aireplay-ng` handles all of this. We proved this empirically — Scapy deauth didn't work, aireplay-ng did.

### Why both deauth and disassoc frames?
Deauth alone doesn't fully disconnect clients on many modern drivers. The client loses authentication but stays associated and silently re-authenticates. Disassociation forces a full reassociation handshake, making the disconnect visible to the user.

### Why 2 aireplay-ng processes per target?
Double the frame rate. One process sends ~64 frames per burst with a pause between bursts. Two processes interleave, effectively doubling throughput.

### Why `--ignore-negative-one` and `-D`?
`--ignore-negative-one` skips channel mismatch validation — saves time. `-D` disables AP detection — aireplay-ng normally waits to confirm the AP exists before attacking. We already know it exists from our scan.

### Why no client discovery before deauth?
Earlier versions ran `airodump-ng` for 10 seconds per target before attacking. With 3 targets = 30 seconds wasted. The Flipper Zero deauther doesn't do this — it attacks immediately. `aireplay-ng` handles client discovery from observed traffic automatically.

### Why targeted_only flag on disassoc loop?
When deauthing a specific client, the disassoc loop must NOT send broadcast frames (`ff:ff:ff:ff:ff:ff`) because that kicks ALL clients on the AP. The `targeted_only` flag ensures only per-client disassoc frames are sent.

### Why a separate sniffer instead of using start_capture for handshakes?
`start_capture` does active PMKID injection — it iterates targets, injects auth/assoc frames, and listens per-target with a raw socket. This is fundamentally different from passive handshake capture, which needs a long-running background sniffer on the channel. Keeping them separate means both can run simultaneously without interference, and the user has explicit control over when passive sniffing is active.

### Why pcap export uses plain Data frames (subtype=0)?
QoS Data frames (subtype=8) require a 2-byte QoS Control field after the Dot11 header. Scapy's `Dot11(subtype=8)` doesn't automatically add this field, which shifts all LLC/SNAP/EAPOL bytes by 2 and corrupts the frame. Using plain Data frames avoids this issue and produces pcap files that aircrack-ng reads correctly.

### Why export per-handshake files instead of one combined file?
In practice, you may capture handshakes from multiple APs but only want to crack specific ones. Per-file export lets you target individual networks with different wordlists or skip already-cracked ones.

---

## 17. Common Workflows

### Full Network Audit (Handshake Capture + Crack)

1. Enable monitor mode → Scan networks
2. Select target AP → Click **Start Sniffer** (locks to channel)
3. Click **Deauth** → Clients reconnect → Sniffer captures handshake
4. **Cracking tab** → Click **Validate All** → Confirm handshake is valid
5. Select `.cap` file → Choose wordlist → Click **Crack**
6. Wait for `KEY FOUND` result

### Full Network Audit (PMKID)

1. Enable monitor mode → Scan networks
2. Select target BSSID → Click **Capture**
3. While capturing, deauth the target to force EAPOL exchange
4. **Export Hashcat** → Crack with `hashcat -m 22000`

### Evil Twin Credential Capture

1. **Monitor tab**: Scan networks → Note target SSID + channel
2. **Evil Twin tab**: Enter SSID/channel → Select WPA2 → Set passphrase → Enable Captive Portal → Choose template → **Start Evil Twin**
3. Victims see your AP → Connect with the passphrase → Captive portal shows fake login
4. Credentials appear in **Captured Credentials** table
5. Click **Stop Evil Twin** when done

### WPA3 Downgrade Attack (transition mode networks)

1. Enable monitor mode → Scan networks → Identify WPA3 target
2. **Recon tab** → Enter BSSID + channel → Click **Dragonblood Scan**
3. If HIGH RISK (PMF optional / transition mode) → Select "Auto" or "Downgrade" → **Attack**
4. Continuous deauth runs (broadcast + per-client targeted + disassoc) until handshake captured
5. **Requires a client connected to the AP** — if all clients show "probing", there's nothing to deauth
6. Captured `.cap` file saved to `data/` → **Cracking tab** → Validate → Crack

### WPA3 SAE/Passive Capture (hcxdumptool)

1. **Disable monitor mode** first — hcxdumptool manages monitor mode itself
2. **Recon tab** → Enter BSSID + channel → Select "SAE Capture" or "Passive"
3. For passive: manually disconnect and reconnect a device to the AP
4. hcxdumptool captures EAPOL exchange → auto-exits on capture
5. If `hcxpcapngtool` installed: converts to `.22000` automatically
6. If not installed: `.pcapng` saved — install `hcxtools` and convert manually: `hcxpcapngtool -o hash.22000 capture.pcapng`
7. Crack with `hashcat -m 22000 hash.22000 wordlist.txt`

**Known limitations:**
- aircrack-ng cannot validate hcxdumptool `.pcapng` files (different format) — use `.22000` for cracking
- Modern devices use **randomized MACs** when probing — the probing MAC differs from the connected MAC, so client scan may show "probing" even when devices are connected
- WPA3-only APs with **mandatory PMF** block all deauth — only passive capture works

### WPS Attack (Pixie-Dust)

1. Enable monitor mode
2. **Recon tab** → Click **Scan for WPS** → Find WPS-enabled networks
3. Click **Pixie** button on a target → Attack form auto-fills with pixie-dust enabled
4. Click **Start** → Pixie-dust completes in seconds on vulnerable routers

### Dual Adapter Setup

1. Plug in second WiFi adapter
2. **Recon tab** → Click **Auto-Detect** → Assigns primary (capture) + secondary (injection)
3. Click **Enable Both Monitor**
4. Use all features normally — capture never misses packets during deauth

### MITM Traffic Sniffing

1. Start Evil Twin (or connect to target network after cracking)
2. **Evil Twin tab** → When client connects, click **Target** button on client row
3. ARP spoof fields auto-fill → Click **Start ARP Spoof**
4. Click **Start Capture** on Traffic Sniffer
5. HTTP URLs, cookies, and form data appear in tables

### Attack Detection (IDS)

1. Enable monitor mode
2. **Recon tab** → Click **Start Monitoring** in Attack Monitor section
3. IDS passively listens for deauth floods, disassoc attacks, evil twin APs
4. Alerts appear in real-time with severity levels

### Hidden SSID Discovery

1. Scan networks — hidden APs show as `[Hidden]` in yellow
2. Start sniffer on the hidden AP's channel
3. Deauth the AP — clients reconnect with probe requests revealing the SSID
4. `[Hidden]` updates to the real network name

---

## 18. Troubleshooting

### "No WiFi interfaces found"
- Check your WiFi adapter is plugged in: `iwconfig`
- Check it supports monitor mode: `iw phy`

### Monitor mode fails
- Kill interfering processes: `sudo airmon-ng check kill`
- Try manually: `sudo ip link set wlan0 down && sudo iw dev wlan0 set type monitor && sudo ip link set wlan0 up`

### Scan finds no networks
- Make sure monitor mode is enabled
- Run the scan longer — 5GHz channels take time to discover
- Check your adapter supports the frequency bands you need

### Deauth not working
- Confirm monitor mode is active
- Check `aireplay-ng` is installed: `which aireplay-ng`
- Verify your adapter supports injection: `aireplay-ng --test wlan0mon`
- Some APs use 802.11w (Protected Management Frames) which blocks deauth

### PMKID not captured
- Not all APs send PMKID in EAPOL Message 1
- The AP must support PMKID (most WPA2 APs do, WPA3 does not)
- Try deauthing a client while capturing — the reconnection triggers EAPOL exchange

### Client scan shows no clients
- Make sure you selected APs before clicking "Scan Clients"
- Run the scan longer — clients send frames infrequently when idle
- The adapter must be on the correct channel (handled automatically)

### Sniffer not capturing handshakes
- Ensure monitor mode is active
- Make sure the sniffer is on the same channel as the target AP (set target BSSID before starting sniffer)
- Don't run a network scan while sniffing — scanning hops channels and moves away from the target
- Verify clients are actually reconnecting after deauth (check log for EAPOL messages)
- You need Messages 1 + 2 for a complete handshake

### Handshake export shows "No handshakes to export"
- Handshakes must be captured after the latest restart — old captures don't persist
- Check the Captured Handshakes section shows entries with Messages 1, 2

### aircrack-ng shows "WEP (0 IVs)" on exported .cap file
- This indicates the EAPOL frames weren't recognized — recapture and re-export
- Ensure you're using the latest version of the tool with the pcap fix

### hashcat segfaults
- Common in VirtualBox/VMware VMs — PoCL OpenCL runtime doesn't work in virtualized environments
- Try: `export POCL_DEVICES=basic && hashcat -m 22000 file.hc22000 wordlist.txt -D 1 --force`
- Alternative: use aircrack-ng with `.cap` export instead — it works on CPU without OpenCL
- For full hashcat support, run on bare metal or with GPU passthrough

### Scanning stops working after evil twin
- The WiFi driver can get stuck after hostapd releases the interface
- Click **Reset Adapter** in the status bar — reloads the WiFi driver
- If that doesn't work, manually: `sudo airmon-ng stop wlan0 && sudo systemctl restart NetworkManager`
- Re-enable monitor mode after reset

### Evil twin: "hostapd not installed"
- Install: `sudo apt install hostapd`
- dnsmasq is usually pre-installed on Kali

### WPA3 attack: "hcxdumptool not installed"
- Install: `sudo apt install hcxdumptool`
- Without hcxdumptool, only the downgrade attack (transition mode) works

### WPA3 hcxdumptool captures but no handshake detected
- **Disable monitor mode first** — hcxdumptool v7 manages monitor mode itself, conflicts with airmon-ng
- Make sure you're on the **correct channel** — hcxdumptool doesn't hop by default with BPF filter
- The `.pcapng` may have data but `hcxpcapngtool` is needed to convert it: `sudo apt install hcxtools`
- Check the `.pcapng` in Wireshark — look for EAPOL frames. If only beacons/probes, the client reconnection wasn't captured

### WPA3 passive capture: phone reconnects but nothing captured
- Ensure hcxdumptool is running BEFORE you disconnect/reconnect the device
- The phone may reconnect using WPA3-SAE while hcxdumptool expects WPA2 EAPOL — this is expected for WPA3-only APs
- Try on a WPA2/WPA3 mixed network where the device may fall back to WPA2

### WPA3 downgrade: "no handshake after attempts"
- Ensure a **client is actually connected** — "probing" clients are NOT connected and can't be deauthed
- Modern devices use **randomized MACs** — the MAC shown as "probing" differs from the connected MAC
- WPA3-only APs with **mandatory PMF** will reject all deauth frames — downgrade cannot work, use passive
- Try the Monitor tab's sniffer + deauth combo instead — it uses the same proven deauth method

### Validator shows "No valid handshake" for .pcapng files
- aircrack-ng cannot parse hcxdumptool's pcapng format directly
- If a `.22000` file exists alongside it, that's the crackable hash — validator now shows it as valid
- Convert manually: `hcxpcapngtool -o hash.22000 capture.pcapng`

### WPS scan shows no networks
- Ensure monitor mode is enabled before scanning
- `wash` requires monitor mode
- Not all networks have WPS enabled

### Pixie-dust fails immediately
- Not all routers are vulnerable to pixie-dust — fall back to brute-force
- Some routers lock WPS after failed attempts — check "Lock" column in WPS scan

### Dual adapter not detected
- Both adapters must be different physical devices (different `phy#`)
- Check with `iw dev` — should show two separate phy entries
- Some USB adapters need drivers: `sudo apt install realtek-rtl88xxau-dkms`

### PDF report generation fails
- Install: `pip3 install fpdf2`
- Check `data/reports/` directory is writable

### IDS shows no alerts but attacks are happening
- IDS requires monitor mode — enable it first
- The adapter must be on the same channel as the attack
- Threshold is 10 deauth frames in 10 seconds from same source
