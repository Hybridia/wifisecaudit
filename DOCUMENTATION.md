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
11. [External Tool Dependencies](#11-external-tool-dependencies)
12. [Design Decisions](#12-design-decisions)
13. [Common Workflows](#13-common-workflows)
14. [Troubleshooting](#14-troubleshooting)

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
Browser (index.html)
  │  HTTP fetch() calls
  ▼
Flask routes (wifisecaudit.py)
  │  Python method calls
  ▼
PMKIDCapture class (modules/pmkid_capture.py)
  │  subprocess / scapy
  ▼
OS tools (aireplay-ng, airmon-ng, airodump-ng, iw, scapy)
  │
  ▼
WiFi radio (monitor mode interface)
```

The tool is a standard web app:
- **Frontend**: Single HTML page with vanilla JavaScript, no frameworks
- **Backend**: Flask web server with JSON API endpoints
- **Engine**: `PMKIDCapture` class that wraps system tools for WiFi operations

All WiFi operations happen server-side. The browser is just a control panel.

---

## 4. File Structure

```
wifisecaudit/
├── wifisecaudit.py         ← Flask web server, all API routes (230 lines)
├── modules/
│   ├── __init__.py          ← Empty, makes it a Python package
│   └── pmkid_capture.py     ← WiFi engine: scan, capture, deauth, clients (1970 lines)
├── templates/
│   └── index.html           ← Single-page web dashboard (CSS + HTML + JS)
├── data/                    ← Created at runtime, stores exported hashcat files
├── requirements.txt         ← Python dependencies
├── README.md                ← Quick start guide
└── DOCUMENTATION.md         ← This file
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

Routes are grouped by feature:

| Section | Routes | Purpose |
|---------|--------|---------|
| UI | `GET /` | Serve index.html |
| Interfaces & Monitor | `GET /api/pmkid/interfaces`, `POST /api/pmkid/monitor` | List WiFi interfaces, toggle monitor mode |
| Network Scanning | `POST /api/pmkid/scan`, `POST /api/pmkid/scan/stop`, `GET /api/pmkid/networks` | Discover nearby WiFi APs |
| PMKID Capture | `POST /api/pmkid/capture`, `POST /api/pmkid/stop`, `GET /api/pmkid/status`, `GET /api/pmkid/results`, `POST /api/pmkid/export`, `GET /api/pmkid/log` | Capture and export PMKID/handshakes |
| Client Scanning | `POST /api/clients/scan`, `POST /api/clients/scan/stop`, `GET /api/clients` | Discover clients on selected APs |
| Deauthentication | `POST /api/deauth/start`, `POST /api/deauth/stop`, `GET /api/deauth/status` | Deauth APs or specific clients |

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
├────────────────────┼────────────────────────────┤
│  Handshakes        │  Log                       │  ← Results
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
- `loadWifiResults()` — renders captured PMKIDs and handshakes
- `wifiExport()` — triggers hashcat export, shows file path in modal

**Polling**
- Status checked every 5s (lightweight, 1 request)
- Results + log only fetched when `status.running` or `status.scanning` is true
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
{"running": false, "scanning": false, "monitor_mode": true, "packets": 1234, "eapol_frames": 5, "pmkids_captured": 1, "handshakes_captured": 0, "networks_seen": 8}
```

#### GET /api/pmkid/results
```json
{
  "pmkids": [{"timestamp": "...", "ssid": "MyNetwork", "bssid": "...", "mac_ap": "...", "mac_client": "...", "pmkid": "abcdef...", "hashcat_line": "WPA*01*..."}],
  "handshakes": [{"timestamp": "...", "ssid": "MyNetwork", "bssid": "...", "messages": [1, 2]}]
}
```

#### POST /api/pmkid/export
Export PMKIDs in hashcat mode 22000 format. Returns `{"success": true, "file": "data/pmkid_20260321_1234.22000"}`.

#### GET /api/pmkid/log?n=50
Returns last N log entries from the WiFi engine.

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

## 11. External Tool Dependencies

| Tool | Package | Used For | Required? |
|------|---------|----------|-----------|
| `aireplay-ng` | aircrack-ng | Deauth frame injection | Yes (for deauth) |
| `airmon-ng` | aircrack-ng | Enable/disable monitor mode | Yes (or use iw) |
| `airodump-ng` | aircrack-ng | Client discovery | Yes (for client scan) |
| `iw` | iw | Channel setting, fallback monitor mode | Recommended |
| Scapy | python scapy | Packet capture, beacon parsing, disassoc, PMKID extraction | Yes |

---

## 12. Design Decisions

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

---

## 13. Common Workflows

### Full Network Audit

1. Enable monitor mode
2. Scan networks (stop when targets found)
3. Select all target APs
4. Scan clients
5. Start PMKID capture on target BSSID
6. While capturing, deauth the target AP to force client reconnections (triggers PMKID)
7. Export PMKIDs for hashcat

### Deauth Test (Single AP)

1. Enable monitor mode
2. Scan networks
3. Click "Deauth" on the target AP row
4. Observe clients disconnecting
5. Click "Stop Attack"

### Deauth Test (All APs, same SSID)

1. Enable monitor mode
2. Scan networks (run long enough to find 5GHz APs too)
3. Select all APs with the same SSID (both 2.4G and 5G)
4. Click "Deauth Selected"
5. Clients have nowhere to reconnect

### Targeted Client Deauth

1. Enable monitor mode
2. Scan networks
3. Select target APs, click "Scan Clients"
4. Wait for clients to appear
5. Check specific client(s)
6. Click "Deauth Selected Clients"
7. Only those clients are disconnected

---

## 14. Troubleshooting

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
