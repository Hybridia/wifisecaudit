# WiFi Security Audit Tool

Standalone web-based WiFi penetration testing toolkit for authorized security assessments.

## Features

### Monitor & Capture
- **Network Scanning** — Discover nearby WiFi networks (2.4GHz + 5GHz), channel hopping, signal strength
- **Hidden SSID Detection** — Hidden networks shown as `[Hidden]` in yellow; revealed via probe requests during deauth
- **Signal Strength Filter** — Slider in the Networks header to hide weak/distant APs
- **Client Discovery** — Find connected clients on selected APs using airodump-ng, with MAC vendor resolution
- **Deauthentication** — Broadcast AP deauth (all clients) or targeted client deauth (specific clients only). Uses 2x `aireplay-ng` processes + Scapy disassoc loop for maximum effectiveness
- **PMKID Capture** — Capture PMKID from WPA2 handshakes for offline password testing
- **Passive Sniffer** — Background EAPOL sniffer that captures handshakes when clients reconnect after deauth
- **Handshake Capture & Export** — Capture 4-way WPA2 handshakes, export as `.cap` (aircrack-ng) or `.hc22000` (hashcat)
- **Adapter Reset** — Full driver reload (`rmmod`/`modprobe`) to recover from broken adapter state after evil twin

### Cracking
- **Handshake Validation** — Verify capture files contain valid handshakes before cracking. Supports `.cap`, `.pcap`, `.pcapng`, and `.22000` files. Uses aircrack-ng + tshark
- **Aircrack-ng Integration** — Crack WPA/WPA2 handshakes with wordlists, real-time progress and key display
- **Capture File Browser** — Lists all `.cap`, `.pcap`, `.pcapng`, `.hc22000`, `.22000` files from the data directory
- **Wordlist Management** — Auto-detects system wordlists (rockyou.txt, etc.), upload custom wordlists, decompress rockyou.txt.gz
- **MAC Address Spoofing** — Randomize, set custom, clone from discovered client, restore original

### Evil Twin & MITM
- **Evil Twin AP** — Create rogue access point (hostapd + dnsmasq) with configurable SSID, channel, encryption
- **WPA2 Passphrase** — Configurable passphrase for WPA2 evil twin (shown/hidden based on encryption selection)
- **Captive Portal** — 3 templates: WiFi Login, Router Firmware Update, Hotel/Cafe Login
- **ARP Spoofing** — Bidirectional MITM between target and gateway
- **Traffic Sniffer** — Capture HTTP URLs, cookies, form data via tshark (unencrypted HTTP only)
- **Network Host Discovery** — Scan local network for live hosts (arp-scan/nmap/ARP table), auto-fills ARP spoof targets
- **Credential Capture** — Live table of captured credentials from captive portal
- **Target Buttons** — Connected clients and discovered hosts have "Target" buttons that auto-fill ARP spoof fields

### Recon
- **Dual Adapter Mode** — Use two WiFi adapters: one for capture (stays on channel), one for injection (deauth). Auto-detect or manual assignment
- **WPA3-SAE Attacks** — 4 strategies:
  - **Auto** — detects transition mode, picks best approach
  - **Downgrade** — forces WPA3-transition clients back to WPA2 (2x continuous deauth + per-client targeted + Scapy disassoc)
  - **SAE Capture** — hcxdumptool v7 with BPF filters, auto-exits on EAPOL capture
  - **Passive** — no deauth, waits for natural reconnections (for PMF-required networks)
- **Dragonblood Scanner** — Passive vulnerability assessment: detects transition mode, PMF status, weak SAE groups. Risk levels: HIGH (PMF optional or transition mode), NONE (PMF required, WPA3-only)
- **WPS Network Scanner** — Detect WPS-enabled networks using `wash` with Pixie/Brute quick-action buttons
- **WPS Pixie-Dust Attack** — Offline WPS attack (seconds on vulnerable routers) via reaver `-K`
- **WPS PIN Brute-Force** — Online PIN attack via reaver or bully
- **Nmap Scanner** — 6 scan types: quick, standard, full, stealth, UDP, vuln scripts
- **Attack Monitor (IDS)** — Detect deauth floods (threshold: 10 frames/10s), disassociation attacks, and evil twin (same SSID from multiple BSSIDs)
- **PDF Report Generation** — Export all findings as a PDF audit report

## Requirements

- Linux (Kali recommended)
- Python 3.10+
- Root privileges (sudo)
- WiFi adapter with monitor mode + injection support
- Second WiFi adapter (optional, for dual adapter mode)

## Install

```bash
pip3 install -r requirements.txt

# Core (required)
sudo apt install aircrack-ng

# Evil Twin
sudo apt install hostapd dnsmasq

# WPA3 attacks
sudo apt install hcxdumptool hcxtools

# WPS scanning
sudo apt install reaver    # includes wash

# PDF reports
pip3 install fpdf2
```

## Run

```bash
sudo python3 wifisecaudit.py
```

Open http://localhost:8080

### Flags

- `--public` — bind to 0.0.0.0 (accessible from other machines)
- `--verbose` — enable HTTP request logging
- `--no-root-check` — skip the root privilege warning

## Tabs

| Tab | Purpose |
|-----|---------|
| **Monitor & Capture** | Network scanning, signal filter, client discovery, deauth, PMKID/handshake capture, sniffer |
| **Cracking** | Handshake validation, capture file browser, aircrack-ng cracking, wordlists, MAC spoofing |
| **Evil Twin** | Rogue AP, captive portal, host discovery, ARP spoofing, traffic sniffing |
| **Recon** | Dual adapter, WPA3 attacks, Dragonblood, WPS scanning/attacks, nmap, IDS, reports |

## Workflows

### Handshake Capture & Crack
1. Enable Monitor Mode → Scan Networks → Select target AP
2. Start Sniffer (locks to channel) → Deauth target → Sniffer captures handshake on reconnect
3. Cracking tab → Validate All → Confirm handshake valid → Select wordlist → Crack

### PMKID Capture
1. Enable Monitor Mode → Scan → Select target BSSID → Capture
2. Export Hashcat → `hashcat -m 22000 pmkid.22000 wordlist.txt`

### WPA3 Downgrade Attack
1. Enable Monitor Mode → Recon tab → Enter target BSSID + channel
2. Dragonblood Scan → Check risk level (HIGH = exploitable)
3. Select Auto or Downgrade → Attack → Captures WPA2 handshake via continuous deauth
4. Cracking tab → Crack the `.cap` file with wordlist
5. **Note:** Requires a client connected to the target AP. Broadcast deauth may not work on WPA3-only — use targeted client deauth

### WPA3 Passive SAE Capture
1. **Disable Monitor Mode** first (hcxdumptool manages monitor mode itself)
2. Recon tab → Enter BSSID + channel → Select Passive → Attack
3. Disconnect and reconnect a device to the target AP
4. hcxdumptool captures the SAE exchange → converts to `.22000` via hcxpcapngtool
5. Crack with `hashcat -m 22000`

### Evil Twin Credential Capture
1. Monitor tab: Scan networks → Note target SSID + channel
2. Evil Twin tab → Enter SSID/channel → Select WPA2 + set passphrase → Enable Captive Portal → Start
3. Victims connect → Captive portal shows fake login → Credentials captured in UI

### WPS Pixie-Dust
1. Enable Monitor Mode → Recon tab → Scan for WPS
2. Click Pixie button on vulnerable target → Attack starts with `-K` flag
3. Completes in seconds if router is vulnerable

### Dual Adapter
1. Plug in second WiFi adapter
2. Recon tab → Auto-Detect → Enable Both Monitor
3. All features use primary for capture, secondary for injection — no missed packets

### MITM Traffic Sniffing
1. Start Evil Twin or connect to cracked network
2. Evil Twin tab → Click Target on connected client → ARP spoof fields auto-fill
3. Start ARP Spoof → Start Traffic Capture → HTTP data appears in tables

## Important Notes

- **hcxdumptool v7** manages monitor mode itself — disable monitor mode before running SAE/passive captures
- **hcxpcapngtool** (from `hcxtools` package) is required to convert `.pcapng` captures to hashcat `.22000` format
- **Client "probing" status** means devices are scanning for networks but not connected — they cannot be deauthed. Modern devices use randomized MACs when probing
- **Evil twin cleanup** reloads the WiFi driver (`rmmod`/`modprobe`) to prevent broken adapter state. If scanning stops working, use the Reset Adapter button
- **WPA3-only APs with mandatory PMF** block deauth attacks — use passive capture or wait for natural reconnections

## Project Structure

```
wifisecaudit.py                  — Flask web server, API routes, module init
modules/
  pmkid_capture.py      — Core WiFi engine: scanning, capture, deauth, clients
  aircrack_runner.py     — Aircrack-ng cracking (supports .cap, .pcapng, .22000)
  wordlist_manager.py    — Wordlist listing/upload/management
  mode_manager.py        — Adapter mode controller + interface reset
  mac_spoofer.py         — MAC address spoofing (macchanger)
  evil_twin.py           — Rogue AP (hostapd + dnsmasq + driver reload)
  captive_portal.py      — Fake login HTTP server (port 80)
  arp_spoofer.py         — Bidirectional ARP spoofing
  traffic_sniffer.py     — HTTP traffic capture (tshark)
  nmap_scanner.py        — Nmap wrapper with XML parsing
  wps_attack.py          — WPS pixie-dust + brute-force (reaver/bully)
  wps_scanner.py         — WPS network detection (wash)
  wpa3_attack.py         — WPA3-SAE attacks + Dragonblood (hcxdumptool v7)
  dual_interface.py      — Dual WiFi adapter management
  handshake_validator.py — Validates .cap/.pcapng/.22000 files
  attack_monitor.py      — Wireless IDS (deauth/disassoc/evil twin detection)
  report_generator.py    — PDF report generation (fpdf2)
routes/
  cracking.py            — Cracking & wordlist API routes
  mac.py                 — MAC spoofing & interface reset routes
  eviltwin.py            — Evil twin, ARP spoof, traffic, host discovery routes
  recon.py               — WPA3, WPS, nmap, dual adapter, IDS, report routes
templates/
  index.html             — Single-page web dashboard (4 tabs)
  captive/               — Captive portal templates (3 designs)
static/
  cracking.js            — Cracking tab JavaScript
  eviltwin.js            — Evil Twin tab JavaScript
  recon.js               — Recon tab JavaScript
data/
  wordlists/             — User-uploaded wordlists
  reports/               — Generated PDF reports
```

## Documentation

See [DOCUMENTATION.md](DOCUMENTATION.md) for the full technical reference.

## Legal

Only use on networks you own or have explicit written authorization to test. Unauthorized access to computer networks is illegal.
