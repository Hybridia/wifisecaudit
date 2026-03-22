# WiFi Security Audit Tool

Standalone web-based WiFi penetration testing toolkit for authorized security assessments.

## Features

- **Network Scanning** — Discover nearby WiFi networks (2.4GHz + 5GHz), channel hopping, signal strength
- **Hidden SSID Reveal** — Automatically uncovers hidden network names from probe requests/responses
- **Client Discovery** — Find connected clients on selected APs using airodump-ng, with MAC vendor resolution
- **Deauthentication** — Broadcast AP deauth (all clients) or targeted client deauth (specific clients only)
- **PMKID Capture** — Capture PMKID from WPA2 handshakes for offline password testing
- **Passive Sniffer** — Background EAPOL sniffer that captures handshakes when clients reconnect after deauth
- **Handshake Capture** — Capture 4-way WPA2 handshakes (Messages 1+2 minimum)
- **Handshake Export** — Export captured handshakes as `.cap` (aircrack-ng) or `.hc22000` (hashcat) per-handshake files
- **Hashcat Export** — Export captured PMKIDs in hashcat mode 22000 format

## Requirements

- Linux (Kali recommended)
- Python 3.10+
- Root privileges (sudo)
- WiFi adapter that supports monitor mode and injection
- aircrack-ng suite (`airmon-ng`, `aireplay-ng`, `airodump-ng`)

## Install

```bash
pip3 install -r requirements.txt
sudo apt install aircrack-ng  # if not already installed
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

## Workflow

1. **Enable Monitor Mode** — click the button in the status bar
2. **Scan Networks** — discover nearby APs, stop when you see your targets
3. **Select Targets** — check the APs you want to test
4. **Scan Clients** — discover who's connected to the selected APs
5. **Start Sniffer** — begin passive EAPOL capture (optionally set target BSSID to lock channel)
6. **Deauth** — broadcast deauth on APs or targeted deauth on specific clients
7. **Capture Handshake** — sniffer automatically captures the 4-way handshake when clients reconnect
8. **Export** — select format (`.cap` for aircrack-ng or `.hc22000` for hashcat), export individual or all handshakes
9. **Crack** — run `aircrack-ng -w wordlist.txt handshake.cap` to recover the password

### PMKID Workflow (alternative)

1. Enable monitor mode, scan networks
2. Select a target BSSID and click **Capture** — injects auth/assoc frames to trigger PMKID
3. **Export Hashcat** — export PMKIDs for `hashcat -m 22000`

## Project Structure

```
wifisecaudit.py                  — Flask web server, all API routes
modules/
  pmkid_capture.py      — WiFi engine: scanning, capture, deauth, client discovery
templates/
  index.html            — Single-page web dashboard
```

## Documentation

See [DOCUMENTATION.md](DOCUMENTATION.md) for the full technical reference — every file, function, API endpoint, and design decision explained in detail.

## Legal

Only use on networks you own or have explicit written authorization to test. Unauthorized access to computer networks is illegal.
