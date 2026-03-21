# WiFi Security Audit Tool

Standalone web-based WiFi penetration testing toolkit for authorized security assessments.

## Features

- **Network Scanning** — Discover nearby WiFi networks (2.4GHz + 5GHz), channel hopping, signal strength
- **Client Discovery** — Find connected clients on selected APs using airodump-ng, with MAC vendor resolution
- **Deauthentication** — Broadcast AP deauth (all clients) or targeted client deauth (specific clients only)
- **PMKID Capture** — Capture PMKID from WPA2 handshakes for offline password testing
- **Handshake Capture** — Capture 4-way WPA2 handshakes
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
5. **Deauth** — broadcast deauth on APs or targeted deauth on specific clients
6. **Capture PMKID** — select a target BSSID and start capture
7. **Export** — export PMKIDs for hashcat cracking

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
