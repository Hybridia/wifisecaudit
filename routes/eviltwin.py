"""
Evil Twin, ARP spoofing, traffic sniffing, and captive portal API routes (Phase 3).
"""

from flask import Blueprint, jsonify, request

eviltwin_bp = Blueprint("eviltwin", __name__)

# Set by wifisecaudit.py
evil_twin = None
captive_portal = None
arp_spoofer = None
traffic_sniffer = None


@eviltwin_bp.route("/api/eviltwin/start", methods=["POST"])
def eviltwin_start():
    data = request.json or {}
    ssid = data.get("ssid")
    channel = data.get("channel", 6)
    captive = data.get("captive", False)
    encryption = data.get("encryption", "open")
    template = data.get("template", "wifi_login")
    wpa_passphrase = data.get("wpa_passphrase", "testing123")

    if not ssid:
        return jsonify({"error": "ssid required"}), 400

    if encryption == "wpa2" and len(wpa_passphrase) < 8:
        return jsonify({"error": "WPA2 passphrase must be at least 8 characters"}), 400

    success, msg = evil_twin.start(ssid, channel, encryption=encryption, captive=captive, wpa_passphrase=wpa_passphrase)

    # Start captive portal if requested
    if success and captive:
        captive_portal.start(template=template)

    return jsonify({"success": success, "message": msg})


@eviltwin_bp.route("/api/eviltwin/stop", methods=["POST"])
def eviltwin_stop():
    captive_portal.stop()
    evil_twin.stop()
    return jsonify({"success": True})


@eviltwin_bp.route("/api/eviltwin/status")
def eviltwin_status():
    return jsonify(evil_twin.get_status())


@eviltwin_bp.route("/api/eviltwin/clients")
def eviltwin_clients():
    return jsonify(evil_twin.get_connected_clients())


# ─── ARP Spoofing ─────────────────────────────────────────────────────────

@eviltwin_bp.route("/api/arpspoof/start", methods=["POST"])
def arpspoof_start():
    data = request.json or {}
    target_ip = data.get("target_ip")
    gateway_ip = data.get("gateway_ip")
    interface = data.get("interface")

    if not target_ip or not gateway_ip:
        return jsonify({"error": "target_ip and gateway_ip required"}), 400

    if not interface:
        interface = evil_twin.mode_manager.interface

    success, msg = arp_spoofer.start(interface, target_ip, gateway_ip)
    return jsonify({"success": success, "message": msg})


@eviltwin_bp.route("/api/arpspoof/stop", methods=["POST"])
def arpspoof_stop():
    arp_spoofer.stop()
    return jsonify({"success": True})


@eviltwin_bp.route("/api/arpspoof/status")
def arpspoof_status():
    return jsonify(arp_spoofer.get_status())


# ─── Traffic Sniffer ──────────────────────────────────────────────────────

@eviltwin_bp.route("/api/traffic/start", methods=["POST"])
def traffic_start():
    data = request.json or {}
    interface = data.get("interface")
    if not interface:
        interface = evil_twin.mode_manager.interface
    success = traffic_sniffer.start(interface)
    return jsonify({"success": success})


@eviltwin_bp.route("/api/traffic/stop", methods=["POST"])
def traffic_stop():
    traffic_sniffer.stop()
    return jsonify({"success": True})


@eviltwin_bp.route("/api/traffic/captured")
def traffic_captured():
    return jsonify(traffic_sniffer.get_captured_data())


# ─── Captive Portal ──────────────────────────────────────────────────────

@eviltwin_bp.route("/api/captive/credentials")
def captive_credentials():
    return jsonify(captive_portal.get_captured_credentials())


# ─── Network Host Discovery ──────────────────────────────────────────────

@eviltwin_bp.route("/api/hosts/discover", methods=["POST"])
def discover_hosts():
    """Scan the local network for live hosts using arp-scan or nmap -sn."""
    import subprocess
    import re

    data = request.json or {}
    interface = data.get("interface") or evil_twin.mode_manager.interface
    subnet = data.get("subnet")

    # Detect gateway and subnet if not provided
    gateway = None
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5
        )
        gw_match = re.search(r"default via (\S+) dev (\S+)", result.stdout)
        if gw_match:
            gateway = gw_match.group(1)
            gw_iface = gw_match.group(2)
            if not subnet:
                # Get subnet from interface
                ip_result = subprocess.run(
                    ["ip", "-4", "addr", "show", gw_iface],
                    capture_output=True, text=True, timeout=5
                )
                subnet_match = re.search(r"inet (\d+\.\d+\.\d+)\.\d+/(\d+)", ip_result.stdout)
                if subnet_match:
                    subnet = f"{subnet_match.group(1)}.0/{subnet_match.group(2)}"
    except Exception:
        pass

    # If evil twin is running, use its subnet
    if not subnet and evil_twin.running:
        subnet = "192.168.4.0/24"
        gateway = "192.168.4.1"

    if not subnet:
        return jsonify({"error": "Could not detect network. Are you connected to a network or running evil twin?", "hosts": [], "gateway": None}), 400

    hosts = []

    # Try arp-scan first (fast and reliable)
    try:
        result = subprocess.run(
            ["arp-scan", "--interface", interface, subnet],
            capture_output=True, text=True, timeout=30
        )
        for line in result.stdout.strip().split("\n"):
            match = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+([\da-f:]{17})\s*(.*)", line, re.I)
            if match:
                hosts.append({
                    "ip": match.group(1),
                    "mac": match.group(2),
                    "vendor": match.group(3).strip() or "Unknown",
                })
    except FileNotFoundError:
        # Fall back to nmap -sn
        try:
            result = subprocess.run(
                ["nmap", "-sn", subnet],
                capture_output=True, text=True, timeout=30
            )
            current_ip = None
            current_mac = None
            for line in result.stdout.split("\n"):
                ip_match = re.search(r"Nmap scan report for .*?(\d+\.\d+\.\d+\.\d+)", line)
                if ip_match:
                    current_ip = ip_match.group(1)
                mac_match = re.search(r"MAC Address: ([\dA-F:]{17})\s*(.*)", line, re.I)
                if mac_match and current_ip:
                    hosts.append({
                        "ip": current_ip,
                        "mac": mac_match.group(1),
                        "vendor": mac_match.group(2).strip("() ") or "Unknown",
                    })
                    current_ip = None
        except FileNotFoundError:
            # Last resort: read ARP table
            try:
                result = subprocess.run(["arp", "-n"], capture_output=True, text=True, timeout=5)
                for line in result.stdout.strip().split("\n")[1:]:
                    parts = line.split()
                    if len(parts) >= 3 and parts[2] != "(incomplete)":
                        hosts.append({
                            "ip": parts[0],
                            "mac": parts[2],
                            "vendor": "Unknown",
                        })
            except Exception:
                pass

    return jsonify({"hosts": hosts, "gateway": gateway, "subnet": subnet})
