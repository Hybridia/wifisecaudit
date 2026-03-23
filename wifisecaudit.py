#!/usr/bin/env python3
"""
WiFi Security Audit Tool
Standalone web-based WiFi penetration testing toolkit.

Features:
  - WiFi network scanning (monitor mode, channel hopping)
  - Client discovery on selected APs
  - PMKID / handshake capture
  - Deauthentication (AP broadcast + targeted client)
  - Export captured hashes for hashcat
  - Aircrack-ng cracking & wordlist management
  - MAC spoofing
  - Evil twin AP with captive portal
  - ARP spoofing & traffic sniffing
Run with: sudo python3 wifisecaudit.py
"""

import os
import sys
import signal
import logging
import threading

from flask import Flask, render_template, jsonify, request
from modules.pmkid_capture import PMKIDCapture
from modules.aircrack_runner import AircrackRunner
from modules.wordlist_manager import WordlistManager
from modules.mode_manager import ModeManager
from modules.mac_spoofer import MacSpoofer
from modules.evil_twin import EvilTwin
from modules.captive_portal import CaptivePortal
from modules.arp_spoofer import ArpSpoofer
from modules.traffic_sniffer import TrafficSniffer
from modules.nmap_scanner import NmapScanner
from modules.wps_attack import WPSAttack
from modules.wps_scanner import WPSScanner
from modules.report_generator import ReportGenerator
from modules.handshake_validator import HandshakeValidator
from modules.attack_monitor import AttackMonitor
from modules.wpa3_attack import WPA3Attack
from modules.dual_interface import DualInterface
from routes.cracking import cracking_bp
from routes.mac import mac_bp
from routes.eviltwin import eviltwin_bp
from routes.recon import recon_bp

app = Flask(__name__)

# Register blueprints
app.register_blueprint(cracking_bp)
app.register_blueprint(mac_bp)
app.register_blueprint(eviltwin_bp)
app.register_blueprint(recon_bp)

# ─── Global state ───────────────────────────────────────────────────────────

pmkid = None  # Set in main()


# ─── Routes: UI ─────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


# ─── Routes: Interfaces & Monitor Mode ──────────────────────────────────────

@app.route("/api/pmkid/interfaces")
def api_pmkid_interfaces():
    return jsonify(pmkid.get_wifi_interfaces())


@app.route("/api/pmkid/monitor", methods=["POST"])
def api_pmkid_monitor_mode():
    data = request.json or {}
    interface = data.get("interface")
    enable = data.get("enable", True)

    if not interface:
        return jsonify({"error": "Interface required"}), 400

    if enable:
        success, msg = pmkid.enable_monitor_mode(interface)
    else:
        success, msg = pmkid.disable_monitor_mode(interface)

    return jsonify({"success": success, "message": msg})


# ─── Routes: Network Scanning ───────────────────────────────────────────────

@app.route("/api/pmkid/scan", methods=["POST"])
def api_pmkid_scan():
    data = request.json or {}
    interface = data.get("interface")
    duration = data.get("duration", 120)

    if not interface:
        wifi = pmkid.get_wifi_interfaces()
        if wifi:
            interface = wifi[0]["name"]
        else:
            return jsonify({"error": "No WiFi interface found"}), 404

    # Use the monitor interface if monitor mode is active
    scan_iface = pmkid.monitor_interface or interface

    def do_scan():
        pmkid.scan_networks(scan_iface, duration=duration)

    threading.Thread(target=do_scan, daemon=True).start()
    return jsonify({"success": True, "interface": scan_iface, "duration": duration})


@app.route("/api/pmkid/scan/stop", methods=["POST"])
def api_pmkid_scan_stop():
    pmkid.stop_scan()
    return jsonify({"success": True})


@app.route("/api/pmkid/networks")
def api_pmkid_networks():
    networks = [n.to_dict() for n in pmkid.networks.values()]
    networks.sort(key=lambda x: x.get("signal", 0), reverse=True)
    return jsonify(networks)


@app.route("/api/debug/scan-test", methods=["POST"])
def api_debug_scan_test():
    """Quick diagnostic: try scapy sniff for 3s and report what happens."""
    import traceback
    iface = pmkid.monitor_interface or "wlan0"
    result = {
        "interface": iface,
        "monitor_mode_active": pmkid.monitor_mode_active,
        "monitor_interface": pmkid.monitor_interface,
    }
    try:
        from scapy.all import sniff as scapy_sniff
        packets = scapy_sniff(iface=iface, timeout=3, store=True, monitor=pmkid.monitor_mode_active)
        result["success"] = True
        result["packets"] = len(packets)
        result["summary"] = [p.summary()[:80] for p in packets[:5]]
    except Exception as e:
        result["success"] = False
        result["error"] = str(e)
        result["traceback"] = traceback.format_exc()
    return jsonify(result)


# ─── Routes: PMKID / Handshake Capture ──────────────────────────────────────

@app.route("/api/pmkid/capture", methods=["POST"])
def api_pmkid_capture_start():
    data = request.json or {}
    interface = data.get("interface")
    target_bssid = data.get("bssid")
    duration = data.get("duration", 60)

    if not interface:
        wifi = pmkid.get_wifi_interfaces()
        if wifi:
            interface = wifi[0]["name"]
        else:
            return jsonify({"error": "No WiFi interface found"}), 404

    if pmkid.running:
        return jsonify({"error": "Capture already in progress"}), 409

    # Use the monitor interface if monitor mode is active
    cap_iface = pmkid.monitor_interface or interface

    def do_capture():
        pmkid.start_capture(cap_iface, target_bssid, duration)

    threading.Thread(target=do_capture, daemon=True).start()
    return jsonify({"success": True, "interface": interface, "duration": duration})


@app.route("/api/pmkid/stop", methods=["POST"])
def api_pmkid_capture_stop():
    pmkid.stop_capture()
    return jsonify({"success": True})


@app.route("/api/pmkid/status")
def api_pmkid_status():
    return jsonify(pmkid.get_status())


@app.route("/api/pmkid/results")
def api_pmkid_results():
    return jsonify(pmkid.get_results())


@app.route("/api/pmkid/export", methods=["POST"])
def api_pmkid_export():
    filepath = pmkid.export_hashcat()
    if filepath:
        return jsonify({"success": True, "file": filepath})
    return jsonify({"error": "No PMKIDs to export"}), 404


@app.route("/api/pmkid/log")
def api_pmkid_log():
    n = request.args.get("n", 50, type=int)
    return jsonify(pmkid.get_log(n))


@app.route("/api/handshake/export", methods=["POST"])
def api_handshake_export():
    data = request.json or {}
    indices = data.get("indices")  # None = all, or list of ints
    fmt = data.get("format", "pcap")  # "pcap" or "hc22000"
    files = pmkid.export_handshakes(indices, fmt=fmt)
    if files:
        return jsonify({"success": True, "files": files, "count": len(files)})
    return jsonify({"error": "No handshakes to export"}), 404


# ─── Routes: Passive Sniffer ────────────────────────────────────────────

@app.route("/api/sniffer/start", methods=["POST"])
def api_sniffer_start():
    data = request.json or {}
    interface = data.get("interface")
    channel = data.get("channel")
    bssid = data.get("bssid")

    if not interface:
        wifi = pmkid.get_wifi_interfaces()
        if wifi:
            interface = wifi[0]["name"]
        else:
            return jsonify({"error": "No WiFi interface found"}), 404

    if pmkid.sniffer_active:
        return jsonify({"error": "Sniffer already running"}), 409

    sniff_iface = pmkid.monitor_interface or interface
    success = pmkid.start_sniffer(sniff_iface, channel=channel, bssid=bssid)
    return jsonify({"success": success})


@app.route("/api/sniffer/stop", methods=["POST"])
def api_sniffer_stop():
    pmkid.stop_sniffer()
    return jsonify({"success": True})


@app.route("/api/sniffer/status")
def api_sniffer_status():
    return jsonify({
        "active": pmkid.sniffer_active,
        "interface": pmkid.sniffer_interface,
    })


# ─── Routes: Client Scanning ────────────────────────────────────────────────

@app.route("/api/clients/scan", methods=["POST"])
def api_client_scan():
    data = request.json or {}
    targets = data.get("targets", [])
    duration = data.get("duration", 30)

    if not targets:
        return jsonify({"error": "targets list required"}), 400

    interface = data.get("interface")
    if not interface:
        wifi = pmkid.get_wifi_interfaces()
        if wifi:
            interface = wifi[0]["name"]
        else:
            return jsonify({"error": "No WiFi interface found"}), 404

    client_iface = pmkid.monitor_interface or interface
    success = pmkid.start_client_scan(client_iface, targets, duration)
    if success:
        return jsonify({"success": True})
    return jsonify({"error": "Failed to start client scan. Check monitor mode."}), 400


@app.route("/api/clients/scan/stop", methods=["POST"])
def api_client_scan_stop():
    pmkid.stop_client_scan()
    return jsonify({"success": True})


@app.route("/api/clients")
def api_clients():
    return jsonify(pmkid.get_client_scan_status())


# ─── Routes: Deauthentication ────────────────────────────────────────────────

@app.route("/api/deauth/start", methods=["POST"])
def api_deauth_start():
    data = request.json or {}
    count = data.get("count", 0)

    targets = data.get("targets")
    target_bssid = data.get("bssid")
    channel = data.get("channel", 0)
    client_targets = data.get("clients")

    if not targets and not target_bssid and not client_targets:
        return jsonify({"error": "bssid, targets, or clients required"}), 400

    interface = data.get("interface")
    if not interface:
        wifi = pmkid.get_wifi_interfaces()
        if wifi:
            interface = wifi[0]["name"]
        else:
            return jsonify({"error": "No WiFi interface found"}), 404

    deauth_iface = pmkid.monitor_interface or interface
    success = pmkid.start_deauth(
        deauth_iface, target_bssid=target_bssid, channel=channel,
        count=count, targets=targets, clients=client_targets
    )

    if success:
        return jsonify({"success": True})
    return jsonify({"error": "Failed to start deauth. Check monitor mode is enabled."}), 400


@app.route("/api/deauth/stop", methods=["POST"])
def api_deauth_stop():
    pmkid.stop_deauth()
    return jsonify({"success": True})


@app.route("/api/deauth/status")
def api_deauth_status():
    return jsonify(pmkid.get_deauth_status())


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    global pmkid

    if os.geteuid() != 0 and "--no-root-check" not in sys.argv:
        print("\n" + "=" * 60)
        print("  WARNING: Not running as root.")
        print("  WiFi scanning and injection require root privileges.")
        print("  Run with: sudo python3 wifisecaudit.py")
        print("=" * 60)
        try:
            response = input("\nContinue anyway? (y/n): ")
            if response.lower() != "y":
                sys.exit(1)
        except EOFError:
            print("Non-interactive mode, continuing...")

    os.makedirs("data", exist_ok=True)
    os.makedirs("data/wordlists", exist_ok=True)
    os.makedirs("data/reports", exist_ok=True)

    pmkid = PMKIDCapture(interface="wlan0")
    log_fn = pmkid._log

    # ─── Initialize new modules ─────────────────────────────────────────
    import routes.cracking as rc
    import routes.mac as rm
    import routes.eviltwin as re_
    import routes.recon as rr

    # Phase 1: Cracking & wordlists
    rc.aircrack = AircrackRunner(data_dir="data", log_fn=log_fn)
    rc.wordlist_mgr = WordlistManager(upload_dir="data/wordlists", log_fn=log_fn)

    # Phase 2: Mode manager & MAC spoofing
    mode_mgr = ModeManager(interface="wlan0", pmkid=pmkid)
    rm.mac_spoofer = MacSpoofer(mode_mgr, log_fn=log_fn)
    rm.mode_manager = mode_mgr

    # Phase 3: Evil twin, captive portal, ARP spoof, traffic sniffer
    re_.evil_twin = EvilTwin(mode_mgr, log_fn=log_fn)
    re_.captive_portal = CaptivePortal(template_dir="templates/captive", log_fn=log_fn)
    re_.arp_spoofer = ArpSpoofer(log_fn=log_fn)
    re_.traffic_sniffer = TrafficSniffer(log_fn=log_fn)

    # Phase 4: Nmap, WPS, handshake validation, attack monitoring, reports
    rr.nmap_scanner = NmapScanner(log_fn=log_fn)
    rr.wps_attack = WPSAttack(log_fn=log_fn)
    rr.wps_scanner = WPSScanner(log_fn=log_fn)
    rr.report_gen = ReportGenerator(output_dir="data/reports", log_fn=log_fn)
    rr.pmkid = pmkid
    rr.handshake_validator = HandshakeValidator(log_fn=log_fn)
    rr.attack_monitor = AttackMonitor(log_fn=log_fn)
    rr.wpa3_attack = WPA3Attack(log_fn=log_fn)
    rr.dual_interface = DualInterface(log_fn=log_fn)

    def shutdown_handler(signum, frame):
        print("\nShutting down...")
        # Clean up evil twin if running
        if re_.evil_twin and re_.evil_twin.running:
            re_.evil_twin.stop()
        if re_.captive_portal and re_.captive_portal.running:
            re_.captive_portal.stop()
        if re_.arp_spoofer and re_.arp_spoofer.running:
            re_.arp_spoofer.stop()
        if re_.traffic_sniffer and re_.traffic_sniffer.running:
            re_.traffic_sniffer.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    if "--verbose" not in sys.argv:
        logging.getLogger("werkzeug").setLevel(logging.WARNING)

    print("\n" + "=" * 60)
    print("  WIFI SECURITY AUDIT TOOL")
    print("  Open http://localhost:8080 in your browser")
    print("=" * 60 + "\n")

    host = "0.0.0.0" if "--public" in sys.argv else "127.0.0.1"
    app.run(host=host, port=8080, debug=False, threaded=True)


if __name__ == "__main__":
    main()
