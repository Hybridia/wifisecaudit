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

Run with: sudo python3 wifisecaudit.py
"""

import os
import sys
import signal
import logging
import threading

from flask import Flask, render_template, jsonify, request
from modules.pmkid_capture import PMKIDCapture

app = Flask(__name__)

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

    def do_scan():
        pmkid.scan_networks(interface, duration=duration)

    threading.Thread(target=do_scan, daemon=True).start()
    return jsonify({"success": True, "interface": interface, "duration": duration})


@app.route("/api/pmkid/scan/stop", methods=["POST"])
def api_pmkid_scan_stop():
    pmkid.stop_scan()
    return jsonify({"success": True})


@app.route("/api/pmkid/networks")
def api_pmkid_networks():
    networks = [n.to_dict() for n in pmkid.networks.values()]
    networks.sort(key=lambda x: x.get("signal", 0), reverse=True)
    return jsonify(networks)


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

    def do_capture():
        pmkid.start_capture(interface, target_bssid, duration)

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

    success = pmkid.start_client_scan(interface, targets, duration)
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

    success = pmkid.start_deauth(
        interface, target_bssid=target_bssid, channel=channel,
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

    pmkid = PMKIDCapture(interface="wlan0")

    def shutdown_handler(signum, frame):
        print("\nShutting down...")
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
