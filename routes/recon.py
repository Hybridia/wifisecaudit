"""
Recon API routes — nmap, WPS attacks/scanning, handshake validation,
attack monitoring, report generation.
"""

from flask import Blueprint, jsonify, request

recon_bp = Blueprint("recon", __name__)

# Set by wifisecaudit.py
nmap_scanner = None
wps_attack = None
wps_scanner = None
report_gen = None
pmkid = None
handshake_validator = None
attack_monitor = None
wpa3_attack = None
dual_interface = None


# ─── Nmap ─────────────────────────────────────────────────────────────────

@recon_bp.route("/api/nmap/scan", methods=["POST"])
def nmap_scan():
    data = request.json or {}
    target = data.get("target")
    scan_type = data.get("scan_type", "quick")

    if not target:
        return jsonify({"error": "target required"}), 400

    success, msg = nmap_scanner.scan(target, scan_type)
    return jsonify({"success": success, "message": msg})


@recon_bp.route("/api/nmap/stop", methods=["POST"])
def nmap_stop():
    nmap_scanner.stop()
    return jsonify({"success": True})


@recon_bp.route("/api/nmap/results")
def nmap_results():
    return jsonify(nmap_scanner.get_results())


# ─── WPS Attack ──────────────────────────────────────────────────────────

@recon_bp.route("/api/wps/start", methods=["POST"])
def wps_start():
    data = request.json or {}
    bssid = data.get("bssid")
    tool = data.get("tool", "reaver")
    channel = data.get("channel")
    interface = data.get("interface")
    pixie_dust = data.get("pixie_dust", False)

    if not bssid:
        return jsonify({"error": "bssid required"}), 400

    if not interface and pmkid:
        interface = pmkid.monitor_interface
        if not interface:
            wifi = pmkid.get_wifi_interfaces()
            if wifi:
                interface = wifi[0]["name"]

    if not interface:
        return jsonify({"error": "No interface available"}), 404

    success, msg = wps_attack.start(bssid, interface, channel=channel, tool=tool, pixie_dust=pixie_dust)
    return jsonify({"success": success, "message": msg})


@recon_bp.route("/api/wps/stop", methods=["POST"])
def wps_stop():
    wps_attack.stop()
    return jsonify({"success": True})


@recon_bp.route("/api/wps/status")
def wps_status():
    return jsonify(wps_attack.get_status())


# ─── WPS Network Scanner (wash) ──────────────────────────────────────────

@recon_bp.route("/api/wps/scan", methods=["POST"])
def wps_scan():
    data = request.json or {}
    duration = data.get("duration", 30)
    interface = data.get("interface")

    if not interface and pmkid:
        interface = pmkid.monitor_interface
        if not interface:
            wifi = pmkid.get_wifi_interfaces()
            if wifi:
                interface = wifi[0]["name"]

    if not interface:
        return jsonify({"error": "No interface available"}), 404

    success, msg = wps_scanner.scan(interface, duration=duration)
    return jsonify({"success": success, "message": msg})


@recon_bp.route("/api/wps/scan/stop", methods=["POST"])
def wps_scan_stop():
    wps_scanner.stop()
    return jsonify({"success": True})


@recon_bp.route("/api/wps/scan/results")
def wps_scan_results():
    return jsonify(wps_scanner.get_results())


# ─── Handshake Validation ────────────────────────────────────────────────

@recon_bp.route("/api/handshake/validate", methods=["POST"])
def handshake_validate():
    data = request.json or {}
    cap_file = data.get("cap_file")

    if cap_file:
        result = handshake_validator.validate(cap_file)
        return jsonify(result)

    # Validate all cap files
    results = handshake_validator.validate_all()
    return jsonify({"files": results})


# ─── Attack Monitoring / IDS ─────────────────────────────────────────────

@recon_bp.route("/api/ids/start", methods=["POST"])
def ids_start():
    data = request.json or {}
    interface = data.get("interface")

    if not interface and pmkid:
        interface = pmkid.monitor_interface
        if not interface:
            wifi = pmkid.get_wifi_interfaces()
            if wifi:
                interface = wifi[0]["name"]

    if not interface:
        return jsonify({"error": "No interface available"}), 404

    success, msg = attack_monitor.start(interface)
    return jsonify({"success": success, "message": msg})


@recon_bp.route("/api/ids/stop", methods=["POST"])
def ids_stop():
    attack_monitor.stop()
    return jsonify({"success": True})


@recon_bp.route("/api/ids/status")
def ids_status():
    return jsonify(attack_monitor.get_status())


@recon_bp.route("/api/ids/clear", methods=["POST"])
def ids_clear():
    attack_monitor.clear_alerts()
    return jsonify({"success": True})


# ─── WPA3-SAE Attack ─────────────────────────────────────────────────────

@recon_bp.route("/api/wpa3/dragonblood", methods=["POST"])
def wpa3_dragonblood():
    data = request.json or {}
    bssid = data.get("bssid")
    channel = data.get("channel")
    interface = data.get("interface")

    if not bssid:
        return jsonify({"error": "bssid required"}), 400

    if not interface and pmkid:
        interface = pmkid.monitor_interface or "wlan0"

    report = wpa3_attack.check_dragonblood(bssid, interface, channel)
    return jsonify(report)


@recon_bp.route("/api/wpa3/start", methods=["POST"])
def wpa3_start():
    data = request.json or {}
    bssid = data.get("bssid")
    channel = data.get("channel")
    method = data.get("method", "auto")
    interface = data.get("interface")

    if not bssid:
        return jsonify({"error": "bssid required"}), 400

    if not interface and pmkid:
        interface = pmkid.monitor_interface or "wlan0"

    # Use secondary interface for deauth if dual mode is active
    secondary = None
    if dual_interface and dual_interface.enabled:
        secondary = dual_interface.get_injection_interface()

    success, msg = wpa3_attack.start_capture(bssid, interface, channel, method, secondary)
    return jsonify({"success": success, "message": msg})


@recon_bp.route("/api/wpa3/stop", methods=["POST"])
def wpa3_stop():
    wpa3_attack.stop()
    return jsonify({"success": True})


@recon_bp.route("/api/wpa3/status")
def wpa3_status():
    return jsonify(wpa3_attack.get_status())


# ─── Dual Interface ──────────────────────────────────────────────────────

@recon_bp.route("/api/dual/detect")
def dual_detect():
    return jsonify(dual_interface.get_status())


@recon_bp.route("/api/dual/auto", methods=["POST"])
def dual_auto():
    success, msg = dual_interface.auto_assign()
    return jsonify({"success": success, "message": msg})


@recon_bp.route("/api/dual/assign", methods=["POST"])
def dual_assign():
    data = request.json or {}
    primary = data.get("primary")
    secondary = data.get("secondary")
    if not primary or not secondary:
        return jsonify({"error": "primary and secondary required"}), 400
    success, msg = dual_interface.assign(primary, secondary)
    return jsonify({"success": success, "message": msg})


@recon_bp.route("/api/dual/monitor", methods=["POST"])
def dual_monitor():
    data = request.json or {}
    enable = data.get("enable", True)
    if enable:
        success, msg = dual_interface.enable_monitor_both()
    else:
        success, msg = dual_interface.disable_monitor_both()
    return jsonify({"success": success, "message": msg})


# ─── Report ───────────────────────────────────────────────────────────────

@recon_bp.route("/api/report/generate", methods=["POST"])
def report_generate():
    data = {}

    if pmkid:
        networks = [n.to_dict() for n in pmkid.networks.values()]
        networks.sort(key=lambda x: x.get("signal", 0), reverse=True)
        data["networks"] = networks

        results = pmkid.get_results()
        data["pmkids"] = results.get("pmkids", [])
        data["handshakes"] = results.get("handshakes", [])

    if nmap_scanner.results:
        data["nmap_results"] = nmap_scanner.results

    req_data = request.json or {}
    if "cracked_keys" in req_data:
        data["cracked_keys"] = req_data["cracked_keys"]

    success, result = report_gen.generate(data)
    if success:
        return jsonify({"success": True, "file": result})
    return jsonify({"error": result}), 500
