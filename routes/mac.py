"""
MAC spoofing & interface management API routes (Phase 2).
"""

from flask import Blueprint, jsonify, request

mac_bp = Blueprint("mac", __name__)

# Set by wifisecaudit.py
mac_spoofer = None
mode_manager = None


@mac_bp.route("/api/mac/change", methods=["POST"])
def mac_change():
    data = request.json or {}
    mac = data.get("mac")
    randomize = data.get("randomize", False)
    clone_from = data.get("clone_from")

    success, msg = mac_spoofer.change_mac(mac=mac, randomize=randomize, clone_from=clone_from)
    return jsonify({"success": success, "message": msg})


@mac_bp.route("/api/mac/restore", methods=["POST"])
def mac_restore():
    success, msg = mac_spoofer.restore_mac()
    return jsonify({"success": success, "message": msg})


@mac_bp.route("/api/mac/current")
def mac_current():
    return jsonify({"mac": mac_spoofer.get_current_mac()})


@mac_bp.route("/api/interface/reset", methods=["POST"])
def interface_reset():
    """Full adapter reset — reloads driver to fix broken state after evil twin."""
    success, msg = mode_manager.reset_interface()
    return jsonify({"success": success, "message": msg})
