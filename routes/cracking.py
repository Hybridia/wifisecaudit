"""
Cracking & wordlist API routes (Phase 1).
"""

from flask import Blueprint, jsonify, request

cracking_bp = Blueprint("cracking", __name__)

# These are set by wifisecaudit.py after module init
aircrack = None
wordlist_mgr = None


@cracking_bp.route("/api/crack/start", methods=["POST"])
def crack_start():
    data = request.json or {}
    cap_file = data.get("cap_file")
    wordlist = data.get("wordlist")

    if not cap_file or not wordlist:
        return jsonify({"error": "cap_file and wordlist required"}), 400

    aircrack.crack(cap_file, wordlist)
    return jsonify({"success": True})


@cracking_bp.route("/api/crack/stop", methods=["POST"])
def crack_stop():
    aircrack.stop()
    return jsonify({"success": True})


@cracking_bp.route("/api/crack/status")
def crack_status():
    return jsonify(aircrack.get_status())


@cracking_bp.route("/api/crack/files")
def crack_files():
    return jsonify(aircrack.list_cap_files())


@cracking_bp.route("/api/wordlists")
def list_wordlists():
    return jsonify(wordlist_mgr.list_wordlists())


@cracking_bp.route("/api/wordlists/upload", methods=["POST"])
def upload_wordlist():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "No filename"}), 400
    success, msg = wordlist_mgr.save_upload(f.filename, f)
    if success:
        return jsonify({"success": True, "message": msg})
    return jsonify({"error": msg}), 400


@cracking_bp.route("/api/wordlists/<name>", methods=["DELETE"])
def delete_wordlist(name):
    if wordlist_mgr.delete_wordlist(name):
        return jsonify({"success": True})
    return jsonify({"error": "Wordlist not found or not deletable"}), 404


@cracking_bp.route("/api/wordlists/decompress-rockyou", methods=["POST"])
def decompress_rockyou():
    success, msg = wordlist_mgr.decompress_rockyou()
    return jsonify({"success": success, "message": msg})
