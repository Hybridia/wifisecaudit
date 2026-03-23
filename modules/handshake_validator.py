"""
Handshake validator — verifies captured .cap files contain valid WPA handshakes.
Uses aircrack-ng to test handshake validity.
"""

import os
import re
import subprocess


class HandshakeValidator:
    """Validate WPA handshakes in capture files."""

    def __init__(self, log_fn=None):
        self.log_fn = log_fn

    def _log(self, level, message):
        if self.log_fn:
            self.log_fn(level, f"[validate] {message}")

    def validate(self, cap_file: str) -> dict:
        """
        Validate a capture file for WPA handshakes.
        Returns dict with validation results.
        """
        if not os.path.isfile(cap_file):
            return {"valid": False, "error": "File not found", "file": cap_file}

        result = {
            "file": cap_file,
            "valid": False,
            "networks": [],
            "method": None,
        }

        # .22000 files are hashcat hashes — already valid by definition
        if cap_file.endswith(".22000"):
            try:
                with open(cap_file, "r") as f:
                    content = f.read().strip()
                lines = [l for l in content.split("\n") if l.startswith("WPA*")]
                if lines:
                    return {
                        "file": cap_file,
                        "valid": True,
                        "networks": [],
                        "method": "hashcat",
                        "hash_lines": len(lines),
                    }
            except Exception:
                pass
            return {"file": cap_file, "valid": False, "error": "Empty or invalid .22000 file", "method": "hashcat"}

        # Try aircrack-ng first (most reliable)
        aircrack_result = self._validate_aircrack(cap_file)
        if aircrack_result:
            result.update(aircrack_result)
            result["method"] = "aircrack-ng"
            return result

        # Try tshark as fallback for EAPOL frame count
        tshark_result = self._validate_tshark(cap_file)
        if tshark_result:
            result.update(tshark_result)
            result["method"] = "tshark"
            return result

        return result

    def _validate_aircrack(self, cap_file: str) -> dict:
        """Use aircrack-ng to check for valid handshakes."""
        try:
            proc = subprocess.run(
                ["aircrack-ng", cap_file],
                capture_output=True, text=True, timeout=15,
                input="q\n"  # quit immediately
            )
            output = proc.stdout + proc.stderr

            networks = []
            # aircrack-ng lists networks with handshake info
            # Look for lines like: "1  AA:BB:CC:DD:EE:FF  MyNetwork  WPA (1 handshake)"
            for line in output.split("\n"):
                hs_match = re.search(
                    r"(\S{2}:\S{2}:\S{2}:\S{2}:\S{2}:\S{2})\s+(.+?)\s+WPA\s*\((\d+)\s+handshake",
                    line, re.I
                )
                if hs_match:
                    networks.append({
                        "bssid": hs_match.group(1),
                        "ssid": hs_match.group(2).strip(),
                        "handshake_count": int(hs_match.group(3)),
                    })

                # Also check for PMKID
                pmkid_match = re.search(
                    r"(\S{2}:\S{2}:\S{2}:\S{2}:\S{2}:\S{2})\s+(.+?)\s+WPA\s*\(\d+\s+handshake.*?(\d+)\s+PMKID",
                    line, re.I
                )
                if pmkid_match:
                    # Update existing entry
                    bssid = pmkid_match.group(1)
                    for n in networks:
                        if n["bssid"] == bssid:
                            n["pmkid_count"] = int(pmkid_match.group(3))

            if networks:
                self._log("info", f"Valid handshake(s) in {os.path.basename(cap_file)}: "
                          + ", ".join(f"{n['ssid']} ({n['handshake_count']})" for n in networks))
                return {"valid": True, "networks": networks}

            # Check if "No networks found" or similar
            if "No networks found" in output or "0 handshake" in output:
                self._log("warning", f"No valid handshakes in {os.path.basename(cap_file)}")
                return {"valid": False, "networks": []}

            return None  # Inconclusive

        except FileNotFoundError:
            return None
        except Exception as e:
            self._log("error", f"aircrack-ng validation failed: {e}")
            return None

    def _validate_tshark(self, cap_file: str) -> dict:
        """Use tshark to count EAPOL frames as a basic validity check."""
        try:
            result = subprocess.run(
                ["tshark", "-r", cap_file, "-Y", "eapol", "-T", "fields",
                 "-e", "wlan.sa", "-e", "wlan.da", "-e", "eapol.type"],
                capture_output=True, text=True, timeout=15
            )

            eapol_count = len([l for l in result.stdout.strip().split("\n") if l.strip()])

            # A valid 4-way handshake needs at least 2 EAPOL frames
            # (messages 1+2 minimum for cracking)
            if eapol_count >= 2:
                self._log("info", f"Found {eapol_count} EAPOL frames in {os.path.basename(cap_file)}")
                return {"valid": True, "eapol_frames": eapol_count, "networks": []}
            else:
                self._log("warning", f"Only {eapol_count} EAPOL frame(s) — insufficient for cracking")
                return {"valid": False, "eapol_frames": eapol_count, "networks": []}

        except FileNotFoundError:
            return None
        except Exception:
            return None

    def validate_all(self, data_dir="data") -> list:
        """Validate all capture files in the data directory."""
        import glob
        results = []
        for pattern in ["*.cap", "*.pcap", "*.pcapng"]:
            for cap_file in glob.glob(os.path.join(data_dir, pattern)):
                result = self.validate(cap_file)
                results.append(result)
        return results
