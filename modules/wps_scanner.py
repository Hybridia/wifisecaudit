"""
WPS network scanner using wash — detects WPS-enabled networks.
"""

import re
import signal
import subprocess
import threading


class WPSScanner:
    """Scan for WPS-enabled networks using wash."""

    def __init__(self, log_fn=None):
        self.log_fn = log_fn
        self.running = False
        self._proc = None
        self._thread = None
        self.results = []
        self.lock = threading.Lock()

    def _log(self, level, message):
        if self.log_fn:
            self.log_fn(level, f"[wps-scan] {message}")

    def scan(self, interface, duration=30) -> tuple:
        """Start scanning for WPS-enabled networks. Returns (success, message)."""
        if self.running:
            return False, "WPS scan already running"

        self.running = True
        with self.lock:
            self.results = []

        self._thread = threading.Thread(
            target=self._run_scan, args=(interface, duration), daemon=True
        )
        self._thread.start()
        self._log("info", f"WPS scan started on {interface} ({duration}s)")
        return True, "WPS scan started"

    def _run_scan(self, interface, duration):
        """Run wash and parse output."""
        try:
            self._proc = subprocess.Popen(
                ["wash", "-i", interface, "-s"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1
            )

            # Let wash run for the specified duration
            try:
                stdout, _ = self._proc.communicate(timeout=duration)
            except subprocess.TimeoutExpired:
                self._proc.send_signal(signal.SIGTERM)
                stdout, _ = self._proc.communicate(timeout=5)

            parsed = []
            for line in stdout.strip().split("\n"):
                line = line.strip()
                if not line or line.startswith("Wash") or line.startswith("BSSID") or line.startswith("---"):
                    continue
                # wash output format:
                # BSSID               Ch  dBm  WPS  Lck  Vendor    ESSID
                # AA:BB:CC:DD:EE:FF    6  -45  2.0  No   RalinkTe  MyNetwork
                parts = line.split(None, 6)
                if len(parts) >= 6:
                    entry = {
                        "bssid": parts[0],
                        "channel": int(parts[1]) if parts[1].isdigit() else 0,
                        "signal": int(parts[2]) if parts[2].lstrip("-").isdigit() else 0,
                        "wps_version": parts[3],
                        "locked": parts[4].lower() == "yes",
                        "vendor": parts[5] if len(parts) > 5 else "",
                        "ssid": parts[6] if len(parts) > 6 else "",
                    }
                    parsed.append(entry)

            with self.lock:
                self.results = parsed
                self.running = False

            self._log("info", f"WPS scan complete: {len(parsed)} WPS network(s) found")

        except FileNotFoundError:
            self._log("error", "wash not found. Install with: sudo apt install reaver")
            with self.lock:
                self.running = False
        except Exception as e:
            self._log("error", f"WPS scan error: {e}")
            with self.lock:
                self.running = False
        finally:
            self._proc = None

    def stop(self):
        """Stop WPS scan."""
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

    def get_results(self) -> dict:
        """Return scan results."""
        with self.lock:
            return {
                "running": self.running,
                "networks": list(self.results),
            }
