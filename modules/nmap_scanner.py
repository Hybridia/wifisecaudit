"""
Nmap scanner module — wraps nmap subprocess for network reconnaissance.
"""

import re
import signal
import subprocess
import threading
import xml.etree.ElementTree as ET


class NmapScanner:
    """Run nmap scans and parse results."""

    SCAN_TYPES = {
        "quick": ["-T4", "-F"],
        "standard": ["-T4", "-sV"],
        "full": ["-T4", "-A", "-p-"],
        "stealth": ["-sS", "-T2"],
        "udp": ["-sU", "--top-ports", "100"],
        "vuln": ["--script", "vuln", "-sV"],
    }

    def __init__(self, log_fn=None):
        self.log_fn = log_fn
        self.running = False
        self._proc = None
        self._thread = None
        self.results = None
        self.raw_output = ""
        self.lock = threading.Lock()

    def _log(self, level, message):
        if self.log_fn:
            self.log_fn(level, f"[nmap] {message}")

    def scan(self, target, scan_type="quick") -> tuple:
        """
        Start an nmap scan.
        Returns (success, message).
        """
        if self.running:
            return False, "Scan already running"

        args = self.SCAN_TYPES.get(scan_type, self.SCAN_TYPES["quick"])

        # Validate target (basic check)
        if not target or not re.match(r'^[a-zA-Z0-9./:_\-\s]+$', target):
            return False, "Invalid target"

        self.running = True
        self.results = None
        self.raw_output = ""

        self._thread = threading.Thread(
            target=self._run_scan, args=(target, args), daemon=True
        )
        self._thread.start()

        self._log("info", f"Nmap {scan_type} scan started: {target}")
        return True, f"Scan started: {target}"

    def _run_scan(self, target, args):
        """Run nmap and parse output."""
        try:
            cmd = ["nmap"] + args + ["-oX", "-", target]
            self._proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )

            stdout, stderr = self._proc.communicate(timeout=600)

            with self.lock:
                self.raw_output = stdout
                self.results = self._parse_xml(stdout)
                self.running = False

            self._log("info", f"Nmap scan complete: {len(self.results.get('hosts', []))} host(s)")

        except subprocess.TimeoutExpired:
            if self._proc:
                self._proc.kill()
            self._log("error", "Nmap scan timed out (10 min limit)")
            with self.lock:
                self.running = False
                self.results = {"error": "Scan timed out"}
        except FileNotFoundError:
            self._log("error", "nmap not found. Install with: sudo apt install nmap")
            with self.lock:
                self.running = False
                self.results = {"error": "nmap not installed"}
        except Exception as e:
            self._log("error", f"Nmap error: {e}")
            with self.lock:
                self.running = False
                self.results = {"error": str(e)}
        finally:
            self._proc = None

    def _parse_xml(self, xml_str: str) -> dict:
        """Parse nmap XML output into structured data."""
        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError:
            return {"hosts": [], "raw": xml_str[:2000]}

        hosts = []
        for host_el in root.findall(".//host"):
            host = {
                "status": host_el.find("status").get("state", "unknown") if host_el.find("status") is not None else "unknown",
                "addresses": [],
                "hostnames": [],
                "ports": [],
                "os": [],
            }

            for addr in host_el.findall("address"):
                host["addresses"].append({
                    "addr": addr.get("addr"),
                    "type": addr.get("addrtype"),
                })

            for hostname in host_el.findall(".//hostname"):
                host["hostnames"].append(hostname.get("name"))

            for port in host_el.findall(".//port"):
                port_info = {
                    "port": port.get("portid"),
                    "protocol": port.get("protocol"),
                    "state": "",
                    "service": "",
                    "version": "",
                }
                state = port.find("state")
                if state is not None:
                    port_info["state"] = state.get("state", "")
                service = port.find("service")
                if service is not None:
                    port_info["service"] = service.get("name", "")
                    product = service.get("product", "")
                    version = service.get("version", "")
                    port_info["version"] = f"{product} {version}".strip()
                host["ports"].append(port_info)

            for osmatch in host_el.findall(".//osmatch"):
                host["os"].append({
                    "name": osmatch.get("name"),
                    "accuracy": osmatch.get("accuracy"),
                })

            hosts.append(host)

        return {"hosts": hosts}

    def stop(self):
        """Stop a running nmap scan."""
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
        self._log("info", "Nmap scan stopped")

    def get_results(self) -> dict:
        """Return scan results."""
        with self.lock:
            return {
                "running": self.running,
                "results": self.results,
            }
