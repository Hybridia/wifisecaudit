"""
Aircrack-ng subprocess wrapper for cracking WPA/WPA2 handshakes.
"""

import os
import re
import glob
import signal
import threading
import subprocess
from datetime import datetime


class AircrackRunner:
    """Runs aircrack-ng against captured .cap files with a wordlist."""

    def __init__(self, data_dir="data", log_fn=None):
        self.data_dir = data_dir
        self.log_fn = log_fn
        self.process = None
        self.running = False
        self.result = None  # None = not started, "cracking" = in progress, or the found key
        self.progress_line = ""
        self.lock = threading.Lock()
        self._thread = None

    def _log(self, level, message):
        if self.log_fn:
            self.log_fn(level, f"[aircrack] {message}")

    def crack(self, cap_file: str, wordlist: str) -> None:
        """Start cracking in a daemon thread."""
        with self.lock:
            if self.running:
                return
            self.running = True
            self.result = None
            self.progress_line = ""

        # Validate files exist
        if not os.path.isfile(cap_file):
            self._log("error", f"Cap file not found: {cap_file}")
            with self.lock:
                self.running = False
                self.result = "error: cap file not found"
            return

        if not os.path.isfile(wordlist):
            self._log("error", f"Wordlist not found: {wordlist}")
            with self.lock:
                self.running = False
                self.result = "error: wordlist not found"
            return

        self._log("info", f"Starting aircrack-ng: {os.path.basename(cap_file)} with {os.path.basename(wordlist)}")

        self._thread = threading.Thread(
            target=self._run_aircrack, args=(cap_file, wordlist), daemon=True
        )
        self._thread.start()

    def _run_aircrack(self, cap_file: str, wordlist: str):
        """Run aircrack-ng subprocess and parse output."""
        try:
            self.process = subprocess.Popen(
                ["aircrack-ng", "-w", wordlist, "-l", "/dev/stdout", cap_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )

            for line in self.process.stdout:
                line = line.strip()
                if not line:
                    continue

                self._parse_output(line)

                if not self.running:
                    break

            self.process.wait()

            with self.lock:
                if self.result is None:
                    # No key found
                    self.result = "exhausted"
                    self._log("warning", "Wordlist exhausted — key not found")
                self.running = False
                self.process = None

        except FileNotFoundError:
            self._log("error", "aircrack-ng not found. Install with: sudo apt install aircrack-ng")
            with self.lock:
                self.running = False
                self.result = "error: aircrack-ng not installed"
                self.process = None
        except Exception as e:
            self._log("error", f"Aircrack error: {e}")
            with self.lock:
                self.running = False
                self.result = f"error: {e}"
                self.process = None

    def _parse_output(self, line: str):
        """Parse aircrack-ng output for progress and key."""
        # KEY FOUND! [ password123 ]
        key_match = re.search(r"KEY FOUND!\s*\[\s*(.+?)\s*\]", line)
        if key_match:
            key = key_match.group(1)
            with self.lock:
                self.result = key
                self.running = False
            self._log("info", f"KEY FOUND: {key}")
            return

        # Progress line: e.g. "123456/1000000 keys tested (12.35%)"
        progress_match = re.search(r"(\d+/\d+\s+keys\s+tested.*)", line)
        if progress_match:
            with self.lock:
                self.progress_line = progress_match.group(1)
            return

        # Current passphrase line
        passphrase_match = re.search(r"Current passphrase:\s*(.+)", line)
        if passphrase_match:
            with self.lock:
                self.progress_line = f"Testing: {passphrase_match.group(1).strip()}"

    def stop(self):
        """Kill the aircrack-ng subprocess."""
        # Grab the process reference under lock, then release before waiting
        with self.lock:
            self.running = False
            proc = self.process

        if proc:
            try:
                proc.kill()  # SIGKILL — immediate, no deadlock risk
                proc.wait(timeout=5)
            except Exception:
                pass

            with self.lock:
                self.process = None
                if self.result is None:
                    self.result = "stopped"

        self._log("info", "Aircrack-ng stopped")

    def get_status(self) -> dict:
        """Return current cracking status."""
        with self.lock:
            return {
                "running": self.running,
                "progress": self.progress_line,
                "result": self.result,
            }

    def list_cap_files(self) -> list:
        """Scan data directory for .cap and .hc22000 files."""
        files = []
        patterns = [
            os.path.join(self.data_dir, "*.cap"),
            os.path.join(self.data_dir, "*.pcap"),
            os.path.join(self.data_dir, "*.pcapng"),
            os.path.join(self.data_dir, "*.hc22000"),
            os.path.join(self.data_dir, "*.22000"),
        ]
        for pattern in patterns:
            for path in glob.glob(pattern):
                try:
                    stat = os.stat(path)
                    files.append({
                        "name": os.path.basename(path),
                        "path": path,
                        "size": stat.st_size,
                        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    })
                except OSError:
                    continue
        files.sort(key=lambda f: f["modified"], reverse=True)
        return files
