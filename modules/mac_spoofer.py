"""
MAC address spoofing module using macchanger.
"""

import re
import subprocess
from modules.mode_manager import AdapterMode


class MacSpoofer:
    """Change/restore MAC address on the WiFi adapter."""

    def __init__(self, mode_manager, log_fn=None):
        self.mode_manager = mode_manager
        self.log_fn = log_fn
        self._original_mac = None
        self._current_mac = None

    def _log(self, level, message):
        if self.log_fn:
            self.log_fn(level, f"[mac] {message}")

    def _get_mac_from_ip(self, interface: str) -> str:
        """Read current MAC via ip link."""
        try:
            result = subprocess.run(
                ["ip", "link", "show", interface],
                capture_output=True, text=True, timeout=5
            )
            match = re.search(r"link/ether\s+([0-9a-f:]{17})", result.stdout, re.I)
            if match:
                return match.group(1)
        except Exception:
            pass
        return "unknown"

    def get_current_mac(self) -> str:
        """Return current MAC address."""
        iface = self.mode_manager.interface
        mac = self._get_mac_from_ip(iface)
        self._current_mac = mac
        return mac

    def change_mac(self, mac=None, randomize=False, clone_from=None) -> tuple:
        """
        Change MAC address.
        - mac: specific MAC to set
        - randomize: use macchanger -r
        - clone_from: MAC to clone
        Returns (success, message).
        """
        iface = self.mode_manager.interface
        previous_mode = self.mode_manager.get_mode()

        # Save original MAC on first call
        if self._original_mac is None:
            self._original_mac = self._get_mac_from_ip(iface)
            self._log("info", f"Saved original MAC: {self._original_mac}")

        # Must be in managed mode with interface down
        if previous_mode == AdapterMode.MONITOR:
            success, msg = self.mode_manager.transition_to(AdapterMode.MANAGED)
            if not success:
                return False, f"Failed to switch to managed mode: {msg}"

        try:
            # Bring interface down
            subprocess.run(
                ["ip", "link", "set", iface, "down"],
                capture_output=True, timeout=5, check=True
            )

            # Change MAC
            if randomize:
                result = subprocess.run(
                    ["macchanger", "-r", iface],
                    capture_output=True, text=True, timeout=10
                )
            elif clone_from:
                result = subprocess.run(
                    ["macchanger", "-m", clone_from, iface],
                    capture_output=True, text=True, timeout=10
                )
            elif mac:
                result = subprocess.run(
                    ["macchanger", "-m", mac, iface],
                    capture_output=True, text=True, timeout=10
                )
            else:
                result = subprocess.run(
                    ["macchanger", "-r", iface],
                    capture_output=True, text=True, timeout=10
                )

            # Bring interface back up
            subprocess.run(
                ["ip", "link", "set", iface, "up"],
                capture_output=True, timeout=5
            )

            # Parse new MAC from macchanger output
            new_mac_match = re.search(r"New MAC:\s+([0-9a-f:]{17})", result.stdout, re.I)
            new_mac = new_mac_match.group(1) if new_mac_match else self._get_mac_from_ip(iface)
            self._current_mac = new_mac

            # Restore previous mode if needed
            if previous_mode == AdapterMode.MONITOR:
                self.mode_manager.transition_to(AdapterMode.MONITOR)

            self._log("info", f"MAC changed to: {new_mac}")
            return True, f"MAC changed to {new_mac}"

        except FileNotFoundError:
            # Bring interface back up
            subprocess.run(["ip", "link", "set", iface, "up"], capture_output=True, timeout=5)
            self._log("error", "macchanger not installed. Install with: sudo apt install macchanger")
            return False, "macchanger not installed"
        except Exception as e:
            # Bring interface back up
            subprocess.run(["ip", "link", "set", iface, "up"], capture_output=True, timeout=5)
            self._log("error", f"MAC change failed: {e}")
            return False, str(e)

    def restore_mac(self) -> tuple:
        """Restore original MAC address."""
        if not self._original_mac or self._original_mac == "unknown":
            return False, "Original MAC not saved"

        iface = self.mode_manager.interface
        previous_mode = self.mode_manager.get_mode()

        if previous_mode == AdapterMode.MONITOR:
            self.mode_manager.transition_to(AdapterMode.MANAGED)

        try:
            subprocess.run(
                ["ip", "link", "set", iface, "down"],
                capture_output=True, timeout=5, check=True
            )
            subprocess.run(
                ["macchanger", "-p", iface],
                capture_output=True, text=True, timeout=10
            )
            subprocess.run(
                ["ip", "link", "set", iface, "up"],
                capture_output=True, timeout=5
            )

            if previous_mode == AdapterMode.MONITOR:
                self.mode_manager.transition_to(AdapterMode.MONITOR)

            self._current_mac = self._original_mac
            self._log("info", f"MAC restored to: {self._original_mac}")
            return True, f"MAC restored to {self._original_mac}"

        except Exception as e:
            subprocess.run(["ip", "link", "set", iface, "up"], capture_output=True, timeout=5)
            self._log("error", f"MAC restore failed: {e}")
            return False, str(e)
