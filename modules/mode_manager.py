"""
Central adapter mode controller.
Wraps PMKIDCapture monitor mode methods and serializes mode transitions.
"""

import enum
import subprocess
import threading


class AdapterMode(enum.Enum):
    MANAGED = "managed"
    MONITOR = "monitor"
    AP = "ap"


class ModeManager:
    """Manages WiFi adapter mode transitions safely."""

    def __init__(self, interface="wlan0", pmkid=None):
        self.interface = interface
        self.pmkid = pmkid
        self._mode = AdapterMode.MANAGED
        self._lock = threading.Lock()
        self._original_mac = None

        # Detect current mode from pmkid state
        if pmkid and pmkid.monitor_mode_active:
            self._mode = AdapterMode.MONITOR

    def get_mode(self) -> AdapterMode:
        """Return current adapter mode."""
        # Sync with pmkid state
        if self.pmkid and self.pmkid.monitor_mode_active:
            self._mode = AdapterMode.MONITOR
        return self._mode

    def _stop_all_pmkid_operations(self):
        """Stop all running pmkid operations before mode change."""
        if not self.pmkid:
            return
        if self.pmkid.sniffer_active:
            self.pmkid.stop_sniffer()
        if self.pmkid.deauth_running:
            self.pmkid.stop_deauth()
        if self.pmkid.scanning:
            self.pmkid.stop_scan()
        if self.pmkid.client_scanning:
            self.pmkid.stop_client_scan()
        if self.pmkid.running:
            self.pmkid.stop_capture()

    def transition_to(self, target: AdapterMode) -> tuple:
        """
        Transition adapter to target mode.
        Returns (success, message).
        """
        with self._lock:
            current = self.get_mode()
            if current == target:
                return True, f"Already in {target.value} mode"

            # Stop all operations before switching
            self._stop_all_pmkid_operations()

            iface = self.pmkid.monitor_interface or self.interface if self.pmkid else self.interface

            if target == AdapterMode.MONITOR:
                if self.pmkid:
                    success, msg = self.pmkid.enable_monitor_mode(self.interface)
                    if success:
                        self._mode = AdapterMode.MONITOR
                    return success, msg
                return False, "No pmkid instance for monitor mode"

            elif target == AdapterMode.MANAGED:
                if current == AdapterMode.MONITOR and self.pmkid:
                    success, msg = self.pmkid.disable_monitor_mode(iface)
                    if success:
                        self._mode = AdapterMode.MANAGED
                    return success, msg
                elif current == AdapterMode.AP:
                    # AP cleanup is handled by evil_twin.stop()
                    self._mode = AdapterMode.MANAGED
                    self._restart_network_manager()
                    return True, "Switched to managed mode"
                self._mode = AdapterMode.MANAGED
                return True, "Already in managed mode"

            elif target == AdapterMode.AP:
                # First go to managed if in monitor
                if current == AdapterMode.MONITOR and self.pmkid:
                    self.pmkid.disable_monitor_mode(iface)

                self._stop_network_manager()
                self._mode = AdapterMode.AP
                return True, "Switched to AP mode"

        return False, "Unknown target mode"

    def _stop_network_manager(self):
        """Stop NetworkManager."""
        try:
            subprocess.run(
                ["systemctl", "stop", "NetworkManager"],
                capture_output=True, timeout=10
            )
        except Exception:
            pass

    def _restart_network_manager(self):
        """Restart NetworkManager."""
        try:
            subprocess.run(
                ["systemctl", "start", "NetworkManager"],
                capture_output=True, timeout=10
            )
        except Exception:
            pass

    def reset_interface(self) -> tuple:
        """
        Full interface reset: bring down, reload driver, bring up.
        Fixes broken adapter state after hostapd/evil twin usage.
        Returns (success, message).
        """
        import time

        self._stop_all_pmkid_operations()
        iface = self.interface

        try:
            # Bring interface down
            subprocess.run(["ip", "link", "set", iface, "down"],
                           capture_output=True, timeout=5)
            subprocess.run(["iw", "dev", iface, "set", "type", "managed"],
                           capture_output=True, timeout=5)

            # Try to reload the driver
            result = subprocess.run(
                ["ethtool", "-i", iface],
                capture_output=True, text=True, timeout=5
            )
            driver = None
            for line in result.stdout.split("\n"):
                if line.startswith("driver:"):
                    driver = line.split(":", 1)[1].strip()
                    break

            if driver:
                subprocess.run(["rmmod", driver], capture_output=True, timeout=10)
                time.sleep(1)
                subprocess.run(["modprobe", driver], capture_output=True, timeout=10)
                time.sleep(2)

            # Bring interface back up
            subprocess.run(["ip", "link", "set", iface, "up"],
                           capture_output=True, timeout=5)

            # Restart NetworkManager
            subprocess.run(["systemctl", "restart", "NetworkManager"],
                           capture_output=True, timeout=10)
            time.sleep(2)

            # Reset pmkid state
            if self.pmkid:
                self.pmkid.monitor_mode_active = False
                self.pmkid.monitor_interface = None
            self._mode = AdapterMode.MANAGED

            return True, f"Interface {iface} reset successfully" + (f" (driver: {driver})" if driver else "")
        except Exception as e:
            # Try to bring interface back up no matter what
            subprocess.run(["ip", "link", "set", iface, "up"],
                           capture_output=True, timeout=5)
            return False, f"Reset failed: {e}"

    def set_mac(self, mac=None, randomize=False) -> tuple:
        """Change MAC address. Delegates to MacSpoofer if available."""
        # This is a convenience method; actual MAC changing is in mac_spoofer.py
        return False, "Use MacSpoofer module directly"
