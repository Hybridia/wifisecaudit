"""
Dual interface manager — uses two WiFi adapters simultaneously.
Primary: capture (stays on channel, never leaves)
Secondary: injection (deauth, probes)
"""

import os
import re
import subprocess
import threading


class DualInterface:
    """Manage two WiFi adapters for simultaneous capture + injection."""

    # Drivers known to work well in monitor/injection mode
    PREFERRED_DRIVERS = ["ath9k", "ath9k_htc", "rt2800usb", "carl9170", "rtl8812au", "rtl88xxau"]

    def __init__(self, log_fn=None):
        self.log_fn = log_fn
        self.primary = None       # capture interface
        self.secondary = None     # injection interface
        self.primary_mon = None   # monitor mode name for primary
        self.secondary_mon = None # monitor mode name for secondary
        self.enabled = False
        self.lock = threading.Lock()

    def _log(self, level, message):
        if self.log_fn:
            self.log_fn(level, f"[dual] {message}")

    def detect_interfaces(self) -> list:
        """Detect all WiFi interfaces with their capabilities."""
        interfaces = []
        try:
            result = subprocess.run(
                ["iw", "dev"], capture_output=True, text=True, timeout=5
            )
            current_iface = None
            current_phy = None
            for line in result.stdout.split("\n"):
                line = line.strip()
                if line.startswith("phy#"):
                    current_phy = line
                elif line.startswith("Interface"):
                    current_iface = line.split()[1]
                elif "type" in line and current_iface:
                    iface_type = line.split()[-1]
                    driver = self._get_driver(current_iface)
                    interfaces.append({
                        "name": current_iface,
                        "phy": current_phy,
                        "type": iface_type,
                        "driver": driver,
                        "preferred": driver in self.PREFERRED_DRIVERS,
                    })
                    current_iface = None
        except Exception as e:
            self._log("error", f"Interface detection failed: {e}")

        return interfaces

    def _get_driver(self, iface: str) -> str:
        """Get the driver name for an interface."""
        try:
            result = subprocess.run(
                ["ethtool", "-i", iface],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split("\n"):
                if line.startswith("driver:"):
                    return line.split(":", 1)[1].strip()
        except Exception:
            pass
        # Fallback: check /sys
        try:
            driver_path = f"/sys/class/net/{iface}/device/driver"
            if os.path.islink(driver_path):
                return os.path.basename(os.readlink(driver_path))
        except Exception:
            pass
        return "unknown"

    def auto_assign(self) -> tuple:
        """
        Auto-detect and assign primary (capture) and secondary (injection) interfaces.
        Returns (success, message).
        """
        interfaces = self.detect_interfaces()
        wifi_ifaces = [i for i in interfaces if i["type"] in ("managed", "monitor")]

        if len(wifi_ifaces) < 2:
            return False, f"Need 2 WiFi adapters, found {len(wifi_ifaces)}"

        # Ensure they're on different physical devices
        phys = set()
        candidates = []
        for iface in wifi_ifaces:
            if iface["phy"] not in phys:
                phys.add(iface["phy"])
                candidates.append(iface)

        if len(candidates) < 2:
            # Allow same phy as fallback but warn
            candidates = wifi_ifaces[:2]
            self._log("warning", "Both interfaces share same physical device — may have limitations")

        # Prefer known-good drivers for injection (secondary)
        candidates.sort(key=lambda i: (i["preferred"], i["name"]), reverse=True)

        with self.lock:
            self.primary = candidates[0]["name"]
            self.secondary = candidates[1]["name"] if len(candidates) > 1 else None
            self.enabled = self.secondary is not None

        if self.enabled:
            self._log("info", f"Dual interface: primary={self.primary} (capture), secondary={self.secondary} (injection)")
            return True, f"Primary: {self.primary}, Secondary: {self.secondary}"
        return False, "Could not assign dual interfaces"

    def assign(self, primary: str, secondary: str) -> tuple:
        """Manually assign interfaces. Returns (success, message)."""
        if primary == secondary:
            return False, "Primary and secondary must be different interfaces"

        with self.lock:
            self.primary = primary
            self.secondary = secondary
            self.enabled = True

        self._log("info", f"Dual interface assigned: primary={primary}, secondary={secondary}")
        return True, f"Primary: {primary}, Secondary: {secondary}"

    def enable_monitor_both(self) -> tuple:
        """Put both interfaces into monitor mode. Returns (success, message)."""
        if not self.enabled:
            return False, "Dual interface not configured"

        results = []
        for iface, role in [(self.primary, "primary"), (self.secondary, "secondary")]:
            try:
                # Kill interfering processes (only once)
                if role == "primary":
                    subprocess.run(["airmon-ng", "check", "kill"],
                                   capture_output=True, timeout=10)

                result = subprocess.run(
                    ["airmon-ng", "start", iface],
                    capture_output=True, text=True, timeout=10
                )

                mon_iface = iface + "mon"
                if mon_iface in result.stdout:
                    if role == "primary":
                        self.primary_mon = mon_iface
                    else:
                        self.secondary_mon = mon_iface
                    results.append(f"{role}: {mon_iface}")
                else:
                    if role == "primary":
                        self.primary_mon = iface
                    else:
                        self.secondary_mon = iface
                    results.append(f"{role}: {iface}")

            except FileNotFoundError:
                # Fallback to iw
                subprocess.run(["ip", "link", "set", iface, "down"],
                               capture_output=True, timeout=5)
                subprocess.run(["iw", "dev", iface, "set", "type", "monitor"],
                               capture_output=True, timeout=5)
                subprocess.run(["ip", "link", "set", iface, "up"],
                               capture_output=True, timeout=5)
                if role == "primary":
                    self.primary_mon = iface
                else:
                    self.secondary_mon = iface
                results.append(f"{role}: {iface}")

        self._log("info", f"Monitor mode enabled: {', '.join(results)}")
        return True, "; ".join(results)

    def disable_monitor_both(self) -> tuple:
        """Restore both interfaces to managed mode."""
        for iface in [self.primary_mon or self.primary, self.secondary_mon or self.secondary]:
            if not iface:
                continue
            try:
                subprocess.run(["airmon-ng", "stop", iface],
                               capture_output=True, timeout=10)
            except FileNotFoundError:
                subprocess.run(["ip", "link", "set", iface, "down"],
                               capture_output=True, timeout=5)
                subprocess.run(["iw", "dev", iface, "set", "type", "managed"],
                               capture_output=True, timeout=5)
                subprocess.run(["ip", "link", "set", iface, "up"],
                               capture_output=True, timeout=5)

        subprocess.run(["systemctl", "start", "NetworkManager"],
                       capture_output=True, timeout=10)

        self.primary_mon = None
        self.secondary_mon = None
        self._log("info", "Monitor mode disabled on both interfaces")
        return True, "Both interfaces restored to managed mode"

    def get_capture_interface(self) -> str:
        """Return the interface to use for packet capture."""
        return self.primary_mon or self.primary

    def get_injection_interface(self) -> str:
        """Return the interface to use for injection (deauth)."""
        return self.secondary_mon or self.secondary

    def get_status(self) -> dict:
        """Return current dual interface status."""
        with self.lock:
            return {
                "enabled": self.enabled,
                "primary": self.primary,
                "secondary": self.secondary,
                "primary_mon": self.primary_mon,
                "secondary_mon": self.secondary_mon,
                "interfaces": self.detect_interfaces(),
            }
