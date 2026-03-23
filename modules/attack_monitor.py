"""
Attack monitoring / IDS module — detects wireless attacks on your network.
Monitors for deauthentication floods, disassociation attacks, and evil twin APs.
"""

import threading
import time
from datetime import datetime
from collections import defaultdict


class AttackMonitor:
    """Passive wireless attack detector."""

    # Thresholds
    DEAUTH_THRESHOLD = 10      # deauth frames in window = alert
    DEAUTH_WINDOW = 10         # seconds
    EVIL_TWIN_CHECK = 30       # seconds between evil twin checks

    def __init__(self, log_fn=None):
        self.log_fn = log_fn
        self.running = False
        self._thread = None
        self.lock = threading.Lock()

        # Tracked state
        self.alerts = []           # [{timestamp, type, details, severity}]
        self.deauth_counts = defaultdict(list)  # bssid -> [timestamps]
        self.beacon_ssids = defaultdict(set)    # ssid -> set of bssids (evil twin detection)
        self.stats = {
            "deauth_frames": 0,
            "disassoc_frames": 0,
            "suspicious_aps": 0,
            "monitoring_since": None,
        }

    def _log(self, level, message):
        if self.log_fn:
            self.log_fn(level, f"[ids] {message}")

    def start(self, interface) -> tuple:
        """Start monitoring for attacks."""
        if self.running:
            return False, "Already monitoring"

        try:
            from scapy.all import sniff as _
        except ImportError:
            return False, "Scapy not available"

        self.running = True
        self.stats["monitoring_since"] = datetime.now().isoformat()

        self._thread = threading.Thread(
            target=self._monitor_loop, args=(interface,), daemon=True
        )
        self._thread.start()

        self._log("info", f"Attack monitoring started on {interface}")
        return True, "Monitoring started"

    def _monitor_loop(self, interface):
        """Main monitoring loop using scapy."""
        try:
            from scapy.all import sniff, Dot11, Dot11Deauth, Dot11Disas, Dot11Beacon, Dot11Elt

            def process_packet(pkt):
                if not self.running:
                    return

                if not pkt.haslayer(Dot11):
                    return

                # Detect deauthentication frames
                if pkt.haslayer(Dot11Deauth):
                    self._handle_deauth(pkt)

                # Detect disassociation frames
                elif pkt.haslayer(Dot11Disas):
                    self._handle_disassoc(pkt)

                # Track beacons for evil twin detection
                elif pkt.haslayer(Dot11Beacon):
                    self._handle_beacon(pkt)

            sniff(
                iface=interface,
                prn=process_packet,
                store=False,
                monitor=True,
                stop_filter=lambda pkt: not self.running,
            )
        except Exception as e:
            self._log("error", f"Monitor error: {e}")
        finally:
            self.running = False

    def _handle_deauth(self, pkt):
        """Process a deauthentication frame."""
        from scapy.all import Dot11
        now = time.time()

        with self.lock:
            self.stats["deauth_frames"] += 1

            # Track source
            src = pkt[Dot11].addr2 or "unknown"
            dst = pkt[Dot11].addr1 or "unknown"

            self.deauth_counts[src].append(now)

            # Clean old entries outside window
            self.deauth_counts[src] = [
                t for t in self.deauth_counts[src]
                if now - t < self.DEAUTH_WINDOW
            ]

            # Check threshold
            if len(self.deauth_counts[src]) >= self.DEAUTH_THRESHOLD:
                alert = {
                    "timestamp": datetime.now().isoformat(),
                    "type": "deauth_flood",
                    "severity": "high",
                    "details": f"Deauth flood detected from {src} targeting {dst} "
                               f"({len(self.deauth_counts[src])} frames in {self.DEAUTH_WINDOW}s)",
                    "attacker": src,
                    "target": dst,
                }
                # Avoid duplicate alerts for same attacker within 30s
                recent = [a for a in self.alerts
                          if a.get("attacker") == src and a["type"] == "deauth_flood"
                          and (datetime.now() - datetime.fromisoformat(a["timestamp"])).seconds < 30]
                if not recent:
                    self.alerts.append(alert)
                    self._log("warning", alert["details"])
                    # Keep alerts manageable
                    if len(self.alerts) > 200:
                        self.alerts = self.alerts[-200:]

    def _handle_disassoc(self, pkt):
        """Process a disassociation frame."""
        from scapy.all import Dot11
        with self.lock:
            self.stats["disassoc_frames"] += 1

            src = pkt[Dot11].addr2 or "unknown"
            dst = pkt[Dot11].addr1 or "unknown"

            # Disassoc floods are also suspicious
            now = time.time()
            key = f"disassoc_{src}"
            self.deauth_counts[key].append(now)
            self.deauth_counts[key] = [
                t for t in self.deauth_counts[key]
                if now - t < self.DEAUTH_WINDOW
            ]

            if len(self.deauth_counts[key]) >= self.DEAUTH_THRESHOLD:
                alert = {
                    "timestamp": datetime.now().isoformat(),
                    "type": "disassoc_flood",
                    "severity": "high",
                    "details": f"Disassoc flood from {src} targeting {dst}",
                    "attacker": src,
                    "target": dst,
                }
                recent = [a for a in self.alerts
                          if a.get("attacker") == src and a["type"] == "disassoc_flood"
                          and (datetime.now() - datetime.fromisoformat(a["timestamp"])).seconds < 30]
                if not recent:
                    self.alerts.append(alert)
                    self._log("warning", alert["details"])

    def _handle_beacon(self, pkt):
        """Track beacons for evil twin detection."""
        from scapy.all import Dot11, Dot11Elt

        try:
            bssid = pkt[Dot11].addr2
            if not bssid:
                return

            # Extract SSID
            ssid = None
            elt = pkt[Dot11Elt]
            while elt:
                if elt.ID == 0 and elt.info:
                    try:
                        ssid = elt.info.decode("utf-8", errors="ignore")
                    except Exception:
                        pass
                    break
                elt = elt.payload if hasattr(elt, 'payload') and isinstance(elt.payload, type(elt)) else None

            if ssid and ssid.strip():
                with self.lock:
                    self.beacon_ssids[ssid].add(bssid)

                    # Evil twin: same SSID from multiple BSSIDs
                    if len(self.beacon_ssids[ssid]) > 1:
                        bssids = list(self.beacon_ssids[ssid])
                        alert = {
                            "timestamp": datetime.now().isoformat(),
                            "type": "evil_twin",
                            "severity": "critical",
                            "details": f"Possible evil twin: SSID '{ssid}' seen from {len(bssids)} BSSIDs: {', '.join(bssids[:5])}",
                            "ssid": ssid,
                            "bssids": bssids,
                        }
                        # Only alert once per SSID
                        existing = [a for a in self.alerts
                                    if a["type"] == "evil_twin" and a.get("ssid") == ssid]
                        if not existing:
                            self.alerts.append(alert)
                            self.stats["suspicious_aps"] += 1
                            self._log("warning", alert["details"])
        except Exception:
            pass

    def stop(self):
        """Stop monitoring."""
        self.running = False
        self._log("info", "Attack monitoring stopped")

    def get_status(self) -> dict:
        """Return monitoring status and alerts."""
        with self.lock:
            return {
                "running": self.running,
                "stats": dict(self.stats),
                "alerts": list(self.alerts[-50:]),
                "alert_count": len(self.alerts),
            }

    def clear_alerts(self):
        """Clear all alerts."""
        with self.lock:
            self.alerts.clear()
            self.deauth_counts.clear()
            self.beacon_ssids.clear()
            self.stats["deauth_frames"] = 0
            self.stats["disassoc_frames"] = 0
            self.stats["suspicious_aps"] = 0
