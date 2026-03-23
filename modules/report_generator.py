"""
PDF report generator for audit findings using fpdf2.
"""

import os
from datetime import datetime


class ReportGenerator:
    """Generate PDF audit reports."""

    def __init__(self, output_dir="data/reports", log_fn=None):
        self.output_dir = output_dir
        self.log_fn = log_fn
        os.makedirs(self.output_dir, exist_ok=True)

    def _log(self, level, message):
        if self.log_fn:
            self.log_fn(level, f"[report] {message}")

    def generate(self, data: dict) -> tuple:
        """
        Generate a PDF audit report.
        data can contain: networks, handshakes, pmkids, cracked_keys, nmap_results, etc.
        Returns (success, filepath_or_error).
        """
        try:
            from fpdf import FPDF
        except ImportError:
            self._log("error", "fpdf2 not installed. Install with: pip3 install fpdf2")
            return False, "fpdf2 not installed"

        try:
            pdf = FPDF()
            pdf.set_auto_page_break(auto=True, margin=15)
            pdf.add_page()

            # Title
            pdf.set_font("Helvetica", "B", 20)
            pdf.cell(0, 15, "WiFi Security Audit Report", new_x="LMARGIN", new_y="NEXT", align="C")
            pdf.set_font("Helvetica", "", 10)
            pdf.cell(0, 8, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", new_x="LMARGIN", new_y="NEXT", align="C")
            pdf.ln(10)

            # Networks section
            networks = data.get("networks", [])
            if networks:
                pdf.set_font("Helvetica", "B", 14)
                pdf.cell(0, 10, f"Discovered Networks ({len(networks)})", new_x="LMARGIN", new_y="NEXT")
                pdf.ln(2)

                pdf.set_font("Helvetica", "B", 8)
                col_widths = [45, 35, 15, 20, 30, 45]
                headers = ["SSID", "BSSID", "CH", "Signal", "Encryption", "Clients"]
                for i, h in enumerate(headers):
                    pdf.cell(col_widths[i], 7, h, border=1)
                pdf.ln()

                pdf.set_font("Helvetica", "", 8)
                for n in networks:
                    ssid = str(n.get("ssid", ""))[:20]
                    bssid = str(n.get("bssid", ""))
                    ch = str(n.get("channel", ""))
                    sig = str(n.get("signal", ""))
                    enc = str(n.get("encryption", ""))[:15]
                    clients_count = str(len(n.get("clients", [])))
                    pdf.cell(col_widths[0], 6, ssid, border=1)
                    pdf.cell(col_widths[1], 6, bssid, border=1)
                    pdf.cell(col_widths[2], 6, ch, border=1)
                    pdf.cell(col_widths[3], 6, sig, border=1)
                    pdf.cell(col_widths[4], 6, enc, border=1)
                    pdf.cell(col_widths[5], 6, clients_count, border=1)
                    pdf.ln()
                pdf.ln(5)

            # PMKIDs
            pmkids = data.get("pmkids", [])
            if pmkids:
                pdf.set_font("Helvetica", "B", 14)
                pdf.cell(0, 10, f"Captured PMKIDs ({len(pmkids)})", new_x="LMARGIN", new_y="NEXT")
                pdf.ln(2)
                pdf.set_font("Helvetica", "", 8)
                for p in pmkids:
                    pdf.cell(0, 6, f"SSID: {p.get('ssid', '?')} | BSSID: {p.get('bssid', '?')}", new_x="LMARGIN", new_y="NEXT")
                    pdf.set_font("Courier", "", 7)
                    pdf.cell(0, 5, f"PMKID: {p.get('pmkid', '')[:64]}", new_x="LMARGIN", new_y="NEXT")
                    pdf.set_font("Helvetica", "", 8)
                    pdf.ln(2)
                pdf.ln(5)

            # Handshakes
            handshakes = data.get("handshakes", [])
            if handshakes:
                pdf.set_font("Helvetica", "B", 14)
                pdf.cell(0, 10, f"Captured Handshakes ({len(handshakes)})", new_x="LMARGIN", new_y="NEXT")
                pdf.ln(2)
                pdf.set_font("Helvetica", "", 8)
                for h in handshakes:
                    pdf.cell(0, 6, f"SSID: {h.get('ssid', '?')} | BSSID: {h.get('bssid', '?')} | Client: {h.get('mac_client', '?')}", new_x="LMARGIN", new_y="NEXT")
                    pdf.cell(0, 5, f"Messages: {', '.join(str(m) for m in h.get('messages', []))}", new_x="LMARGIN", new_y="NEXT")
                    pdf.ln(2)
                pdf.ln(5)

            # Cracked keys
            cracked = data.get("cracked_keys", [])
            if cracked:
                pdf.set_font("Helvetica", "B", 14)
                pdf.set_text_color(200, 0, 0)
                pdf.cell(0, 10, f"Cracked Keys ({len(cracked)})", new_x="LMARGIN", new_y="NEXT")
                pdf.set_text_color(0, 0, 0)
                pdf.ln(2)
                pdf.set_font("Helvetica", "", 9)
                for c in cracked:
                    pdf.cell(0, 7, f"Network: {c.get('ssid', '?')} | Key: {c.get('key', '?')}", new_x="LMARGIN", new_y="NEXT")
                pdf.ln(5)

            # Nmap results
            nmap = data.get("nmap_results", {})
            hosts = nmap.get("hosts", [])
            if hosts:
                pdf.set_font("Helvetica", "B", 14)
                pdf.cell(0, 10, f"Nmap Scan Results ({len(hosts)} hosts)", new_x="LMARGIN", new_y="NEXT")
                pdf.ln(2)
                pdf.set_font("Helvetica", "", 8)
                for host in hosts:
                    addrs = ", ".join(a.get("addr", "") for a in host.get("addresses", []))
                    pdf.set_font("Helvetica", "B", 9)
                    pdf.cell(0, 7, f"Host: {addrs} ({host.get('status', '')})", new_x="LMARGIN", new_y="NEXT")
                    pdf.set_font("Helvetica", "", 8)
                    for port in host.get("ports", []):
                        pdf.cell(0, 5, f"  {port.get('port')}/{port.get('protocol')} - {port.get('state')} - {port.get('service')} {port.get('version', '')}", new_x="LMARGIN", new_y="NEXT")
                    pdf.ln(3)

            # Footer
            pdf.ln(10)
            pdf.set_font("Helvetica", "I", 8)
            pdf.cell(0, 5, "Generated by WiFi Security Audit Tool", new_x="LMARGIN", new_y="NEXT", align="C")
            pdf.cell(0, 5, "For authorized security testing only.", new_x="LMARGIN", new_y="NEXT", align="C")

            # Save
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"audit_report_{timestamp}.pdf"
            filepath = os.path.join(self.output_dir, filename)
            pdf.output(filepath)

            self._log("info", f"Report generated: {filepath}")
            return True, filepath

        except Exception as e:
            self._log("error", f"Report generation failed: {e}")
            return False, str(e)
