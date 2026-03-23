"""
Wordlist manager — lists system and user-uploaded wordlists, handles uploads.
"""

import os
import gzip
import shutil
from datetime import datetime


class WordlistManager:
    """Manage wordlists for cracking operations."""

    SYSTEM_PATHS = [
        "/usr/share/wordlists/rockyou.txt",
        "/usr/share/wordlists/rockyou.txt.gz",
        "/usr/share/wordlists/fasttrack.txt",
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/wordlists/wifite.txt",
        "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt",
    ]

    def __init__(self, upload_dir="data/wordlists", log_fn=None):
        self.upload_dir = upload_dir
        self.log_fn = log_fn
        os.makedirs(self.upload_dir, exist_ok=True)

    def _log(self, level, message):
        if self.log_fn:
            self.log_fn(level, f"[wordlist] {message}")

    def list_wordlists(self) -> list:
        """Return all available wordlists (system + uploaded)."""
        wordlists = []

        # System wordlists
        for path in self.SYSTEM_PATHS:
            if os.path.isfile(path):
                try:
                    stat = os.stat(path)
                    wordlists.append({
                        "name": os.path.basename(path),
                        "path": path,
                        "size": stat.st_size,
                        "source": "system",
                        "compressed": path.endswith(".gz"),
                    })
                except OSError:
                    continue

        # Also scan /usr/share/wordlists/ for any .txt files not in the list
        wl_dir = "/usr/share/wordlists"
        if os.path.isdir(wl_dir):
            known = {os.path.basename(p) for p in self.SYSTEM_PATHS}
            try:
                for f in os.listdir(wl_dir):
                    full = os.path.join(wl_dir, f)
                    if os.path.isfile(full) and f not in known and (f.endswith(".txt") or f.endswith(".lst")):
                        stat = os.stat(full)
                        wordlists.append({
                            "name": f,
                            "path": full,
                            "size": stat.st_size,
                            "source": "system",
                            "compressed": False,
                        })
            except OSError:
                pass

        # User-uploaded wordlists
        if os.path.isdir(self.upload_dir):
            for f in os.listdir(self.upload_dir):
                full = os.path.join(self.upload_dir, f)
                if os.path.isfile(full):
                    try:
                        stat = os.stat(full)
                        wordlists.append({
                            "name": f,
                            "path": full,
                            "size": stat.st_size,
                            "source": "uploaded",
                            "compressed": f.endswith(".gz"),
                        })
                    except OSError:
                        continue

        return wordlists

    def save_upload(self, filename: str, stream) -> tuple:
        """Save an uploaded wordlist file. Returns (success, message)."""
        # Sanitize filename
        safe_name = os.path.basename(filename)
        if not safe_name:
            return False, "Invalid filename"

        # Only allow text/wordlist files
        allowed_ext = (".txt", ".lst", ".wordlist", ".dict", ".gz")
        if not any(safe_name.endswith(ext) for ext in allowed_ext):
            return False, f"Invalid file type. Allowed: {', '.join(allowed_ext)}"

        dest = os.path.join(self.upload_dir, safe_name)
        try:
            stream.save(dest)
            size = os.path.getsize(dest)
            self._log("info", f"Uploaded wordlist: {safe_name} ({size:,} bytes)")
            return True, f"Saved {safe_name} ({size:,} bytes)"
        except Exception as e:
            return False, f"Upload failed: {e}"

    def delete_wordlist(self, name: str) -> bool:
        """Delete a user-uploaded wordlist (not system ones)."""
        path = os.path.join(self.upload_dir, os.path.basename(name))
        if os.path.isfile(path):
            os.remove(path)
            self._log("info", f"Deleted wordlist: {name}")
            return True
        return False

    def decompress_rockyou(self) -> tuple:
        """Decompress rockyou.txt.gz if it exists. Returns (success, message)."""
        gz_path = "/usr/share/wordlists/rockyou.txt.gz"
        txt_path = "/usr/share/wordlists/rockyou.txt"

        if os.path.isfile(txt_path):
            return True, "rockyou.txt already decompressed"

        if not os.path.isfile(gz_path):
            return False, "rockyou.txt.gz not found"

        try:
            with gzip.open(gz_path, "rb") as f_in:
                with open(txt_path, "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)
            self._log("info", "Decompressed rockyou.txt.gz")
            return True, "rockyou.txt decompressed successfully"
        except Exception as e:
            return False, f"Decompression failed: {e}"
