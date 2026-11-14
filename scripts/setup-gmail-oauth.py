#!/usr/bin/env python3
"""Local-only Gmail OAuth bootstrap for CSIRT Incident Intake.

Reads a Google OAuth Desktop client JSON, verifies the authorized Gmail account,
and writes a mode-0600 shell environment outside the git repository.
Never sends OAuth credentials or tokens to ChatGPT.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.server
import json
import os
import re
from pathlib import Path
import secrets
import shlex
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
PORT = 8765
REDIRECT_URI = f"http://127.0.0.1:{PORT}/oauth2callback"
GOOGLE_AUTH = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN = "https://oauth2.googleapis.com/token"
GOOGLE_PROFILE = "https://gmail.googleapis.com/gmail/v1/users/me/profile"
OUT_DIR = Path.home() / ".config" / "csirt-intake"
OUT_FILE = OUT_DIR / "gmail-env.sh"


def request_json(url: str, *, fields: dict[str, str] | None = None, bearer: str | None = None) -> dict:
    headers = {"Accept": "application/json"}
    data = None
    if fields is not None:
        data = urllib.parse.urlencode(fields).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if bearer is not None:
        headers["Authorization"] = f"Bearer {bearer}"
    req = urllib.request.Request(url, data=data, headers=headers, method="POST" if data is not None else "GET")
    try:
        with urllib.request.urlopen(req, timeout=25) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"Google API menolak permintaan (HTTP {exc.code}); periksa OAuth consent/test user/izin Gmail") from None
    except urllib.error.URLError:
        raise RuntimeError("Gagal menghubungi Google API; periksa koneksi internet Kali WSL") from None


def main() -> int:
    parser = argparse.ArgumentParser(description="Hubungkan Gmail ke CSIRT Incident Intake via OAuth read-only")
    parser.add_argument("credentials_json", type=Path, help="Path ke JSON OAuth client bertipe Desktop app dari Google Cloud")
    parser.add_argument("--email", required=True, help="Alamat Gmail CSIRT yang diotorisasi")
    parser.add_argument("--query", default="label:CSIRT", help="Filter Gmail API, default: label:CSIRT")
    parser.add_argument("--mailbox-id", default="csirt-team", help="Namespace kasus untuk mailbox ini")
    args = parser.parse_args()
    account = args.email.strip().lower()
    if not re.fullmatch(r"[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}", account):
        parser.error("--email harus berupa alamat email yang valid")
    if not args.query.strip() or len(args.query) > 512 or any(ord(ch) < 32 for ch in args.query):
        parser.error("--query harus non-kosong, maksimal 512 karakter tanpa control characters")
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._\-]{0,63}", args.mailbox_id):
        parser.error("--mailbox-id harus 1-64 karakter huruf/angka/._-")
    if not args.credentials_json.is_file():
        parser.error(f"File JSON tidak ditemukan: {args.credentials_json}")
    try:
        info = json.loads(args.credentials_json.read_text(encoding="utf-8"))
        client = info["installed"]
        client_id = client["client_id"]
        client_secret = client["client_secret"]
        if not isinstance(client_id, str) or not isinstance(client_secret, str) or not client_id or not client_secret:
            raise ValueError("Invalid desktop client")
    except (json.JSONDecodeError, KeyError, TypeError, ValueError):
        parser.error("JSON tidak valid; download OAuth Client bertipe 'Desktop app' (bukan API key atau Web app)")

    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    expected_state = secrets.token_urlsafe(32)
    received: dict[str, str] = {}

    class Callback(http.server.BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            # Never write OAuth authorization codes into console logs.
            return

        def do_GET(self):
            parsed = urllib.parse.urlsplit(self.path)
            if parsed.path != "/oauth2callback":
                self.send_error(404)
                return
            params = urllib.parse.parse_qs(parsed.query)
            if params.get("state", [""])[0] != expected_state:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Invalid OAuth state. Return to the terminal.")
                received["error"] = "state-mismatch"
                return
            received["code"] = params.get("code", [""])[0]
            received["error"] = params.get("error", [""])[0]
            good = bool(received["code"] and not received["error"])
            self.send_response(200 if good else 400)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            msg = "Authorization captured. You may return to your Kali terminal." if good else "Authorization failed. Return to the Kali terminal."
            self.wfile.write(f"<html><body><h2>{msg}</h2></body></html>".encode("utf-8"))

    try:
        server = http.server.HTTPServer(("127.0.0.1", PORT), Callback)
    except OSError:
        print(f"Port {PORT} sedang digunakan di WSL. Tutup proses lain di port tersebut lalu ulangi.", file=sys.stderr)
        return 1

    params = {
        "client_id": client_id,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": SCOPE,
        "access_type": "offline",
        "prompt": "consent select_account",
        "state": expected_state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    url = GOOGLE_AUTH + "?" + urllib.parse.urlencode(params)
    print("\n1. Buka URL ini di browser Windows dan login sebagai", account)
    print("2. Setujui akses baca Gmail (read-only).\n")
    print(url)
    print("\nBrowser akan mengarah ke 127.0.0.1:8765. Jangan tutup terminal ini.\n")
    with server:
        server.timeout = 2
        deadline = time.monotonic() + 240
        while not received and time.monotonic() < deadline:
            server.handle_request()
    if not received.get("code"):
        print("Otorisasi belum selesai atau ditolak. Pastikan Gmail test user sudah didaftarkan.", file=sys.stderr)
        return 1

    tokens = request_json(GOOGLE_TOKEN, fields={
        "code": received["code"],
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code",
        "code_verifier": verifier,
    })
    access_token = tokens.get("access_token")
    refresh_token = tokens.get("refresh_token")
    if not isinstance(access_token, str) or not isinstance(refresh_token, str) or not refresh_token:
        print("Google tidak memberi access/refresh token. Cabut izin app lalu lakukan OAuth ulang dengan offline access.", file=sys.stderr)
        return 1

    profile = request_json(GOOGLE_PROFILE, bearer=access_token)
    email = str(profile.get("emailAddress", "")).lower()
    if email != account:
        print(f"AKUN SALAH: otorisasi untuk {email!r}; yang dibutuhkan {account}. Tidak ada token disimpan.", file=sys.stderr)
        return 1

    os.umask(0o077)
    OUT_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(OUT_DIR, 0o700)
    variables = {
        "GMAIL_CLIENT_ID": client_id,
        "GMAIL_CLIENT_SECRET": client_secret,
        "GMAIL_REFRESH_TOKEN": refresh_token,
        "GMAIL_MAILBOX_ID": args.mailbox_id,
        "GMAIL_QUERY": args.query.strip(),
    }
    contents = (
        "# Private OAuth config. Do not commit or share. Run: source ~/.config/csirt-intake/gmail-env.sh\n"
        "unset GMAIL_ACCESS_TOKEN GMAIL_API_BASE_URL\n"
        + "".join(f"export {key}={shlex.quote(value)}\n" for key, value in variables.items())
    )
    fd = os.open(OUT_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(contents)
    os.chmod(OUT_FILE, 0o600)
    print(f"\n[OK] Akun Gmail terverifikasi: {email}")
    print(f"[OK] Konfigurasi privat disimpan: {OUT_FILE}")
    print("[OK] Scope: Gmail read-only")
    print("\nJalankan MCP Server:\n")
    print('  cd "$HOME/Kartika Cyber/csirt-skill-hermes"')
    print('  source "$HOME/.config/csirt-intake/gmail-env.sh"')
    print('  HOST=127.0.0.1 INTAKE_DATA_DIR=$HOME/.local/share/csirt-intake/cases npm run dev')
    print("\nPENTING: Jangan jalankan mock Gmail saat pengujian inbox sungguhan.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
