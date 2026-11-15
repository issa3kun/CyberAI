"""Passive FTP greeting and SSH handshake checks; no authentication or file operations."""
import re
import socket
from time import monotonic
from urllib.parse import urlsplit

import paramiko

from scanner.domain_checks import UnsafeTargetError, resolve_public_addresses


def _public_socket(host, port, addresses):
    """Pin the socket to a DNS-validated public IP; no second DNS lookup."""
    ips = addresses if addresses is not None else resolve_public_addresses(host, port)
    last = None
    for ip in ips[:3]:
        try:
            return socket.create_connection((ip, port), timeout=5)
        except OSError as exc:
            last = exc
    raise OSError("Could not connect to the remote service") from last


def _ftp_greeting_code(sock):
    """Read a bounded FTP greeting, including a complete multiline reply."""
    deadline = monotonic() + 5
    remaining_bytes = 512
    pending = b""
    multiline_code = None
    while remaining_bytes:
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise TimeoutError("FTP greeting timed out")
        sock.settimeout(remaining)
        chunk = sock.recv(min(128, remaining_bytes))
        if not chunk:
            return None
        remaining_bytes -= len(chunk)
        pending += chunk
        while b"\n" in pending:
            line, pending = pending.split(b"\n", 1)
            if multiline_code is not None:
                if line.startswith(multiline_code + b" "):
                    return multiline_code.decode("ascii")
                continue
            reply = re.match(rb"^(120|220|421)([ -])", line)
            if not reply:
                return None
            if reply[2] == b" ":
                return reply[1].decode("ascii")
            multiline_code = reply[1]
    return None


def inspect_transfer(url, *, addresses=None):
    """Inspect the service associated with an ftp:// or sftp:// URL."""
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    if scheme not in ("ftp", "sftp"):
        raise ValueError("Unsupported transfer protocol")
    port = 21 if scheme == "ftp" else 22
    result = {
        "url": url,
        "protocol": scheme,
        "checks": {"service_response": {
            "connection_completed": False,
            "protocol_handshake_verified": False,
            "authentication_attempted": False,
            "path_checked": False,
            "server_key_verified": None,
            "sftp_subsystem_verified": None,
            "port": port,
        }},
        "findings": [],
        "preliminary_assessment": {
            "risk_level": "Not enough information",
            "reason": "The service has not been verified.",
        },
    }
    live = result["checks"]["service_response"]
    findings = result["findings"]
    if scheme == "ftp":
        live.update({"greeting_code": None, "ftp_ready": None})
        findings.append({
            "id": "ftp_cleartext_protocol",
            "category": "Transport Security",
            "severity": "medium",
            "evidence": "Plain FTP does not encrypt its protocol traffic; FTPS is not assessed.",
            "limitation": "This alone does not establish the purpose or sensitivity of any files.",
        })
    try:
        with _public_socket(parsed.hostname, port, addresses) as sock:
            live["connection_completed"] = True
            sock.settimeout(5)
            if scheme == "ftp":
                greeting_code = _ftp_greeting_code(sock)
                greeting_ok = greeting_code is not None
                live["protocol_handshake_verified"] = greeting_ok
                live["greeting_code"] = greeting_code
                live["ftp_ready"] = {"120": False, "220": True, "421": False}.get(greeting_code)
                result["preliminary_assessment"] = {
                    "risk_level": "Medium" if greeting_ok else "Not enough information",
                    "reason": "An FTP greeting was received. Plain FTP is unencrypted." if greeting_ok else "A connection was opened, but an FTP greeting was not confirmed.",
                }
            else:
                transport = paramiko.Transport(sock)
                try:
                    transport.banner_timeout = 5
                    transport.start_client(timeout=5)
                    if not transport.is_active():
                        raise paramiko.SSHException("SSH handshake not active")
                    key = transport.get_remote_server_key()
                    live["protocol_handshake_verified"] = True
                    live["ssh_host_key_algorithm"] = key.get_name()
                    # No known_hosts reference has been supplied; do not claim trust.
                    live["server_key_verified"] = None  # Not checked against a trusted key
                    findings.append({
                        "id": "ssh_host_key_not_authenticated",
                        "category": "Identity Verification",
                        "severity": "info",
                        "evidence": "SSH handshake succeeded, but the host key was not matched against a trusted reference.",
                    })
                    result["preliminary_assessment"] = {
                        "risk_level": "Not enough information",
                        "reason": "SSH negotiation succeeded, but host identity and the SFTP subsystem were not verified.",
                    }
                finally:
                    transport.close()
    except (OSError, EOFError, UnsafeTargetError, paramiko.SSHException):
        # Keep connection exception details out of the public API.
        findings.append({
            "id": "service_handshake_unconfirmed",
            "category": "Connection",
            "severity": "info",
            "evidence": "The service greeting or handshake could not be completed.",
        })
    return result
