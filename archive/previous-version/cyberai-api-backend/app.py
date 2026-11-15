from urllib.parse import urlsplit
import ipaddress
import re

from flask import Flask, request, jsonify

from scanner.domain_checks import inspect_domain
from scanner.protocol_checks import inspect_transfer
from scanner.url_checks import inspect_url

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
STANDARD_PORTS = {"http": 80, "https": 443, "ftp": 21, "sftp": 22}
HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.IGNORECASE)


def _parse_scan_target(url, *, domain_only=False):
    """Validate URL syntax without contacting the resolver or target."""
    if not isinstance(url, str) or not url.strip():
        raise ValueError("Please provide a URL.")

    url = url.strip()
    if len(url) > 2048 or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in url):
        raise ValueError("The URL is too long or contains whitespace/control characters.")

    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Please provide a valid URL and port.") from exc

    if parsed.scheme not in STANDARD_PORTS:
        raise ValueError("Supported schemes: HTTP, HTTPS, FTP, and SFTP.")
    if not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise ValueError("Please provide a complete URL without login credentials.")
    if not re.fullmatch(r"(?:\[[^\]]+\]|[^:\[\]]+)(?::[0-9]+)?", parsed.netloc):
        raise ValueError("Please provide a valid hostname and port.")

    hostname = parsed.hostname.removesuffix(".")
    if not hostname or "%" in hostname:
        raise ValueError("Please provide a valid hostname or IP address.")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        if parsed.netloc.startswith("["):
            raise ValueError("Brackets are reserved for IPv6 addresses.")
        try:
            ascii_hostname = hostname.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError("Please provide a valid hostname or IP address.") from exc
        if len(ascii_hostname) > 253 or not all(HOST_LABEL.fullmatch(label) for label in ascii_hostname.split(".")):
            raise ValueError("Please provide a valid hostname or IP address.")

    expected_port = STANDARD_PORTS[parsed.scheme]
    if not domain_only and port not in (None, expected_port):
        raise ValueError(f"Only the standard port {expected_port} is allowed for {parsed.scheme.upper()}.")
    if not domain_only and parsed.scheme in ("ftp", "sftp") and (parsed.query or parsed.fragment):
        raise ValueError("FTP/SFTP URLs may contain a path, but omit the query and fragment.")
    return parsed, expected_port


def validate_url(url):
    """Keep the existing (valid, error) return format for other callers."""
    try:
        parsed, port = _parse_scan_target(url)
    except ValueError as exc:
        return False, str(exc)
    domain = inspect_domain(parsed.hostname, port)
    if domain["status"] != "public_address":
        return False, domain["message"]
    return True, None


@app.post("/api/domain-check")
def domain_check():
    """Look up a bare hostname, IP address, or supported URL without scanning."""
    data = request.get_json(silent=True)
    target = data.get("target") if isinstance(data, dict) else None
    if not isinstance(target, str) or not target.strip():
        return jsonify({"error": "Send a JSON object with a 'target' hostname, IP address, or URL."}), 400

    target = target.strip()
    if "://" not in target:
        if any(char in target for char in "/?#@"):
            return jsonify({"error": "Enter a hostname, IP address, or complete URL."}), 400
        try:
            literal = ipaddress.ip_address(target)
        except ValueError:
            pass
        else:
            if literal.version == 6:
                target = f"[{target}]"
        target = "https://" + target

    try:
        parsed, port = _parse_scan_target(target, domain_only=True)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(inspect_domain(parsed.hostname, port))


@app.route("/api/health", methods=["GET"])
def health():
    """Confirm that the backend is running."""

    return jsonify({
        "status": "running",
        "service": "CyberAI Backend"
    }), 200


@app.route("/api/scan", methods=["POST"])
def scan_url():
    """Inspect a URL and separate lookup results from service or page evidence."""
    data = request.get_json(silent=True)
    url = data.get("url") if isinstance(data, dict) else None

    try:
        parsed, port = _parse_scan_target(url)
    except ValueError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400

    scheme = parsed.scheme
    legacy_web_response = scheme in ("http", "https") and request.args.get("details") != "1"
    domain = inspect_domain(parsed.hostname, port)
    if domain["status"] != "public_address":
        error = {
            "success": False,
            "error": domain["message"],
        }
        if not legacy_web_response:
            error["checks"] = {"domain": domain}
        return jsonify(error), 400

    if scheme in ("http", "https"):
        result = inspect_url(url.strip(), addresses=domain["addresses"])
        if legacy_web_response:
            # Keep the original HTTP/HTTPS response contract for the risk engine.
            return jsonify({
                "success": True,
                "scan_type": "Surface-level checks",
                "status": "URL validated",
                **result,
            }), 200

        live = result["checks"]["live_response"]
        website_responded = live["request_completed"]
        service_responded = None
        status_code = live["http_status_code"]
        page_accessible = status_code is not None and 200 <= status_code < 300
        status = "HTTP response received" if website_responded else "No HTTP response received"
        if page_accessible:
            resource_status = "http_success"
        elif status_code in (404, 410):
            resource_status = "http_not_found"
        elif live["redirect_detected"]:
            resource_status = "http_redirect"
        elif website_responded:
            resource_status = "http_other_response"
        else:
            resource_status = "no_http_response"
        success = website_responded
    else:
        result = inspect_transfer(url.strip(), addresses=domain["addresses"])
        live = result["checks"]["service_response"]
        website_responded = page_accessible = None
        service_responded = live["protocol_handshake_verified"]
        resource_status = "path_not_checked"
        if scheme == "ftp":
            status = {
                "220": "FTP service reported ready",
                "120": "FTP service reported it would be ready later",
                "421": "FTP service reported unavailable",
            }.get(live["greeting_code"], "FTP greeting not confirmed")
        else:
            status = (
                "SSH handshake completed (SFTP availability unverified)"
                if service_responded else "SSH handshake not confirmed"
            )
        success = service_responded

    result["checks"]["domain"] = domain
    return jsonify({
        "success": success,
        "scan_type": "Surface-level checks",
        "status": status,
        "protocol": scheme,
        "website_responded": website_responded,
        "service_responded": service_responded,
        "page_accessible": page_accessible,
        "resource_status": resource_status,
        **result,
    }), 200


if __name__ == "__main__":
    app.run()
