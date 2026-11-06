"""Contains scanner's checking functions."""

from contextlib import contextmanager
from http.client import HTTPConnection, HTTPSConnection, HTTPException
from urllib.parse import quote, urljoin, urlparse, urlsplit, urlunsplit
from http.cookies import SimpleCookie, CookieError
import re
import socket
import ssl

from scanner.domain_checks import UnsafeTargetError, resolve_public_addresses


@contextmanager
def _open_public_response(url, addresses):
    """Send one GET to a validated public IP, preserving the hostname for TLS.

    Pinning the socket to the checked IP avoids a second, unvalidated DNS lookup
    between URL validation and the network connection (DNS rebinding).
    """
    parsed = urlsplit(url)
    hostname = parsed.hostname
    if parsed.scheme not in ("http", "https") or not hostname:
        raise UnsafeTargetError("Only HTTP/HTTPS URLs with a hostname are supported.")

    standard_port = 443 if parsed.scheme == "https" else 80
    if parsed.port not in (None, standard_port):
        raise UnsafeTargetError("Only standard HTTP/HTTPS ports are supported.")
    port = standard_port
    hostname = hostname.removesuffix(".").encode("idna").decode("ascii")
    ips = addresses if addresses is not None else resolve_public_addresses(hostname, port)
    target = quote(urlunsplit(("", "", parsed.path or "/", parsed.query, "")), safe="/%?:@!$&'()*+,;=-._~[]")

    last_error = None
    connection = None
    response = None
    for ip in ips[:3]:  # Limit the number of connection attempts.
        connection = None
        try:
            if parsed.scheme == "https":
                connection = HTTPSConnection(
                    hostname, port=port, timeout=5,
                    context=ssl.create_default_context(),
                )
            else:
                connection = HTTPConnection(hostname, port=port, timeout=5)

            # HTTPConnection / HTTPSConnection uses _create_connection when
            # opening a socket. Replace it for this request with a pinned IP.
            # HTTPS still sends the original hostname as SNI and verifies its
            # certificate against that hostname.
            def connect_to_checked_ip(address, timeout, source_address=None, *, checked_ip=ip):
                return socket.create_connection(
                    (checked_ip, port), timeout=timeout, source_address=source_address
                )

            connection._create_connection = connect_to_checked_ip
            connection.request("GET", target, headers={
                "User-Agent": "CyberAI-Academic-Scanner/0.1",
                "Connection": "close",
            })
            response = connection.getresponse()
            break
        except (OSError, HTTPException) as exc:
            last_error = exc
            if connection is not None:
                connection.close()
            connection = None

    if response is None:
        if last_error is not None:
            raise last_error
        raise UnsafeTargetError("No connection attempt could be made.")

    try:
        yield response
    finally:
        try:
            response.close()
        finally:
            connection.close()


def inspect_url(url, *, addresses=None):
    """Perform basic URL checks."""

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    is_https = parsed.scheme == "https"

    findings = []

    if not is_https:
        findings.append({
            "id": "https_not_used",
            "category": "Transport Security",
            "severity": "info",
            "evidence": "The submitted URL does not use HTTPS.",
            "limitation": (
                "This checks the submitted URL only. "
                "It does not test redirects or server configuration."
            )
        })

    if hostname:
        findings.append({
            "id": "hostname_detected",
            "category": "URL Information",
            "severity": "info",
            "evidence": f"Hostname identified: {hostname}",
        })

    # Perform the additional live website checks
    live_checks = _inspect_live_response(url, findings, addresses)

    # Count the findings
    finding_counts = {
        severity: sum(
            1 for finding in findings
            if finding.get("severity") == severity
        )
        for severity in ["low", "medium", "high", "info"]
    }

    # Generate a preliminary risk indication
    if live_checks["tls_connection_verified"] is False:

        risk_level = "High"

        risk_reason = (
            "The HTTPS connection could not be securely verified. "
            "Manual investigation is recommended."
        )

    elif not is_https:

        risk_level = "Medium"

        risk_reason = (
            "The submitted URL uses HTTP, which does not "
            "provide HTTPS transport encryption."
        )

        if not live_checks["request_completed"]:

            risk_level = "Not enough information"
            risk_reason = (
                "The scanner could not complete the HTTP inspection."
            )
        else:
            risk_reason = (
                "The submitted URL uses HTTP rather than HTTPS."
            )

    elif not live_checks["request_completed"]:

        risk_level = "Not enough information"
        risk_reason = (
            "The scanner could not complete the website inspection."
        )

    elif finding_counts["high"] > 0:

        risk_level = "High"

        risk_reason = (
            "One or more high-severity security issues were detected. Avoid going into website."
        )

    elif finding_counts["medium"] > 0:

        risk_level = "Medium"

        risk_reason = (
            "One or more medium-severity security issues were detected. Avoid giving sensitive information to website."
        )

    elif not 200 <= live_checks["http_status_code"] < 300:
        risk_level = "Not enough information"
        risk_reason = "The requested page did not return a successful HTTP response."

    elif finding_counts["low"] > 0:

        risk_level = "Low"

        risk_reason = (
            "One or more low-severity security issues were detected. Use website with normal browser security precautions."
        )

    else:

        risk_level = "Low"

        risk_reason = (
            "No major issues were detected by the limited checks performed. "
            "Use website with normal browser security precautions."
        )


    return {
        "url": url,
        "checks": {
            "https_in_submitted_url": is_https,
            "hostname_present": bool(hostname),
            "live_response": live_checks
        },

        "findings": findings,

        "preliminary_assessment": {
            "risk_level": risk_level,
            "reason": risk_reason,
        },
    }


def _get_set_cookie_headers(response):
    """Get individual Set-Cookie headers from the response."""
    return response.headers.get_all("Set-Cookie", [])


def _parse_csp_directives(csp_value):
    """Extract basic Content-Security-Policy directives."""

    directives = {}

    for directive in csp_value.split(";"):

        parts = directive.strip().lower().split()

        if parts:
            directives[parts[0]] = parts[1:]

    return directives


def _inspect_live_response(url, findings, addresses=None):
    """Perform checks on the website's HTTP response."""

    parsed = urlparse(url)

    live_checks = {
        "request_completed": False,
        "http_status_code": None,
        "tls_connection_verified": None,
        "security_headers": {},
        "cookies_detected": False,
        "cookies": [],
        "redirect_detected": False,
        "server_header_present": False
    }

    try:
        with _open_public_response(url, addresses) as response:

            live_checks["request_completed"] = True
            live_checks["http_status_code"] = response.status
            live_checks["server_header_present"] = bool(response.headers.get("Server"))

            if parsed.scheme == "https":
                live_checks["tls_connection_verified"] = True

            assess_page_headers = 200 <= response.status < 300

            # 1. Check Content-Security-Policy, X-Content-Type-Options

            csp_value = response.headers.get(
                "Content-Security-Policy", ""
            )

            csp_directives = _parse_csp_directives(csp_value)

            csp_present = bool(csp_value.strip())

            live_checks["security_headers"][
                "content_security_policy"
            ] = csp_present

            if assess_page_headers and not csp_present:
                findings.append({
                    "id": "missing_csp",
                    "category": "HTTP Security",
                    "severity": "low",
                    "evidence": (
                        "Content-Security-Policy header "
                        "was not detected."
                    ),
                    "limitation": (
                        "A missing CSP header does not prove "
                        "that the website is vulnerable."
                    )
                })

            # 2. X-Content-Type-Options

            xcto_value = response.headers.get(
                "X-Content-Type-Options", ""
            ).strip().lower()

            xcto_configured = xcto_value == "nosniff"

            live_checks["security_headers"][
                "x_content_type_options"
            ] = xcto_configured

            if assess_page_headers and not xcto_configured:
                findings.append({
                    "id": "weak_x_content_type_options",
                    "category": "HTTP Security",
                    "severity": "low",
                    "evidence": (
                        "X-Content-Type-Options is missing "
                        "or is not configured as 'nosniff'."
                    )
                })


            # 3. Strict-Transport-Security (HTTPS only)

            if parsed.scheme.lower() == "https":

                hsts_value = response.headers.get(
                    "Strict-Transport-Security", ""
                )

                max_age = re.search(
                    r"(?:^|;)\s*max-age\s*=\s*([0-9]+)\s*(?:;|$)",
                    hsts_value,
                    re.IGNORECASE
                )

                hsts_configured = bool(
                    max_age and max_age.group(1).lstrip("0")
                )

                live_checks["security_headers"][
                    "strict_transport_security"
                ] = hsts_configured

                if assess_page_headers and not hsts_configured:
                    findings.append({
                        "id": "missing_or_weak_hsts",
                        "category": "Transport Security",
                        "severity": "low",
                        "evidence": (
                            "HSTS is missing or does not specify "
                            "a positive max-age value."
                        )
                    })

            else:

                live_checks["security_headers"][
                    "strict_transport_security"
                ] = None


            # 4. Clickjacking protection

            xfo_value = response.headers.get(
                "X-Frame-Options", ""
            ).strip().lower()

            xfo_protection = xfo_value in (
                "deny",
                "sameorigin"
            )

            frame_ancestors = csp_directives.get(
                "frame-ancestors", []
            )

            csp_frame_protection = (
                bool(frame_ancestors)
                and frame_ancestors != ["*"]
            )

            frame_protection = (
                xfo_protection or csp_frame_protection
            )

            live_checks["security_headers"][
                "frame_protection"
            ] = frame_protection

            if assess_page_headers and not frame_protection:
                findings.append({
                    "id": "missing_frame_protection",
                    "category": "HTTP Security",
                    "severity": "low",
                    "evidence": (
                        "Neither a recognised X-Frame-Options "
                        "value nor a restrictive CSP "
                        "frame-ancestors directive was detected."
                    )
                })

            # 5. Cookie security attributes

            cookie_headers = _get_set_cookie_headers(response)
            live_checks["cookies_detected"] = bool(cookie_headers)

            for raw_cookie in cookie_headers:

                cookie = SimpleCookie()

                try:
                    cookie.load(raw_cookie)
                except CookieError:
                    continue

                for cookie_name, morsel in cookie.items():

                    secure = bool(morsel["secure"])
                    httponly = bool(morsel["httponly"])
                    samesite = morsel["samesite"].strip().lower()

                    # Store attributes, never the cookie value.
                    live_checks["cookies"].append({
                        "name": cookie_name,
                        "secure": secure,
                        "httponly": httponly,
                        "samesite": samesite or None
                    })

                    if not secure:
                        findings.append({
                            "id": "cookie_missing_secure",
                            "category": "Cookie Security",
                            "severity": "low",
                            "evidence": (
                                f"Cookie '{cookie_name}' "
                                "does not include the Secure attribute."
                            ),
                            "limitation": (
                                "The scanner cannot determine whether "
                                "this cookie contains sensitive data."
                            )
                        })

                    if not httponly:
                        findings.append({
                            "id": "cookie_missing_httponly",
                            "category": "Cookie Security",
                            "severity": "low",
                            "evidence": (
                                f"Cookie '{cookie_name}' "
                                "does not include the HttpOnly attribute."
                            ),
                            "limitation": (
                                "Not every cookie needs HttpOnly. "
                                "The scanner cannot determine its purpose."
                            )
                        })

                    if not samesite:
                        findings.append({
                            "id": "cookie_missing_samesite",
                            "category": "Cookie Security",
                            "severity": "low",
                            "evidence": (
                                f"Cookie '{cookie_name}' "
                                "does not specify a SameSite attribute."
                            )
                        })

                    elif samesite not in (
                        "strict",
                        "lax",
                        "none"
                    ):
                        findings.append({
                            "id": "cookie_invalid_samesite",
                            "category": "Cookie Security",
                            "severity": "low",
                            "evidence": (
                                f"Cookie '{cookie_name}' has an "
                                "unrecognised SameSite value."
                            )
                        })

                    if samesite == "none" and not secure:
                        findings.append({
                            "id": "cookie_samesite_none_without_secure",
                            "category": "Cookie Security",
                            "severity": "low",
                            "evidence": (
                                f"Cookie '{cookie_name}' uses "
                                "SameSite=None without Secure."
                            )
                        })

            # 6. Detect redirects without following them.

            if (
                response.status in (301, 302, 303, 307, 308)
                and response.headers.get("Location")
            ):

                live_checks["redirect_detected"] = True
                live_checks["redirect_status_code"] = (
                    response.status
                )

                try:
                    redirect_url = urljoin(url, response.headers["Location"])
                    target_scheme = urlparse(redirect_url).scheme.lower()
                except ValueError:
                    target_scheme = None

                live_checks["redirect_target_scheme"] = target_scheme

                findings.append({
                    "id": "redirect_detected",
                    "category": "URL Behaviour",
                    "severity": "info",
                    "evidence": (
                        "The server returned a redirect. "
                        "The scanner did not follow its destination."
                    )
                })

                if (
                    parsed.scheme.lower() == "https"
                    and target_scheme == "http"
                ):
                    findings.append({
                        "id": "https_redirects_to_http",
                        "category": "Transport Security",
                        "severity": "medium",
                        "evidence": (
                            "The HTTPS website redirects to an "
                            "HTTP destination without encryption."
                        )
                    })




    except ssl.SSLError:
        live_checks["tls_connection_verified"] = False
        findings.append({
            "id": "tls_verification_failed",
            "category": "Transport Security",
            "severity": "high",
            "evidence": "The TLS handshake or certificate verification failed.",
        })

    except TimeoutError:

        findings.append({
            "id": "request_timeout",
            "category": "Connection",
            "severity": "info",
            "evidence": (
                "The website did not respond within the "
                "scanner's configured timeout."
            )
        })

    except (OSError, HTTPException, ValueError, UnsafeTargetError):

        findings.append({
            "id": "connection_error",
            "category": "Connection",
            "severity": "info",
            "evidence": (
                "The scanner could not complete the HTTP request."
            )
        })

    return live_checks


