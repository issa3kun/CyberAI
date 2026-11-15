"""Small JSON POST client. Uses Python's standard library; sends once only."""

from http.client import HTTPException
import json
import math
import re
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

MAX_RESPONSE_BYTES = 1024 * 1024


class DeliveryError(RuntimeError):
    """The sender could not confirm a JSON response; delivery may still have occurred."""


class _NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _check_url(webhook_url):
    if not isinstance(webhook_url, str) or not webhook_url:
        raise ValueError("Set the n8n webhook URL before sending.")
    if any(ord(c) < 33 or ord(c) == 127 for c in webhook_url):
        raise ValueError("The webhook URL must not contain whitespace or control characters.")
    try:
        parsed = urlsplit(webhook_url)
        _ = parsed.port
        valid = (parsed.scheme in {"http", "https"} and parsed.hostname
                 and parsed.username is None and parsed.password is None and not parsed.fragment)
    except ValueError:
        valid = False
    if not valid:
        raise ValueError("Use an HTTP/HTTPS webhook URL without embedded credentials or a fragment.")


def post_json(payload, webhook_url, *, timeout=30, auth_header=None, auth_token=None):
    """POST JSON to an operator-configured URL and return its JSON response.

    No retries: a timeout can occur after n8n has already started the workflow.
    No redirects: data and credentials stay at the configured destination.
    HTTP 200 confirms a response, not correctness of the assessment or AI report.
    """
    _check_url(webhook_url)
    if (isinstance(timeout, bool) or not isinstance(timeout, (float, int))
            or not math.isfinite(timeout) or timeout <= 0):
        raise ValueError("timeout must be a finite positive number of seconds.")
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if auth_header is not None or auth_token is not None:
        if (not isinstance(auth_header, str)
                or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", auth_header)
                or auth_header.lower() in {"host", "content-type", "content-length", "accept", "transfer-encoding"}
                or not isinstance(auth_token, str) or not auth_token
                or any(ord(c) < 32 or ord(c) > 126 for c in auth_token)):
            raise ValueError("Supply both a valid authentication header name and a non-empty ASCII token.")
        headers[auth_header] = auth_token
    try:
        body = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, OverflowError, RecursionError, UnicodeError) as exc:
        raise ValueError("Payload must be valid JSON with finite numbers.") from exc
    request = Request(webhook_url, data=body, headers=headers, method="POST")
    try:
        with build_opener(_NoRedirects()).open(request, timeout=timeout) as response:
            status = response.status
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except HTTPError as exc:
        code = exc.code
        exc.close()
        if 300 <= code < 400:
            raise DeliveryError("Webhook redirected the request; use its final URL. No redirect was followed.") from None
        raise DeliveryError(f"Webhook returned HTTP {code}; check n8n's execution history.") from None
    except (URLError, OSError, HTTPException) as exc:
        raise DeliveryError("Could not confirm the webhook response. Check n8n's execution history before resending; it may already have run.") from exc
    if not 200 <= status < 300:
        raise DeliveryError(f"Webhook returned HTTP {status}.")
    if len(raw) > MAX_RESPONSE_BYTES:
        raise DeliveryError("Webhook response exceeded 1 MiB; check its output settings.")
    if not raw.strip():
        raise DeliveryError("Webhook returned an empty response. Configure Respond to Webhook to return JSON.")
    try:
        result = json.loads(raw.decode("utf-8-sig"), parse_constant=_invalid_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise DeliveryError("Webhook returned invalid JSON; check Respond to Webhook.") from None
    return {"delivery_status": "response_received", "http_status": status, "response": result}


def _invalid_constant(value):
    raise ValueError("Invalid JSON constant.")
