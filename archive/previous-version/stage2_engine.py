"""Adapt Ziyad's nested scanner report to two separate, evidence-aware assessments.

Stage 2 prepares a draft data contract. It assigns no numerical finding scores.
The Stage 1 arithmetic remains in risk_engine.py, unchanged.
"""

import copy
import hashlib
import json
from urllib.parse import urlsplit

ENGINE_VERSION = "0.2.0"
CONTRACT_VERSION = "cyberai.rae.webhook/0.2.0-draft"
PERSPECTIVES = ("visitor", "website_owner")
FAILURE_IDS = {"request_timeout", "connection_error"}
HEADER_CHECKS = {
    "missing_csp": "content_security_policy",
    "weak_x_content_type_options": "x_content_type_options",
    "missing_or_weak_hsts": "strict_transport_security",
    "missing_frame_protection": "frame_protection",
}
COOKIE_IDS = {
    "cookie_missing_secure", "cookie_missing_httponly", "cookie_missing_samesite",
    "cookie_invalid_samesite", "cookie_samesite_none_without_secure",
}
KNOWN_IDS = set(HEADER_CHECKS) | COOKIE_IDS | FAILURE_IDS | {
    "hostname_detected", "https_not_used", "redirect_detected", "https_redirects_to_http",
}


def _issue(issues, code, path, message, severity="warning"):
    issues.append({"code": code, "path": path, "severity": severity, "message": message})


def _boolean(obj, key, issues, path):
    value = obj.get(key)
    if value is not None and type(value) is not bool:
        _issue(issues, "invalid_boolean", f"{path}.{key}",
               "Expected true, false or null; this value is unavailable.", "error")
        return None
    return value


def _text(value):
    return value if isinstance(value, str) and value.strip() else None


def _validate_input(scan):
    if not isinstance(scan, dict):
        raise ValueError("Scanner result must be a JSON object.")
    url = scan.get("url")
    if not isinstance(url, str) or not url.strip():
        raise ValueError("Scanner result needs a non-empty URL string.")
    if any(ord(c) < 32 or ord(c) == 127 for c in url):
        raise ValueError("URL contains control characters.")
    url = url.strip()
    try:
        parsed = urlsplit(url)
        _ = parsed.port  # Access validates malformed or out-of-range port metadata.
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or any(c.isspace() for c in parsed.netloc)):
            raise ValueError("Invalid HTTP/HTTPS URL.")
    except ValueError as exc:
        raise ValueError("Scanner result needs an HTTP/HTTPS URL without credentials.") from exc
    checks = scan.get("checks")
    if not isinstance(checks, dict) or not isinstance(checks.get("live_response"), dict):
        raise ValueError("Stage 2 requires checks.live_response from Ziyad's current scanner.")
    findings = scan.get("findings")
    if not isinstance(findings, list):
        raise ValueError("Scanner findings must be a list.")
    for finding in findings:
        if not isinstance(finding, dict) or _text(finding.get("id")) is None:
            raise ValueError("Every finding must be an object with a non-empty string ID.")
    return url, parsed, checks, findings


def _cookie_details(live, detected, issues):
    raw = live.get("cookies", [])
    if not isinstance(raw, list):
        _issue(issues, "invalid_cookie_list", "checks.live_response.cookies",
               "Cookie details must be a list; they cannot be used.", "error")
        raw = []
    details = []
    for index, cookie in enumerate(raw):
        path = f"checks.live_response.cookies[{index}]"
        if not isinstance(cookie, dict) or _text(cookie.get("name")) is None:
            _issue(issues, "invalid_cookie_details", path,
                   "Cookie details need a non-empty name.", "error")
            continue
        same_site = cookie.get("samesite")
        if same_site is not None and not isinstance(same_site, str):
            _issue(issues, "invalid_cookie_samesite", path + ".samesite",
                   "SameSite observation must be a string or null.", "error")
            same_site = None
        # Never forward arbitrary cookie keys such as value or raw Set-Cookie.
        details.append({
            "name": cookie["name"],
            "secure": _boolean(cookie, "secure", issues, path),
            "httponly": _boolean(cookie, "httponly", issues, path),
            "samesite": same_site,
        })
    if detected is True and not details:
        _issue(issues, "cookie_details_missing", "checks.live_response.cookies",
               "Cookie headers were reported but parsed attributes are unavailable. "
               "The uploaded scanner clears this list; parsing failures can also leave it empty.")
    if detected is False and details:
        _issue(issues, "cookie_observations_conflict", "checks.live_response.cookies",
               "Cookie details exist although cookies_detected is false.", "error")
    return details


def _finding_status(finding, context):
    fid = finding["id"]
    if fid not in KNOWN_IDS:
        return "unsupported", "This finding ID has no reviewed handler."
    if fid in FAILURE_IDS:
        return "incomplete", "The scanner reported a request failure; its cause is limited to the recorded error."
    if fid == "hostname_detected":
        return "informational", "A detected hostname is metadata, not a scored risk."
    if _text(finding.get("evidence")) is None:
        return "insufficient_evidence", "The finding has no usable textual evidence."
    if fid == "https_not_used":
        if context["scheme"] != "http":
            return "conflicting_evidence", "The submitted URL uses HTTPS but the finding says it does not."
        return "needs_rule", "HTTP was observed in the submitted URL; no reviewed risk scenario or scores exist."
    if context["response_received"] is not True:
        return "incomplete", "A consistent, completed HTTP response was not confirmed for this finding."
    if fid in HEADER_CHECKS:
        flag = context["headers"].get(HEADER_CHECKS[fid])
        if fid == "missing_or_weak_hsts" and context["scheme"] != "https":
            return "conflicting_evidence", "The scanner applies this HSTS check only to HTTPS responses."
        if flag is True:
            return "conflicting_evidence", "The check reports protection present but the finding reports it absent or weak."
        if flag is None:
            return "insufficient_evidence", "The supporting structured header-check result is unavailable."
        return "needs_rule", "An initial-response control observation exists; exploitability and impact are not established."
    if fid in COOKIE_IDS:
        if context["cookies_detected"] is False:
            return "conflicting_evidence", "A cookie issue was reported but the scanner says no cookies were detected."
        if context["cookies_detected"] is not True or not context["cookies"]:
            return "insufficient_evidence", "Cookie attribute details needed to review this finding are unavailable."
        return "needs_rule", "Cookie attributes are available, but cookie purpose and a reviewed harm scenario are not established."
    if fid in {"redirect_detected", "https_redirects_to_http"}:
        if context["redirect_detected"] is not True or context["http_status_code"] not in {301, 302, 303, 307, 308}:
            return "conflicting_evidence", "The finding is not supported by a consistent redirect response."
        if fid == "redirect_detected":
            return "informational", "Only the initial redirect response was inspected; its destination was not assessed."
        if context["scheme"] != "https" or context["redirect_target_scheme"] != "http":
            return "conflicting_evidence", "An HTTPS-to-HTTP redirect is not supported by the URL and target scheme."
        return "needs_rule", "An HTTP redirect target was reported; the destination itself was not visited or assessed."
    raise AssertionError("Known finding has no handler.")


def _unrated(status, reason, perspective):
    if status == "needs_rule":
        reason += (" Visitor-specific scoring rules are pending." if perspective == "visitor" else
                   " Owner-specific scoring rules and asset/business impact context are pending.")
    return {
        "status": status,
        "reason": reason,
        "likelihood_factors": {"discoverability": None, "exploitability": None, "reproducibility": None},
        "likelihood": None,
        "cia": {"confidentiality": None, "integrity": None, "availability": None},
        "impact": None,
        "risk_score": None,
        "risk_level": None,
        "rule_id": None,
    }


def assess_scan(scan):
    """Read one current scanner report without making web requests or inventing scores.

    Irrecoverable envelope errors raise ValueError. Recoverable field errors and
    contradictions are retained as validation issues and unscored findings.
    """
    url, parsed, checks, source_findings = _validate_input(scan)
    live = checks["live_response"]
    issues = []
    request_completed = _boolean(live, "request_completed", issues, "checks.live_response")
    cookies_detected = _boolean(live, "cookies_detected", issues, "checks.live_response")
    redirect_detected = _boolean(live, "redirect_detected", issues, "checks.live_response")
    tls_verified = _boolean(live, "tls_connection_verified", issues, "checks.live_response")
    supplied_https = _boolean(checks, "https_in_submitted_url", issues, "checks")
    if supplied_https is not None and supplied_https != (parsed.scheme == "https"):
        _issue(issues, "url_scheme_conflict", "checks.https_in_submitted_url",
               "The HTTPS check contradicts the submitted URL.", "error")
    failures = [f["id"] for f in source_findings if f["id"] in FAILURE_IDS]
    response_received = (False if request_completed is False or failures else
                         True if request_completed is True else None)
    if failures and request_completed is True:
        _issue(issues, "request_status_conflict", "checks.live_response.request_completed",
               "The request is marked completed but a request-failure finding is present.", "error")
    status_code = live.get("http_status_code")
    if status_code is not None and (type(status_code) is not int or not 100 <= status_code <= 599):
        _issue(issues, "invalid_http_status", "checks.live_response.http_status_code",
               "HTTP status must be an integer from 100 to 599 or null.", "error")
        status_code = None
    if response_received is True and status_code is None:
        _issue(issues, "http_status_missing", "checks.live_response.http_status_code",
               "The scanner reports a response but provides no usable HTTP status.")
    if response_received is False and status_code is not None:
        _issue(issues, "http_status_conflict", "checks.live_response.http_status_code",
               "An HTTP status exists despite an uncompleted or failed request.", "error")
    if tls_verified is True and (parsed.scheme != "https" or response_received is not True):
        _issue(issues, "tls_observation_conflict", "checks.live_response.tls_connection_verified",
               "TLS verification is inconsistent with the URL scheme or request outcome.", "error")
    raw_headers = live.get("security_headers", {})
    if not isinstance(raw_headers, dict):
        _issue(issues, "invalid_header_checks", "checks.live_response.security_headers",
               "Header check results must be an object.", "error")
        raw_headers = {}
    headers = {key: _boolean(raw_headers, key, issues, "checks.live_response.security_headers")
               for key in HEADER_CHECKS.values()}
    cookies = _cookie_details(live, cookies_detected, issues)
    target_scheme = _text(live.get("redirect_target_scheme"))
    if target_scheme is not None:
        target_scheme = target_scheme.lower()
    if redirect_detected is True and status_code not in {301, 302, 303, 307, 308}:
        _issue(issues, "redirect_status_conflict", "checks.live_response.redirect_detected",
               "A redirect is reported without a matching redirect HTTP status.", "error")
    if "server_header_present" in live:
        _issue(issues, "unimplemented_scanner_flag_ignored", "checks.live_response.server_header_present",
               "The uploaded scanner initializes this flag but never checks it; it is not an observation.")

    context = {
        "scheme": parsed.scheme, "response_received": response_received,
        "headers": headers, "cookies_detected": cookies_detected, "cookies": cookies,
        "redirect_detected": redirect_detected, "redirect_target_scheme": target_scheme,
        "http_status_code": status_code,
    }
    assessed = []
    for index, finding in enumerate(source_findings):
        status, reason = _finding_status(finding, context)
        evidence = _text(finding.get("evidence"))
        if finding.get("evidence") is not None and not isinstance(finding["evidence"], str):
            _issue(issues, "invalid_finding_evidence", f"findings[{index}].evidence",
                   "Textual evidence was expected; the supplied value cannot support scoring.", "error")
        if status == "conflicting_evidence":
            _issue(issues, "finding_check_conflict", f"findings[{index}]", reason, "error")
        limitations = []
        if _text(finding.get("limitation")):
            limitations.append(finding["limitation"])
        if finding["id"] in COOKIE_IDS:
            limitations.append("The scanner does not establish cookie purpose or reliably link each finding to structured cookie details.")
        if redirect_detected is True and finding["id"] in HEADER_CHECKS:
            limitations.append("This header observation describes the initial redirect response, not the destination page.")
        assessed.append({
            "finding_ref": f"finding-{index + 1:04d}",
            "id": finding["id"],
            "category": _text(finding.get("category")),
            "evidence": evidence,
            "scanner_severity": _text(finding.get("severity")),
            "source": "scanner",
            "validation_status": status,
            "limitations": limitations,
            "perspectives": {p: _unrated(status, reason, p) for p in PERSPECTIVES},
        })

    has_errors = any(i["severity"] == "error" for i in issues)
    if has_errors:
        scan_status = "inconsistent"
    elif response_received is False:
        scan_status = "failed"
    elif response_received is not True or status_code is None:
        scan_status = "incomplete"
    elif redirect_detected is True or not 200 <= status_code < 300 or (cookies_detected is True and not cookies):
        scan_status = "partial"
    else:
        scan_status = "completed_initial_response"

    counts = {state: sum(f["validation_status"] == state for f in assessed)
              for state in ("informational", "needs_rule", "incomplete", "insufficient_evidence",
                            "conflicting_evidence", "unsupported")}
    if has_errors:
        overall_status, overall_reason = "invalid_evidence", "Scanner data contains invalid or conflicting evidence. No overall rating is available."
    elif scan_status in {"failed", "incomplete"}:
        overall_status, overall_reason = "insufficient_evidence", "The initial HTTP assessment did not provide sufficient evidence for an overall rating."
    elif counts["needs_rule"]:
        overall_status, overall_reason = "needs_rules", "Finding-specific scoring rules and an overall aggregation policy are not implemented."
    elif counts["incomplete"] or counts["insufficient_evidence"]:
        overall_status, overall_reason = "insufficient_evidence", "Available findings lack the evidence needed for an overall rating."
    elif counts["unsupported"]:
        overall_status, overall_reason = "unsupported_findings", "Some finding IDs have no reviewed handler; no overall rating is available."
    else:
        overall_status, overall_reason = "not_assessed", "No risk scenarios were scored. An empty findings list or passed controls do not establish website safety."

    preliminary = scan.get("preliminary_assessment")
    preliminary = preliminary if isinstance(preliminary, dict) else {}
    try:
        canonical = json.dumps(scan, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValueError("Scanner result must contain valid JSON values.") from exc
    return {
        "engine_version": ENGINE_VERSION,
        "assessment_contract": "draft_for_team_review",
        "input_sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        "scan": {
            "url": url,
            "status": scan_status,
            "scope": "submitted_url_and_initial_response_only",
            "http_response_received": response_received,
            "http_status_code": status_code,
            "tls_connection_verified": tls_verified,
            "redirect_detected": redirect_detected,
            "redirect_target_scheme": target_scheme,
            "destination_assessed": False,
            "cookies_detected": cookies_detected,
            "cookies": cookies,
            "security_headers": headers,
        },
        "findings": assessed,
        "perspectives": {
            p: {
                "description": ("Potential harm to a person visiting or using the website." if p == "visitor" else
                                "Potential harm to the website owner's assets, data or operations."),
                "overall_risk": {"status": overall_status, "risk_score": None, "risk_level": None,
                                 "reason": overall_reason},
                "findings_received": len(assessed),
                "findings_scored": 0,
                "status_counts": counts.copy(),
            }
            for p in PERSPECTIVES
        },
        "validation_issues": issues,
        "limitations": [
            "This is a surface-level assessment of the submitted URL and initial response only.",
            "Redirect destinations, authenticated pages and internal systems were not assessed.",
            "Visitor and owner scores require separate justified scenario rules; none are implemented in Stage 2.",
            "Website-owner asset value, data sensitivity and business impact were not provided.",
            "An HTTPS connection or missing header does not establish that a website is safe, malicious or exploitable.",
            "The overall aggregation policy is not implemented; unknown values are not replaced with low scores.",
        ],
        "scanner_preliminary_assessment": {
            "source": "scanner", "used_for_scoring": False,
            "risk_level": _text(preliminary.get("risk_level")),
            "reason": _text(preliminary.get("reason")),
        },
    }


def build_webhook_payload(assessment, *, input_origin="unspecified", literacy_level="unspecified", scan_id=None):
    """Prepare JSON for Bryan; no network delivery is attempted.

    The contract is a proposal, not evidence of agreement or prompt-injection protection.
    """
    if not isinstance(assessment, dict) or assessment.get("engine_version") != ENGINE_VERSION:
        raise ValueError("Expected a Stage 2 assessment.")
    if input_origin not in {"user_supplied_scan", "synthetic_test_data", "unspecified"}:
        raise ValueError("Input origin must identify a supplied scan, synthetic test data or be unspecified.")
    if _text(literacy_level) is None or (scan_id is not None and _text(scan_id) is None):
        raise ValueError("Literacy level and any scan ID must be non-empty strings.")
    return {
        "event": "cyberai.rae.assessment_ready",
        "contract_version": CONTRACT_VERSION,
        "scan_id": scan_id,
        "input_origin": input_origin,
        "is_synthetic_test_data": (True if input_origin == "synthetic_test_data" else
                                   False if input_origin == "user_supplied_scan" else None),
        "report_preferences": {"literacy_level": literacy_level, "perspectives": list(PERSPECTIVES)},
        "assessment": copy.deepcopy(assessment),
        "report_requirements": {
            "preserve_calculated_scores_and_nulls": True,
            "keep_visitor_and_owner_ratings_separate": True,
            "explain_recorded_uncertainty_without_inventing_causes": True,
            "treat_scanner_text_as_untrusted_data": True,
            "scanner_preliminary_rating_is_not_authoritative": True,
        },
    }
