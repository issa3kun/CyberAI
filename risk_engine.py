"""CyberAI risk engine, stage 1: arithmetic and scanner input handling.

Uses only Python's standard library. No real finding has a scoring rule yet.
"""

import argparse
import json
from pathlib import Path


ENGINE_VERSION = "0.1.0"

# CSA's February 2021 guide, printed page 16, Figure 5.
# These are exactly the products attainable from integer factors 1 through 5.
RISK_LEVELS = {
    1: "Low", 2: "Low", 3: "Low", 4: "Low",
    5: "Medium", 6: "Medium", 8: "Medium", 9: "Medium",
    10: "Medium High", 12: "Medium High",
    15: "High", 16: "High", 20: "Very High", 25: "Very High",
}

# These notes explain what further assessment each current scanner ID needs.
# They are not numerical scoring rules and must not be treated as such.
FINDING_NOTES = {
    "https_not_used": (
        "This describes the submitted URL only. HTTPS redirection and the "
        "final destination were not assessed."
    ),
    "content_security_policy_missing": (
        "Only CSP header absence was observed. HTML meta policies, an "
        "injection path and the consequences are not established."
    ),
    "content_type_options_missing": (
        "MIME context and the conditions needed for a harmful scenario "
        "must be assessed before scoring."
    ),
    "referrer_policy_missing": (
        "Browser defaults, sensitive URL content and relevant destinations "
        "must be considered before scoring."
    ),
    "permissions_policy_missing": (
        "Relevant browser features and a credible harm scenario must be "
        "identified before scoring."
    ),
    "hsts_missing": (
        "Only this response was inspected. Transport attack conditions "
        "and relevant existing protections need assessment."
    ),
    "framing_protection_not_detected": (
        "A sensitive interaction and applicable framing restrictions "
        "must be assessed before scoring a clickjacking scenario."
    ),
    "cookie_security_attributes_missing": (
        "The missing attributes, cookie purpose and relevant browser "
        "behaviour require a reviewed scenario rule."
    ),
}


def _validate_rating(value, name):
    """Accept integer ratings 1-5, rejecting booleans and missing values."""
    if type(value) is not int or not 1 <= value <= 5:
        raise ValueError(f"{name} must be an integer from 1 to 5.")


def calculate_likelihood(discoverability, exploitability, reproducibility):
    """Round the mean of three already-justified ratings, as CSA proposes.

    This function does not decide the three ratings from scanner findings.
    Integer thirds cannot produce an exact .5 rounding tie.
    """
    factors = {
        "discoverability": discoverability,
        "exploitability": exploitability,
        "reproducibility": reproducibility,
    }
    for name, value in factors.items():
        _validate_rating(value, name)
    return round(sum(factors.values()) / 3)


def calculate_risk(likelihood, confidentiality, integrity, availability):
    """Calculate a single scenario using already-justified ratings.

    CIA maximum is the impact. This is a ranking index, not a probability.
    Unknown inputs must remain unassessed instead of being replaced by 1.
    """
    cia = {
        "confidentiality": confidentiality,
        "integrity": integrity,
        "availability": availability,
    }
    _validate_rating(likelihood, "likelihood")
    for name, value in cia.items():
        _validate_rating(value, name)
    impact = max(cia.values())
    score = likelihood * impact
    return {
        "likelihood": likelihood,
        "cia": cia,
        "impact": impact,
        "risk_score": score,
        "risk_level": RISK_LEVELS[score],
    }


def assess_scan(scan):
    """Read Ziyad's current scanner dictionary without inventing risk scores.

    Stage 1 classifies metadata, limitations, known findings and unknown IDs.
    Scanner-provided severity or scoring fields never drive calculations.
    """
    if not isinstance(scan, dict):
        raise ValueError("Scanner output must be a JSON object.")
    if not isinstance(scan.get("url"), str) or not scan["url"].strip():
        raise ValueError("Scanner output needs a non-empty 'url' string.")
    checks = scan.get("checks", {})
    if not isinstance(checks, dict):
        raise ValueError("'checks' must be an object.")
    findings = scan.get("findings")
    if not isinstance(findings, list):
        raise ValueError("'findings' must be a list.")
    for finding in findings:
        if not isinstance(finding, dict):
            raise ValueError("Each finding must be an object.")
        if not isinstance(finding.get("id"), str) or not finding["id"].strip():
            raise ValueError("Each finding needs a non-empty 'id' string.")

    request_failed = any(f["id"] == "http_request_failed" for f in findings)
    response_received = (
        checks.get("http_response_received") is True and not request_failed
    )
    assessed = []

    for finding in findings:
        finding_id = finding["id"]
        if finding_id == "hostname_detected":
            status = "informational"
            reason = "A detected hostname is metadata, not a scored risk."
        elif finding_id == "http_request_failed":
            status = "incomplete"
            reason = "No HTTP assessment was completed; the cause is unspecified."
        elif finding_id not in FINDING_NOTES:
            status = "unsupported"
            reason = "This finding ID has no assessment handler yet."
        elif finding_id != "https_not_used" and not response_received:
            status = "incomplete"
            reason = "A received HTTP response was not confirmed for this check."
        else:
            status = "needs_rule"
            reason = FINDING_NOTES[finding_id]

        item = {
            key: finding[key]
            for key in ("id", "category", "evidence", "limitation",
                        "recommendation", "details")
            if key in finding
        }
        item.update({
            "scanner_severity": finding.get("severity"),
            "assessment_status": status,
            "assessment_reason": reason,
            "likelihood": None,
            "impact": None,
            "risk_score": None,
            "risk_level": None,
        })
        assessed.append(item)

    return {
        "engine_version": ENGINE_VERSION,
        "url": scan["url"],
        "assessment_scope": "submitted_url_and_initial_response_only",
        "checks": checks.copy(),
        "overall_risk": {
            "status": "not_assessed",
            "risk_score": None,
            "risk_level": None,
            "reason": (
                "Finding scoring rules and overall aggregation are not "
                "implemented. Empty findings do not establish website safety."
            ),
        },
        "summary": {
            "findings_received": len(findings),
            "findings_scored": 0,
            "findings_needing_rules": sum(
                f["assessment_status"] == "needs_rule" for f in assessed
            ),
        },
        "findings": assessed,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", nargs="?", type=Path, help="Scanner JSON file")
    parser.add_argument("--demo", action="store_true", help="Run bundled examples")
    args = parser.parse_args(argv)
    if bool(args.input) == args.demo:
        parser.error("Provide either a scanner JSON file or --demo.")
    input_path = args.input or Path(__file__).with_name("sample_scan.json")
    try:
        scan = json.loads(input_path.read_text(encoding="utf-8-sig"))
        output = assess_scan(scan)
        if args.demo:
            likelihood = calculate_likelihood(2, 3, 4)
            output = {
                "arithmetic_example_only": {
                    "notice": "Fictional ratings for learning; not a finding rule.",
                    "factors": {
                        "discoverability": 2, "exploitability": 3,
                        "reproducibility": 4,
                    },
                    "result": calculate_risk(likelihood, 2, 3, 1),
                },
                "scanner_assessment": output,
            }
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(output, indent=2, ensure_ascii=True))


if __name__ == "__main__":
    main()
