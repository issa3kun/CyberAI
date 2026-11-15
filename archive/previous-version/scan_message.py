"""The draft scanner-to-n8n envelope. Evidence stays separate from assessment."""

import copy
import json

SCAN_EVENT = "cyberai.scanner.result_ready"
SCAN_CONTRACT = "cyberai.scanner.intake/0.1.0-draft"
INPUT_ORIGINS = ("user_supplied_scan", "synthetic_test_data", "unspecified")


def validate_scan_message(message):
    """Validate delivery structure, leaving evidence checks to the RAE adapter."""
    if not isinstance(message, dict):
        raise ValueError("Expected a scanner intake JSON object.")
    if message.get("event") != SCAN_EVENT or message.get("contract_version") != SCAN_CONTRACT:
        raise ValueError("Expected the cyberai.scanner.result_ready intake contract; send raw scan evidence, not a prepared assessment.")
    scan = message.get("scan_result")
    if not isinstance(scan, dict):
        raise ValueError("scan_result must contain the scanner's JSON object.")
    if not isinstance(scan.get("url"), str) or not scan["url"].strip():
        raise ValueError("scan_result needs a non-empty URL.")
    if not isinstance(scan.get("checks"), dict) or not isinstance(scan.get("findings"), list):
        raise ValueError("scan_result needs a checks object and findings list.")
    if message.get("input_origin") not in INPUT_ORIGINS:
        raise ValueError("input_origin must be user_supplied_scan, synthetic_test_data or unspecified.")
    literacy = message.get("literacy_level")
    scan_id = message.get("scan_id")
    if not isinstance(literacy, str) or not literacy.strip():
        raise ValueError("literacy_level must be a non-empty string.")
    if scan_id is not None and (not isinstance(scan_id, str) or not scan_id.strip()):
        raise ValueError("scan_id must be a non-empty string or null.")
    # JSON has no NaN or infinity. Reject these rather than silently changing evidence.
    try:
        json.dumps(message, allow_nan=False)
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise ValueError("The intake message must contain finite, JSON-compatible values.") from exc
    return message


def build_scan_message(scan_result, *, input_origin="unspecified", literacy_level="unspecified", scan_id=None):
    """Wrap a scan without assigning scores or changing its findings."""
    message = {
        "event": SCAN_EVENT,
        "contract_version": SCAN_CONTRACT,
        "scan_id": scan_id,
        "input_origin": input_origin,
        "literacy_level": literacy_level,
        "scan_result": scan_result,
    }
    validate_scan_message(message)
    return copy.deepcopy(message)
