"""Send a scanner JSON file to the new n8n scanner intake workflow."""

import argparse
import json
import os
from pathlib import Path

from n8n_client import DeliveryError, post_json
from scan_message import INPUT_ORIGINS, build_scan_message


def send_scan_result(scan_result, *, webhook_url=None, input_origin="unspecified",
                     literacy_level="unspecified", scan_id=None, timeout=30):
    """Ziyad can call this after his scanner returns its result dictionary."""
    message = build_scan_message(scan_result, input_origin=input_origin,
                                 literacy_level=literacy_level, scan_id=scan_id)
    return post_json(
        message, webhook_url or os.environ.get("CYBERAI_N8N_SCAN_WEBHOOK_URL"), timeout=timeout,
        auth_header=os.environ.get("CYBERAI_N8N_HEADER_NAME"),
        auth_token=os.environ.get("CYBERAI_N8N_HEADER_VALUE"),
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Raw scanner response; use fixtures, not webhook_examples")
    parser.add_argument("--input-origin", choices=INPUT_ORIGINS, default="unspecified")
    parser.add_argument("--literacy-level", default="unspecified")
    parser.add_argument("--scan-id")
    parser.add_argument("--timeout", type=float, default=30)
    parser.add_argument("--output", type=Path, help="Save the full returned RAE envelope and receipt here")
    args = parser.parse_args(argv)
    try:
        scan = json.loads(args.input.read_text(encoding="utf-8-sig"))
        receipt = send_scan_result(scan, input_origin=args.input_origin,
                                   literacy_level=args.literacy_level,
                                   scan_id=args.scan_id, timeout=args.timeout)
    except (OSError, UnicodeError, ValueError, DeliveryError) as exc:
        parser.error(str(exc))
    if args.output:
        try:
            args.output.write_text(json.dumps(receipt, indent=2, allow_nan=False) + "\n", encoding="utf-8")
        except OSError:
            parser.error("n8n returned a response, but the receipt could not be saved. Do not resend just to save the file; check n8n's execution history.")
        print(f"Response received (HTTP {receipt['http_status']}). Saved {args.output}")
    else:
        print(json.dumps(receipt, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
