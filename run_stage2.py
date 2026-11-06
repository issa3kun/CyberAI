"""Read a scanner JSON file and print/save a Stage 2 assessment or webhook draft."""

import argparse
import json
from pathlib import Path

from stage2_engine import assess_scan, build_webhook_payload


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Ziyad's scanner response JSON")
    parser.add_argument("--webhook", action="store_true", help="Prepare Bryan's draft webhook JSON; does not send it")
    parser.add_argument("--output", type=Path, help="Save JSON instead of printing it")
    parser.add_argument("--input-origin", choices=["user_supplied_scan", "synthetic_test_data", "unspecified"], default="unspecified")
    parser.add_argument("--literacy-level", default="unspecified", help="Pass through the agreed frontend literacy label when available")
    parser.add_argument("--scan-id", help="An optional scan/job ID supplied by the caller")
    args = parser.parse_args(argv)
    try:
        scan = json.loads(args.input.read_text(encoding="utf-8-sig"))
        result = assess_scan(scan)
        if args.webhook:
            result = build_webhook_payload(result, input_origin=args.input_origin,
                                           literacy_level=args.literacy_level, scan_id=args.scan_id)
        content = json.dumps(result, indent=2, ensure_ascii=True, allow_nan=False) + "\n"
        if args.output:
            args.output.write_text(content, encoding="utf-8")
            print(f"Saved {args.output}")
        else:
            print(content, end="")
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
