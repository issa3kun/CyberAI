"""A reusable Flask RAE route, plus a local test server for Imran's computer."""

import argparse
import hmac
import os

from flask import Blueprint, Flask, jsonify, request
from werkzeug.exceptions import BadRequest, RequestEntityTooLarge

from scan_message import validate_scan_message
from stage2_engine import assess_scan, build_webhook_payload

MAX_REQUEST_BYTES = 1024 * 1024


def _error(code, message, status):
    return jsonify({"error": {"code": code, "message": message}}), status


def create_rae_blueprint(api_token=None):
    """Register this component in Ziyad's Flask app; scoring stays in the engine."""
    token = os.environ.get("CYBERAI_RAE_API_TOKEN") if api_token is None else api_token
    if not isinstance(token, str) or not token.strip() or not token.isascii() or any(ord(c) < 33 or ord(c) > 126 for c in token):
        raise ValueError("Set CYBERAI_RAE_API_TOKEN to a non-empty ASCII token without whitespace.")
    blueprint = Blueprint("cyberai_rae", __name__, url_prefix="/api/rae")

    @blueprint.get("/health")
    def health():
        return jsonify({"service": "cyberai-rae", "status": "ready", "engine_version": "0.2.0"})

    @blueprint.post("/assess")
    def assess():
        supplied = request.headers.get("X-CyberAI-Token", "")
        if not hmac.compare_digest(supplied.encode("utf-8"), token.encode("ascii")):
            return _error("unauthorized", "A valid X-CyberAI-Token header is required.", 401)
        if not request.is_json:
            return _error("json_required", "Send Content-Type: application/json.", 415)
        try:
            if request.content_length is not None and request.content_length > MAX_REQUEST_BYTES:
                raise RequestEntityTooLarge()
            # A bounded read also protects a blueprint registered in an existing app.
            raw = request.stream.read(MAX_REQUEST_BYTES + 1)
            if len(raw) > MAX_REQUEST_BYTES:
                raise RequestEntityTooLarge()
            message = request.json_module.loads(raw)
        except RequestEntityTooLarge:
            return _error("payload_too_large", "Scanner intake is limited to 1 MiB.", 413)
        except (BadRequest, ValueError, UnicodeError, RecursionError):
            return _error("invalid_json", "The request body must be valid JSON.", 400)
        try:
            validate_scan_message(message)
            assessment = assess_scan(message["scan_result"])
            result = build_webhook_payload(assessment, input_origin=message["input_origin"],
                                           literacy_level=message["literacy_level"],
                                           scan_id=message.get("scan_id"))
        except ValueError as exc:
            return _error("invalid_scan_message", str(exc), 400)
        return jsonify(result)

    return blueprint


def create_app(api_token=None):
    """Local prototype only. The blueprint is also reusable in the team backend."""
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_REQUEST_BYTES
    app.register_blueprint(create_rae_blueprint(api_token))
    return app


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5001)
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535.")
    try:
        app = create_app()
    except ValueError as exc:
        parser.error(str(exc))
    app.run(host=args.host, port=args.port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
