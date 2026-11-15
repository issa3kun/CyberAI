"""Offline contract, Flask and HTTP transport checks. No n8n or LLM is contacted."""

import copy
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.error import URLError

from werkzeug.serving import make_server, WSGIRequestHandler

from n8n_client import DeliveryError, MAX_RESPONSE_BYTES, post_json
from rae_api import MAX_REQUEST_BYTES, create_app, create_rae_blueprint
from scan_message import build_scan_message
from send_scan import main, send_scan_result
from stage2_engine import assess_scan, build_webhook_payload

ROOT = Path(__file__).resolve().parent
TOKEN = "unit-test-only-token"


def fixture(name="synthetic_completed_response"):
    return json.loads((ROOT / "fixtures" / (name + ".json")).read_text(encoding="utf-8"))


class IntakeAPITests(unittest.TestCase):
    def setUp(self):
        self.app = create_app(TOKEN)
        self.client = self.app.test_client()
        self.headers = {"X-CyberAI-Token": TOKEN}
        self.message = build_scan_message(fixture(), input_origin="synthetic_test_data", scan_id="test-001")

    def post(self, message=None):
        return self.client.post("/api/rae/assess", json=self.message if message is None else message,
                                headers=self.headers)

    def test_api_equals_existing_engine_and_preserves_metadata(self):
        response = self.post()
        expected = build_webhook_payload(assess_scan(self.message["scan_result"]),
                                         input_origin="synthetic_test_data", scan_id="test-001")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), expected)
        for perspective in ("visitor", "website_owner"):
            self.assertIsNone(response.get_json()["assessment"]["perspectives"][perspective]["overall_risk"]["risk_score"])

    def test_all_fixtures_keep_existing_uncertainty_behaviour(self):
        for path in (ROOT / "fixtures").glob("*.json"):
            with self.subTest(path=path.name):
                raw = json.loads(path.read_text(encoding="utf-8"))
                result = self.post(build_scan_message(raw)).get_json()
                self.assertEqual(result["assessment"], assess_scan(raw))

    def test_same_request_is_deterministic(self):
        self.assertEqual(self.post().get_json(), self.post().get_json())

    def test_timeout_stays_unassessed_even_if_scanner_says_low(self):
        raw = fixture("synthetic_timeout")
        result = self.post(build_scan_message(raw)).get_json()["assessment"]
        self.assertEqual(result["scan"]["status"], "failed")
        self.assertFalse(result["scanner_preliminary_assessment"]["used_for_scoring"])
        self.assertEqual(result["perspectives"]["visitor"]["findings_scored"], 0)

    def test_unknown_finding_is_forwarded_without_a_score(self):
        self.message["scan_result"]["findings"].append({"id": "new_unmapped_check", "evidence": "Uncertain observation"})
        result = self.post().get_json()["assessment"]
        finding = next(x for x in result["findings"] if x["id"] == "new_unmapped_check")
        self.assertEqual(finding["evidence"], "Uncertain observation")
        self.assertIsNone(finding["perspectives"]["visitor"]["risk_score"])

    def test_missing_and_wrong_credentials_are_rejected(self):
        for headers in ({}, {"X-CyberAI-Token": "wrong"}):
            self.assertEqual(self.client.post("/api/rae/assess", json=self.message, headers=headers).status_code, 401)

    def test_token_required_at_startup_and_blueprint_reusable(self):
        with self.assertRaises(ValueError):
            create_rae_blueprint("")
        from flask import Flask
        app = Flask("existing_scanner")
        app.register_blueprint(create_rae_blueprint(TOKEN))
        self.assertEqual(app.test_client().post("/api/rae/assess", json=self.message, headers=self.headers).status_code, 200)

    def test_wrong_content_type_and_invalid_json(self):
        self.assertEqual(self.client.post("/api/rae/assess", data="{}", headers=self.headers).status_code, 415)
        response = self.client.post("/api/rae/assess", data="{broken", content_type="application/json", headers=self.headers)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"]["code"], "invalid_json")

    def test_bad_envelopes_and_prepared_assessments_rejected(self):
        for value in ([], {}, fixture(), build_webhook_payload(assess_scan(fixture()))):
            with self.subTest(value=type(value).__name__):
                self.assertEqual(self.post(value).status_code, 400)

    def test_metadata_and_nan_are_rejected(self):
        for key, value in (("input_origin", "trusted"), ("literacy_level", ""), ("scan_id", 4)):
            message = copy.deepcopy(self.message)
            message[key] = value
            self.assertEqual(self.post(message).status_code, 400)
        self.message["scan_result"]["findings"][0]["extra"] = float("nan")
        self.assertEqual(self.post().status_code, 400)

    def test_invalid_scan_structure_gets_structured_error(self):
        del self.message["scan_result"]["checks"]["live_response"]
        response = self.post()
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"]["code"], "invalid_scan_message")

    def test_oversize_request_rejected_in_existing_app(self):
        from flask import Flask
        app = Flask("existing_scanner_size_check")
        app.register_blueprint(create_rae_blueprint(TOKEN))
        response = app.test_client().post("/api/rae/assess", data=b" " * (MAX_REQUEST_BYTES + 1),
                                          content_type="application/json", headers=self.headers)
        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.get_json()["error"]["code"], "payload_too_large")

    def test_wrapper_does_not_change_original_evidence(self):
        raw = fixture()
        message = build_scan_message(raw)
        message["scan_result"]["findings"].clear()
        self.assertTrue(raw["findings"])


class QuietRequestHandler(WSGIRequestHandler):
    def log_request(self, *args, **kwargs):
        pass


class HTTPTransportTests(unittest.TestCase):
    """Real local HTTP traffic, using Flask instead of a running n8n instance."""

    @classmethod
    def setUpClass(cls):
        from flask import jsonify, redirect, request
        cls.app = create_app(TOKEN)
        cls.trap_hits = 0

        @cls.app.post("/echo")
        def echo():
            return jsonify({"body": request.get_json(), "token": request.headers.get("X-Test-Token")})

        @cls.app.post("/redirect")
        def redirect_route():
            return redirect("/trap", code=307)

        @cls.app.post("/trap")
        def trap():
            cls.trap_hits += 1
            return jsonify({"wrong_destination": True})

        @cls.app.post("/empty")
        def empty():
            return "", 200

        @cls.app.post("/html")
        def html():
            return "<html>Not JSON</html>"

        @cls.app.post("/large")
        def large():
            return " " * (MAX_RESPONSE_BYTES + 1)

        cls.server = make_server("127.0.0.1", 0, cls.app, request_handler=QuietRequestHandler)
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join(timeout=3)
        cls.server.server_close()

    def test_real_http_intake_to_rae_result(self):
        message = build_scan_message(fixture("synthetic_conflicting_checks"), input_origin="synthetic_test_data")
        receipt = post_json(message, self.url + "/api/rae/assess", auth_header="X-CyberAI-Token", auth_token=TOKEN)
        self.assertEqual(receipt["http_status"], 200)
        self.assertEqual(receipt["response"]["assessment"], assess_scan(message["scan_result"]))

    def test_utf8_body_and_optional_auth_header(self):
        receipt = post_json({"evidence": "café — observation"}, self.url + "/echo",
                            auth_header="X-Test-Token", auth_token="example-only")
        self.assertEqual(receipt["response"], {"body": {"evidence": "café — observation"}, "token": "example-only"})

    def test_redirect_never_reaches_second_endpoint(self):
        before = self.trap_hits
        with self.assertRaisesRegex(DeliveryError, "redirect"):
            post_json({"data": "private"}, self.url + "/redirect")
        self.assertEqual(self.trap_hits, before)

    def test_empty_invalid_and_oversize_responses_are_not_success_receipts(self):
        for endpoint in ("/empty", "/html", "/large"):
            with self.subTest(endpoint=endpoint), self.assertRaises(DeliveryError):
                post_json({}, self.url + endpoint)

    def test_http_error_reported_without_response_body_or_secret(self):
        with self.assertRaisesRegex(DeliveryError, "HTTP 401") as caught:
            post_json(build_scan_message(fixture()), self.url + "/api/rae/assess",
                      auth_header="X-CyberAI-Token", auth_token="wrong-secret")
        self.assertNotIn("wrong-secret", str(caught.exception))


class SenderTests(unittest.TestCase):
    def test_bad_destination_timeout_auth_and_nan_fail_before_network(self):
        with patch("n8n_client.build_opener") as opener:
            for url in (None, "file:///tmp/x", "https://user:pass@example.invalid/hook", "http://x:999999/", "http://x/\nhook"):
                with self.assertRaises(ValueError):
                    post_json({}, url)
            for timeout in (0, -1, True, float("nan"), float("inf")):
                with self.assertRaises(ValueError):
                    post_json({}, "http://example.invalid/hook", timeout=timeout)
            with self.assertRaises(ValueError):
                post_json({}, "http://example.invalid/hook", auth_header="X-Test", auth_token="bad\r\nheader")
            with self.assertRaises(ValueError):
                post_json({"score": float("nan")}, "http://example.invalid/hook")
            opener.assert_not_called()

    def test_connection_failure_sends_once_and_explains_uncertain_delivery(self):
        with patch("n8n_client.build_opener") as opener:
            opener.return_value.open.side_effect = URLError("private host details")
            with self.assertRaisesRegex(DeliveryError, "may already have run") as caught:
                post_json({}, "http://example.invalid/hook")
            self.assertNotIn("private host details", str(caught.exception))
            self.assertEqual(opener.return_value.open.call_count, 1)

    def test_library_helper_wraps_raw_evidence_and_passes_environment(self):
        env = {"CYBERAI_N8N_SCAN_WEBHOOK_URL": "http://example.invalid/hook",
               "CYBERAI_N8N_HEADER_NAME": "X-Team-Token", "CYBERAI_N8N_HEADER_VALUE": "test-only"}
        with patch.dict(os.environ, env, clear=True), patch("send_scan.post_json", return_value={}) as send:
            send_scan_result(fixture(), input_origin="user_supplied_scan", scan_id="scan-123")
        message, url = send.call_args.args
        self.assertEqual(url, env["CYBERAI_N8N_SCAN_WEBHOOK_URL"])
        self.assertEqual(message["scan_id"], "scan-123")
        self.assertEqual(message["scan_result"], fixture())
        self.assertEqual(send.call_args.kwargs["auth_header"], "X-Team-Token")

    def test_cli_saves_receipt_after_one_send(self):
        receipt = {"http_status": 200, "delivery_status": "response_received", "response": {"assessment": {}}}
        with tempfile.TemporaryDirectory() as directory, patch("send_scan.send_scan_result", return_value=receipt) as send:
            output = Path(directory) / "receipt.json"
            with redirect_stdout(io.StringIO()):
                main([str(ROOT / "fixtures/synthetic_completed_response.json"), "--output", str(output),
                      "--input-origin", "synthetic_test_data"])
            self.assertEqual(json.loads(output.read_text()), receipt)
            self.assertEqual(send.call_count, 1)

    def test_cli_missing_file_does_not_send(self):
        with patch("send_scan.send_scan_result") as send, redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                main([str(ROOT / "missing-example.json")])
            self.assertEqual(caught.exception.code, 2)
            send.assert_not_called()

    def test_save_failure_does_not_retry_and_says_response_was_received(self):
        with tempfile.TemporaryDirectory() as directory, patch("send_scan.send_scan_result", return_value={"http_status": 200}) as send:
            error = io.StringIO()
            with redirect_stderr(error), self.assertRaises(SystemExit):
                main([str(ROOT / "fixtures/synthetic_completed_response.json"), "--output", directory])
            self.assertIn("n8n returned a response", error.getvalue())
            self.assertEqual(send.call_count, 1)


if __name__ == "__main__":
    unittest.main()
