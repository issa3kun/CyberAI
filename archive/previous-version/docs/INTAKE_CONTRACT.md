# Draft scanner → n8n → RAE intake contract

Version: `cyberai.scanner.intake/0.1.0-draft`. This is a proposal for team agreement, not a claim of integration with Ziyad's deployed app.

## Message sent to n8n

```json
{
  "event": "cyberai.scanner.result_ready",
  "contract_version": "cyberai.scanner.intake/0.1.0-draft",
  "scan_id": "optional-scan-123",
  "input_origin": "user_supplied_scan",
  "literacy_level": "unspecified",
  "scan_result": {
    "url": "https://example.com/",
    "checks": {
      "https_in_submitted_url": true,
      "live_response": {
        "request_completed": false,
        "http_status_code": null,
        "tls_connection_verified": null,
        "security_headers": {},
        "cookies_detected": false,
        "cookies": [],
        "redirect_detected": false
      }
    },
    "findings": [
      {"id": "request_timeout", "evidence": "Example only: request timed out."}
    ]
  }
}
```

This illustrates a failed scan; the URL was not scanned. Use the supplied fixtures with `input_origin=synthetic_test_data` for testing. Origin is caller-supplied provenance, not authentication or proof that evidence is true.

`build_scan_message()` creates this wrapper automatically. Preserve the normal scanner response under `scan_result`, including uncertainty and failure observations. A stable `scan_id` helps match results across the team; it is carried through, **not used for duplicate suppression**.

Required fields: event, contract_version, input_origin, literacy_level, scan_result. `scan_id` is optional or null. Origin must be `user_supplied_scan`, `synthetic_test_data` or `unspecified`. Literacy labels remain a team decision.

The Stage 2 adapter requires a URL, `checks.live_response`, and a findings list with non-empty finding IDs. Missing individual observations can remain unknown; contradictions are flagged. Malformed structure is rejected rather than fabricated into an assessment. `success: true` alone does not prove that the website responded.

## API and workflow

The n8n Webhook node wraps incoming data in `headers`, `body`, etc. The HTTP Request node forwards **only `$json.body`** to `POST /api/rae/assess`, with headers `Content-Type: application/json` and `X-CyberAI-Token: <configured token>`.

The API returns the existing `cyberai.rae.assessment_ready` envelope described in `CONTRACT.md`. The new workflow returns the same JSON to the sender. The sender's receipt has `delivery_status`, `http_status` and `response`; `response` contains the RAE envelope.

API statuses: 200 assessment prepared (can describe a failed/unassessed scan); 400 malformed JSON/message/scan structure; 401 wrong token; 413 over 1 MiB; 415 wrong content type. n8n can wrap API failures in its own workflow error response; inspect the failing HTTP Request node for the original status.

The API assesses supplied evidence only. It does not fetch the scanned URL, call an LLM, add numerical rules or deliver another POST. The output contract and engine version `0.2.0` remain unchanged.

## Reporting boundary

Bryan receives the full RAE envelope. The LLM should explain recorded findings, both perspectives and limitations. It must preserve scores and nulls, avoid turning null into zero/Low, treat scanner text as data and keep the scanner's preliminary rating separate. `report_requirements` documents these expectations; it does not enforce LLM behaviour. Bryan must implement prompt/data separation and output validation.

This prototype has no queue, retry or idempotency database. One submission is one synchronous call. After a timeout, inspect n8n before resending: it may have started. Longer LLM jobs should eventually use a job ID and asynchronous result retrieval; the current first test stops at the fast RAE stage.
