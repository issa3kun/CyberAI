# CyberAI Stage 2 Data Contract

This is a proposal for team review, not a final agreement with Ziyad or Bryan. It prepares two separate assessment perspectives from the scanner version uploaded on 2 November 2026.

## Scanner input

The adapter expects a JSON object with `url`, `checks.live_response` and a `findings` list. It can process the body returned by Ziyad's `/api/scan`, including the extra API envelope fields. API validation-rejection bodies lacking scanner data are rejected, not classified as Low risk.

| Field | Expected content |
| --- | --- |
| `url` | Submitted HTTP/HTTPS URL, without embedded credentials |
| `checks.https_in_submitted_url` | Boolean or null |
| `checks.live_response.request_completed` | Boolean or null; API success is not a substitute |
| `checks.live_response.http_status_code` | Integer 100-599 or null |
| `checks.live_response.tls_connection_verified` | Boolean or null; generic connection errors do not establish a certificate problem |
| `checks.live_response.security_headers` | Named Boolean/null observations for CSP, content-type options, HSTS and framing protection |
| `checks.live_response.cookies_detected` | Whether Set-Cookie headers were observed on the initial response |
| `checks.live_response.cookies` | Cookie name and Secure, HttpOnly, SameSite attributes; no values |
| `checks.live_response.redirect_detected` | Boolean or null |
| `checks.live_response.redirect_target_scheme` | Observed target scheme, if reported; not an inspected destination |
| `findings[].id` | Stable scanner finding ID |
| `findings[].evidence` | Scanner-supplied observation text, treated as untrusted data |
| `findings[].limitation` | Optional scanner-supplied limitation |
| `findings[].severity` | Scanner label retained for traceability; never an RAE score |

Missing observations remain unavailable. Invalid Booleans are not converted by truthiness. A finding claiming a missing header cannot be accepted as consistent evidence when its corresponding check says the header is present.

The scanner's `server_header_present` currently remains at its initialized value without an implemented check. Stage 2 ignores it as evidence and reports a warning. Raw header values, owner asset context and structured links from cookie findings to particular cookies are not available in the present input contract.

## Assessment output

`assess_scan` returns scanner scope, findings, validation issues, limitations and two independent perspective objects. `input_sha256` identifies the exact input content; it is not a unique job ID or a measure of evidence truth.

| Path | Meaning |
| --- | --- |
| `scan.status` | Initial-response assessment completeness |
| `scan.http_response_received` | Whether consistent evidence supports a received response |
| `scan.scope` | Submitted URL and initial response only |
| `scan.destination_assessed` | False for this scanner version |
| `findings[].finding_ref` | Stable position-based reference within this report; duplicate IDs are retained |
| `findings[].validation_status` | Handling state of the observation |
| `findings[].perspectives.visitor` | Unscored visitor scenario fields and reason |
| `findings[].perspectives.website_owner` | Separate unscored owner scenario fields and reason |
| `perspectives.visitor.overall_risk` | Overall visitor assessment status and nullable rating |
| `perspectives.website_owner.overall_risk` | Overall owner assessment status and nullable rating |
| `validation_issues` | Invalid fields, contradictory observations and known scanner limitations |
| `scanner_preliminary_assessment` | Non-authoritative scanner summary; `used_for_scoring` is false |

No numerical finding rules or aggregation policy are implemented. Every likelihood factor, CIA rating, likelihood, impact, risk score and risk level remains null in the Stage 2 adapter. The existing Stage 1 calculation functions are still usable with independently justified numerical inputs.

## Status meanings

| Scan status | Meaning |
| --- | --- |
| `completed_initial_response` | Initial response available for the limited scanner checks; not proof of website safety |
| `partial` | A redirect, non-2xx response or missing cookie details limits the assessment |
| `failed` | Request failed or did not complete, without contradictory input |
| `incomplete` | Request outcome or response metadata is insufficient |
| `inconsistent` | Invalid or contradictory input was detected |

| Finding status | Meaning |
| --- | --- |
| `informational` | Metadata or redirect observation, not a scored scenario |
| `needs_rule` | A recognized observation exists; reviewed scoring is still required |
| `incomplete` | Response-dependent finding or recorded request failure lacks a completed HTTP assessment |
| `insufficient_evidence` | Required textual or structured evidence is unavailable |
| `conflicting_evidence` | Finding contradicts its supporting checks or scope |
| `unsupported` | No handler exists for the ID; observation remains visible |

Overall statuses describe why a rating is unavailable: `needs_rules`, `insufficient_evidence`, `invalid_evidence`, `unsupported_findings` or `not_assessed`. These are not numerical risk levels. `null` means unavailable, not zero or Low.

## Webhook envelope

`build_webhook_payload` wraps an assessment. It does not deliver it.

| Field | Meaning |
| --- | --- |
| `event` | `cyberai.rae.assessment_ready` |
| `contract_version` | `cyberai.rae.webhook/0.2.0-draft` |
| `scan_id` | Optional ID supplied by the caller; null until one is provided |
| `input_origin` | `user_supplied_scan`, `synthetic_test_data` or `unspecified` |
| `is_synthetic_test_data` | True for explicit synthetic input, false for a user-supplied scan, null when origin is unspecified |
| `report_preferences.literacy_level` | Pass-through frontend/team label; default unspecified |
| `report_preferences.perspectives` | Visitor and website_owner |
| `assessment` | Structured RAE output |
| `report_requirements` | Proposed report-preservation requirements, not an enforcement mechanism |

Bryan should explain recorded observations, missing evidence and limitations. He should not invent error causes, treat preliminary scanner labels as final ratings, replace nulls with Low, merge the two perspectives or calculate scores with the LLM.

Before live integration, agree the webhook URL/method/authentication, input and output versions, supported literacy labels, synchronous response or polling behavior, timeout/failure handling and score-validation behavior. Do not put secret keys in this contract or sample files.
