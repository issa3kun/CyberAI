# CyberAI RAE Next Steps

Stage 2 completes an offline scanner-adapter prototype and draft report payload. It does not complete risk-scoring methodology or live integration.

## Imran

1. Run the tests and inspect the supplied redirect response using the README commands.
2. Review the proposed contract with Ziyad and Bryan, then record agreed field names and version changes.
3. Define separate visitor and owner risk scenarios. State the affected asset, threat, observable weakness, prerequisites and possible consequence.
4. Research defensible D/E/R and CIA descriptors. The CSA guide supports the calculation mechanics; it does not assign scores to CyberAI's individual observations. OWASP guidance can support the meaning and limits of particular controls.
5. Implement one justified scenario at a time, with evidence requirements, source, assumptions and boundary tests. If owner asset/business information is unavailable, keep that owner's impact unassessed rather than borrowing visitor values.
6. Define overall aggregation independently for each perspective. Include incomplete evidence and unsupported findings without presenting an incomplete report as a safe verdict.
7. Integrate the RAE into the validated Flask workflow, then test Bryan's actual webhook and report response when available.

## Ziyad

- Preserve parsed cookie metadata. In `scanner/url_checks.py`, replace `live_checks["cookies"] = []` after `_inspect_live_response` with `live_checks.setdefault("cookies", [])`.
- Distinguish recorded SSL/TLS failures from generic connection errors, without claiming that every SSL error means an invalid certificate.
- Keep finding IDs and schema changes coordinated with Imran. Consider adding a scanner/schema version and per-check outcomes.
- Add a structured cookie identifier to cookie findings so the engine can link them to the corresponding attribute record.
- Reject non-object request JSON with a clear client error rather than an unhandled server error.
- Confirm future raw header/TLS/DNS evidence and AdaBoost/SHAP output when implemented. Downloaded packages alone do not establish an implemented model.

These are proposed changes for Ziyad. His uploaded backend has not been modified in this package.

## Bryan

- Review the draft contract and JSON examples now; finished model code is not required for this review.
- Keep visitor and owner explanations separate and preserve assessment status, calculated values and nulls.
- Treat supplied evidence as data. Contract flags do not by themselves stop prompt injection or hallucination.
- Make the recorded uncertainty visible. A timeout does not establish a cause beyond the recorded timeout; a generic connection error does not establish a certificate failure.
- Agree the webhook details and provide an example response. Verify model output against the RAE's authoritative numeric fields before display.

## Evidence of individual contribution

Keep the code, unit-test results, contract decisions and scoring-source notes in version control. The included `TEST_RESULTS.txt` records the offline verification for this package. Later live integration results should be recorded separately from synthetic examples.
