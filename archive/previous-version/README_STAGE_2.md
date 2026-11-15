# CyberAI Risk Assessment Engine Stage 2

Stage 2 connects Imran's RAE to Ziyad's current nested scanner JSON and prepares a draft webhook payload for Bryan. It keeps visitor and website-owner assessments separate. It preserves the original Stage 1 calculation code and tests.

The new part handles evidence and integration data. It does not yet assign numerical scores to real findings. Missing scores are deliberately `null`, with a reason. This is not a completed website safety classifier.

## Start in Windows and VS Code

1. Extract this ZIP into a new Stage 2 folder. Keep your existing Stage 1 folder.
2. In VS Code, open the `cyberai-risk-engine` folder containing this README.
3. Open **Terminal > New Terminal**.
4. Use Python 3.10 or later. No pip installs or API keys are required for this RAE package.

First run all tests:

```powershell
python -m unittest -v
```

Expected result: **44 tests, OK**. The original 14 tests still run, including the test with all 25 matrix cells.

Then run the response Imran supplied from Ziyad's Postman test:

```powershell
python run_stage2.py fixtures/footyroom_redirect.json
```

If Windows does not recognise `python`, replace it with `py`.

## What the supplied response should show

- `scan.status` is `partial`: an HTTP 301 redirect response was received.
- `scan.destination_assessed` is `false`: the destination page was not inspected.
- The header observations describe the initial response.
- `cookies_detected` remains false and `cookies` remains empty. This run is not evidence that cookie details were lost.
- The scanner's preliminary `Low` is retained separately with `used_for_scoring: false`.
- `perspectives.visitor` and `perspectives.website_owner` are separate objects. Both have unavailable numerical ratings because scoring rules and overall aggregation are pending.

The supplied response is an example from the conversation, not a new scan run by this package and not a claim about the website's present configuration.

## Prepare Bryan's example JSON

```powershell
python run_stage2.py fixtures/footyroom_redirect.json --webhook --input-origin user_supplied_scan --output bryan_example.json
```

This writes a JSON file. It does not send a webhook. Open it in VS Code to inspect it. The already-generated `webhook_examples` folder contains examples for the supplied redirect and four synthetic test cases.

To inspect a failed scan:

```powershell
python run_stage2.py fixtures/synthetic_timeout.json --webhook --input-origin synthetic_test_data
```

The failed request should retain unavailable ratings and explain the recorded error. A successful API response (`success: true`) is not treated as proof that the website scan completed.

## Files to read first

| File | Purpose |
| --- | --- |
| `stage2_engine.py` | New scanner adapter and draft webhook builder |
| `run_stage2.py` | Command-line runner for the new format |
| `docs/CONTRACT.md` | Proposed fields and their meanings for Ziyad and Bryan |
| `docs/NEXT_STEPS.md` | What is complete and what to develop next |
| `fixtures` | One user-supplied response and clearly identified synthetic cases |
| `webhook_examples` | Prepared JSON examples for Bryan to review |
| `test_stage2_engine.py` | New behavior and integration-contract tests |
| `risk_engine.py` | Original Stage 1 arithmetic and legacy input handling, unchanged |
| `test_risk_engine.py` | Original Stage 1 tests, unchanged |
| `README_STAGE_1.md` | Original Stage 1 instructions and methodology reference |

For the new scanner format, use `run_stage2.py` or import `assess_scan` from `stage2_engine`. The original `risk_engine.py` command still expects its original flat format.

## Connect within Flask later

Ziyad can place the RAE modules alongside his application and call the adapter after his existing URL validation and scanner function:

```python
from stage2_engine import assess_scan, build_webhook_payload

# Run this only after the backend's existing URL validation succeeds.
scanner_result = inspect_url(validated_url)
assessment = assess_scan(scanner_result)
payload = build_webhook_payload(
    assessment,
    input_origin="user_supplied_scan",
    literacy_level="unspecified",
)
```

This is a proposed integration point, not an installed Flask route. The RAE makes no web requests and does not replace the scanner's public-address/SSRF controls. Nothing in this ZIP starts or modifies Ziyad's backend.

## Current limits

- No finding-specific scoring rules or overall aggregation policy are implemented.
- Visitor and owner scoring require different justified harm scenarios; an owner score cannot be inferred from a domain name alone.
- No AdaBoost or SHAP results are consumed because the uploaded backend has no implemented model output contract.
- The webhook contract is a draft for team review. Live delivery, authentication, timeout handling and Bryan's response format remain to be agreed.
- Report-requirement flags are metadata. They do not enforce LLM behavior. Bryan must treat scanner strings as untrusted data and validate preserved scores before displaying a report.
- Cookie values are excluded from structured cookie output. Textual evidence and URLs are retained as supplied and may need upstream redaction before real reports are shared.
- No new live website scans or real webhook deliveries were performed to verify this package. Tests are offline and use fixtures.

## Next milestone

Confirm the input/output contract with Ziyad and Bryan. Then research and implement one visitor scenario and one owner scenario with documented prerequisites, assumptions, D/E/R factors, CIA impact and source references. Keep unsupported scenarios unscored.
