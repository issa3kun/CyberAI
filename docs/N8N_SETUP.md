# Start here: Windows setup and team handoff

The first milestone is **raw scanner evidence in → RAE assessment out through n8n**. Keep your existing two-node **CyberAI RAE Connection Test** as your working connection test.

This package adds a separate workflow. It stops before the LLM so you can check the RAE input/output first. No remote website scans or paid AI calls are needed for this test.

## 1. Extract and check this package

Extract the ZIP into a new folder. In VS Code open the inner `cyberai-risk-engine` folder. The terminal's folder must contain `rae_api.py`, `send_scan.py` and `stage2_engine.py`.

```powershell
python -m pip install -r requirements-n8n.txt
python -m unittest -v
```

Expected: `Ran 68 tests` and `OK`. If you get zero tests, change into the inner folder first. These tests check the code, not your running n8n installation.

## 2. Start the local RAE API — terminal A

n8n needs an address it can call to run the RAE. `rae_api.py` supplies that address while you test. Generate a private token and start it:

```powershell
$env:CYBERAI_RAE_API_TOKEN = python -c "import secrets; print(secrets.token_urlsafe(32))"
$env:CYBERAI_RAE_API_TOKEN = python rae_api.py --host 0.0.0.0 --port 5001
```

Copy the displayed token into the n8n credential in step 3. Keep it out of screenshots and shared files. The variable is set only in this terminal; when reopening it later, reuse the token stored in n8n or update both ends with a new token.

Leave terminal A running. `0.0.0.0` lets Docker Desktop reach this prototype service; it is a listening address, not a URL to paste into n8n. The Flask development-server message is expected for this local test. For shared hosting, register the Blueprint in the team's backend and use its deployment server.

Optional browser check: `http://localhost:5001/api/rae/health` should return JSON with `status: ready`. This checks the process, not the scoring.

## 3. Import the new n8n workflow

1. Open `http://localhost:5678` with Docker container `cyberai-n8n` running.
2. Create a **new workflow**, open its menu and choose **Import from File**.
3. Select `n8n/CyberAI_Scanner_Intake.json` from this package.
4. Open **Assess scan with RAE**. Create/select a **Header Auth** credential. Set its **Name** to `X-CyberAI-Token` and **Value** to the token from terminal A. Save and select it. Authentication is **Generic Credential Type**, type **Header Auth**.
5. Verify the URL is `http://host.docker.internal:5001/api/rae/assess`, method POST, body JSON, expression `{{ JSON.stringify($json.body) }}`. These are already set in the imported file.
6. Verify **Receive scanner result** uses POST, path `cyberai-scanner-intake`, and responds **Using Respond to Webhook Node**. **Return RAE assessment** should respond with JSON using `{{ JSON.stringify($json) }}`.
7. **Publish** the workflow. Copy its production URL if it differs from the one below.

The credential is deliberately absent from the export; selecting it is required. The JSON/template configuration has been checked, but this workflow has not yet run in your n8n instance.

Docker Desktop supplies `host.docker.internal` so a container can reach your Windows computer. `localhost:5001` inside n8n would refer to the container itself. Keep the two addresses distinct.

## 4. Send a raw fixture — terminal B

Open another PowerShell terminal in the same project folder:

```powershell
$env:CYBERAI_N8N_SCAN_WEBHOOK_URL = "http://localhost:5678/webhook/cyberai-scanner-intake"
python send_scan.py fixtures/synthetic_completed_response.json --input-origin synthetic_test_data --scan-id demo-001 --output demo-001-receipt.json
```

Expected terminal message:

```text
Response received (HTTP 200). Saved demo-001-receipt.json
```

In n8n, open the latest execution. **All three nodes** should be green. Inspect the HTTP Request node's output and the receipt file:

| Receipt field | What it means |
|---|---|
| `http_status: 200` | The sender received an HTTP response |
| `response.event: cyberai.rae.assessment_ready` | The response contains RAE output, not the old static acknowledgement |
| `response.scan_id: demo-001` | Your supplied ID survived the journey |
| `response.is_synthetic_test_data: true` | This is a fixture test |
| `response.assessment.scan.status: completed_initial_response` | The fixture says an initial HTTP response was received |
| `response.assessment.perspectives.visitor` and `.website_owner` | Both assessment perspectives are present |
| `overall_risk.risk_score: null` and `risk_level: null` | Rules/aggregation remain pending; this is not a zero or Low rating |

Then try the failed-scan fixture:

```powershell
python send_scan.py fixtures/synthetic_timeout.json --input-origin synthetic_test_data --scan-id demo-timeout --output demo-timeout-receipt.json
```

The HTTP call can succeed with 200 while `response.assessment.scan.status` is `failed`. The RAE processed evidence of a failed scan; it did not successfully scan the website. Scores remain unavailable.

**Use `fixtures/`, not `webhook_examples/`, with send_scan.py.** The latter files are already-assessed RAE output. For a Test URL (`/webhook-test/`), click Execute/Listen before each request. Publishing and using `/webhook/` avoids that one-call registration issue.

## 5. What Ziyad needs to provide and change

First, get a complete saved JSON response from his current `/api/scan`, including a failed-scan example. Send those raw files through `send_scan.py` before modifying his app. Keep actual observations separate from synthetic fixtures.

To call the sender from his code, put `scan_message.py`, `n8n_client.py` and `send_scan.py` beside his app. After his existing scanner returns a dictionary:

```python
from send_scan import send_scan_result

# scan_result = dictionary returned by his existing scanner.
# Set CYBERAI_N8N_SCAN_WEBHOOK_URL in his backend's environment.
receipt = send_scan_result(
    scan_result,
    input_origin="user_supplied_scan",
    scan_id=scan_id,  # use his existing job ID, or omit this argument
)
rae_envelope = receipt["response"]
```

This is a handoff example, not an installed patch to his Flask route. Call it once after scanning, not once per finding. Catch `DeliveryError` from `n8n_client` to handle an unconfirmed response and retain the scanner evidence. A delivery failure is not a website risk rating.

He needs to retain `checks.live_response`, stable finding IDs, evidence, per-check failures/uncertainty and cookie attributes without cookie values. In the uploaded `scanner/url_checks.py`, `live_checks["cookies"] = []` resets parsed cookies after inspection. Retain that list, for example with `setdefault("cookies", [])`, and rerun the cookie checks. A scanner `success: true` or preliminary `Low` must not override a failed HTTP request in the evidence.

### Reuse the API in his existing Flask backend

The standalone server is for Imran's local test. For the team's backend, put `rae_api.py`, `scan_message.py`, `stage2_engine.py` and `risk_engine.py` beside Ziyad's app. After creating his Flask `app`, register:

```python
from rae_api import create_rae_blueprint

app.register_blueprint(create_rae_blueprint())
```

Set `CYBERAI_RAE_API_TOKEN` in that backend's environment. Change n8n's HTTP Request URL to that backend's reachable `/api/rae/assess` endpoint. If his existing app is on this same Windows computer at port 5000, n8n uses `http://host.docker.internal:5000/api/rae/assess`; the app must listen for connections from Docker Desktop.

The RAE route must not call `/api/scan` again or POST back to the intake webhook: that would create a loop. Keep one active location for the RAE endpoint during migration.

If `/api/scan` waits for n8n while n8n calls the RAE route in that same backend, the backend needs capacity to handle the callback concurrently. A single synchronous worker can block itself until timeout. Keep the separate test API for this milestone; for the shared deployment, agree a background-job design or verified worker/thread capacity before putting that waiting sender inside the scan request.

## 6. What Bryan needs to do

After the three-node test passes, Bryan can insert LLM/report steps **between Assess scan with RAE and Return RAE assessment**. The HTTP Request node's `$json` contains the complete `cyberai.rae.assessment_ready` envelope.

If his report system is a separate webhook, an additional HTTP Request node can send that envelope to his agreed report URL. His report URL must not be this scanner intake URL. Agree the report response format before changing the final response node.

He must preserve calculated values and nulls, keep visitor/owner sections separate, explain incomplete evidence and treat scanner text as data. This version is unrated where scoring rules are missing. These requirements need prompt handling and output validation; the JSON flags alone do not enforce LLM behaviour.

The sender waits 30 seconds by default, and n8n's prototype RAE call waits 20 seconds. LLM reporting may take longer. `--timeout` can extend a supervised test; longer jobs should use a job ID/queued response and separate report retrieval. Do not add automatic retries without duplicate handling.

## 7. How CIA, DER, CSA and other references fit

n8n carries evidence between the parts. The RAE applies your adapted CSA method:

- **DER → likelihood:** Discoverability, Exploitability and Reproducibility, rated 1–5. Rounded average gives likelihood.
- **CIA → impact:** Confidentiality, Integrity and Availability. The highest property rating gives impact.
- **Score:** likelihood × impact. The CSA sample matrix maps the likelihood/impact pair to a risk band.
- **Two perspectives:** visitor harm and website-owner harm need separate justified scenarios. OWASP or other references can support those rules; n8n does not automatically perform framework checks.

Stage 1 implements arithmetic for supplied ratings. Stage 2/2.1 does not yet map scanner findings to justified DER/CIA ratings or aggregate findings into overall website risk. Build those rules after the evidence path works. Preserve unsupported findings and uncertainty instead of asking the LLM to invent ratings.

## 8. Access from other computers

The published local workflow runs repeatedly while Docker/n8n and the API are running. It still lives on your computer. Ziyad's `localhost` means **his** computer; an app on Render cannot reach your laptop's localhost.

For remote testing, agree one reachable shared deployment. Use its HTTPS addresses and authentication rather than publishing these local prototype ports openly. Community Edition can run this webhook/HTTP workflow; it does not supply hosting or the team's report code automatically.

The current intake Webhook has authentication None for your local test. If you later enable Header Auth on that node, the Python sender supports:

```powershell
$env:CYBERAI_N8N_HEADER_NAME = "X-Team-Token"
$env:CYBERAI_N8N_HEADER_VALUE = "<value from the intake webhook credential>"
```

These optional values authenticate the sender **to n8n**. They are separate from `CYBERAI_RAE_API_TOKEN`, which authenticates **n8n to the RAE**. Leave them unset for the current local template.

## Troubleshooting

| Symptom | Check |
|---|---|
| Cannot import Flask | Install requirements with the same `python` used to start the API |
| 404 webhook not registered | New path, published workflow, production URL; or re-arm the test listener |
| Old static acknowledgement returns | Use `/webhook/cyberai-scanner-intake`, not your original test workflow URL |
| HTTP Request credential missing | Create/select Header Auth with name `X-CyberAI-Token` |
| RAE returns 401 | Credential value must match the API's environment token |
| n8n cannot reach port 5001 | Keep terminal A running; check host.docker.internal, port and Windows/Docker networking/firewall permissions for Python |
| RAE returns 400 | Forward `$json.body`, use raw fixtures, inspect the structured API error |
| Empty/non-JSON reply | Final Respond node must return JSON; initial Webhook must use responseNode |
| Timeout | Check execution history before resending; the job may already have run |
| Scores are null | Expected until finding rules and aggregation are implemented |

## Reference documentation

- n8n HTTP Request: https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.httprequest/
- n8n import/export: https://docs.n8n.io/workflows/export-import/
- Docker host access: https://docs.docker.com/desktop/features/networking/networking-how-tos/
- Flask Blueprints: https://flask.palletsprojects.com/en/stable/blueprints/

See `STAGE_2_1_TEST_RESULTS.txt` for verification limits. The tests do not contact your live n8n or Bryan's LLM.
