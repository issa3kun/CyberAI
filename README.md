# CyberAI RAE — Stage 2.1: scanner intake through n8n

This adds the connection between Ziyad's scanner, Imran's existing Stage 2 RAE and n8n: a Python sender, a Flask endpoint and a draft workflow to import.

**Read `docs/N8N_SETUP.md` first.** It contains Windows/PowerShell setup, result checks and instructions for both teammates.

## What happens

1. Ziyad's scanner produces its normal JSON evidence.
2. `send_scan.py` wraps the evidence and sends it to the new n8n intake webhook.
3. An n8n HTTP Request node calls the Python RAE endpoint.
4. The RAE checks the evidence and returns the existing two-perspective assessment envelope to n8n.
5. For the first test, n8n returns that envelope to the sender. Bryan can later insert LLM/report nodes before the response.

Your tested **CyberAI RAE Connection Test** workflow remains separate. The RAE does not POST back into its own intake workflow.

## Implementation status

| Item | Status |
|---|---|
| Stage 1 DER/CIA/CSA arithmetic | Existing code, unchanged |
| Stage 2 scanner adapter, uncertainty handling, two perspectives | Existing code, unchanged |
| Python sender and Flask endpoint | Added; tested locally |
| n8n workflow JSON | Added; import, configure a credential and test in your n8n |
| Finding-specific DER/CIA rules and overall aggregation | Still pending; scores remain null |
| Bryan's LLM/report nodes | Team integration still required |
| Shared hosting for different computers | Still required for remote use |

A successful HTTP response is not proof that a website is safe, a score is justified or an AI report is correct.

## New files

| File | Purpose |
|---|---|
| `scan_message.py` | Wraps raw scanner evidence and metadata in a versioned message |
| `n8n_client.py` | Sends one JSON POST and checks its response; no automatic retry |
| `send_scan.py` | One-command sender; also callable from Ziyad's code |
| `rae_api.py` | Exposes `/api/rae/assess`; supplies a Blueprint for Ziyad's Flask app |
| `requirements-n8n.txt` | Flask dependency for the API |
| `n8n/CyberAI_Scanner_Intake.json` | Local three-node workflow, without LLM nodes or embedded secrets |
| `test_n8n_integration.py` | New contract/API/transport tests |
| `docs/N8N_SETUP.md` | Setup, results, handoff and troubleshooting |
| `docs/INTAKE_CONTRACT.md` | Exact draft scanner-to-n8n format |
| `STAGE_2_1_TEST_RESULTS.txt` | Test results and verification limits |

`README_STAGE_2.md` is the original Stage 2 README. Earlier engines, tests, fixtures and documents are retained. `TEST_RESULTS.txt` is the earlier record. Python may regenerate `__pycache__`; it is disposable compiled bytecode and is not included.

**Use `fixtures/*.json` with the new sender.** They contain raw scanner results. Files in `webhook_examples/` are already-prepared RAE output for Bryan, so they are not input to the new scanner intake.

## First checks

Open PowerShell in this folder, containing `rae_api.py`:

```powershell
python -m pip install -r requirements-n8n.txt
python -m unittest -v
```

Expected: **68 tests, OK**. Running from a parent folder may discover zero tests. Use Python 3.10 or newer for this package; development verification used Python 3.12.14 with Flask 3.1.3 and Werkzeug 3.1.9.

## Scanner compatibility

The uploaded scanner clears its parsed cookies in `scanner/url_checks.py` with `live_checks["cookies"] = []` after inspection. Ziyad should retain that list and rerun the cookie checks. The RAE marks detected cookies without details as uncertain; it does not invent attributes.

The API and sender do not change the mathematics. For pending scoring work, see `docs/NEXT_STEPS.md`. All new intake and existing output contracts remain drafts for team agreement.
