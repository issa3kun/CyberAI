# CyberAI Risk Assessment Engine - Stage 1

This starter implements the calculation mechanics and reads Ziyad's current
scanner dictionary. It uses Python's standard library: no pip installs,
API keys, Flask server or internet access are needed to run it.

**This is a foundation, not a finished website risk assessor.** Real scanner
findings remain unassessed until their scenario rules are justified.

## Start on Windows in VS Code

1. Extract the ZIP into a folder, for example `Documents\CyberAI`.
2. In VS Code, choose **File > Open Folder** and select the extracted
   `cyberai-risk-engine` folder containing this README and `risk_engine.py`.
3. Choose **Terminal > New Terminal**.
4. Run:

```powershell
python risk_engine.py --demo
```

If Windows does not recognise `python`, use `py` instead in these commands.
The code targets Python 3.10 or later.

## Understand the demonstration

The output has two separate sections:

- `arithmetic_example_only`: fictional numbers for learning. The factors
  2, 3 and 4 produce likelihood 3. CIA scores 2, 3 and 1 produce impact 3.
  The product is 9, which the sample CSA matrix labels Medium.
- `scanner_assessment`: reads the bundled fictional scanner output. Hostname
  detection is informational; missing CSP is `needs_rule`, with null scores.

**The fictional numbers are not a CSP rule or a recommendation for any finding.**
Both sample JSON files are invented fixtures, not scans of example.com.
Do not divide the risk score by 25 to claim a probability.

Run either scanner fixture separately:

```powershell
python risk_engine.py sample_scan.json
python risk_engine.py sample_failed_scan.json
```

`null` means a rating is unavailable. It does not mean zero or Low.

## Read the code in this order

1. `calculate_likelihood`: rounds the mean of three already-justified factors.
2. `calculate_risk`: uses the highest CIA rating, then likelihood x impact.
3. `assess_scan`: reads scanner findings and preserves uncertainty.

The scanner's `severity` is retained as `scanner_severity`. Its severity or
supplied scoring fields never control the engine's calculations.
Unknown IDs are `unsupported`. Request failures are `incomplete`.

There are no per-finding scoring rules or overall aggregation policy yet.
An empty findings list therefore never produces a safe/Low verdict.
The scope is the submitted URL and initial response only; no redirects are
followed or inferred. This program itself makes no web requests.

## Run verification

```powershell
python -m unittest -v
```

The tests cover all 25 matrix cells, CIA maximum selection, likelihood
rounding, invalid ratings, every current security finding ID, unknown IDs,
request failures and scanner-supplied scores.

## Future integration point

Once scanner and rule contracts are agreed, the function can be called from
Ziyad's backend:

```python
from risk_engine import assess_scan

scanner_result = inspect_url(url)  # Ziyad's existing function
risk_result = assess_scan(scanner_result)
```

This shows the interface only; it is not a complete Flask route. Bryan's AI
must receive and preserve `not_assessed`, `needs_rule` and `incomplete` states.

## Next development step

Agree one scenario rule: observed condition, credible harm, prerequisites,
existing protections, justified D/E/R and CIA ratings, assumptions and source.
Use a controlled example for validation. Then add that rule and its tests.
Review response context, structured cookie attributes and error types with
Ziyad before assigning real finding scores. Overall aggregation is a separate
design decision; this starter does not choose highest, average or total.

## Methodology reference

CyberAI adapts CSA guidance; it does not claim CII compliance or certification.

- CSA, February 2021 guide: printed pages 11-13 describe likelihood factors
  and their rounded mean; pages 14-15 describe CIA impact and its maximum;
  page 16, Figure 5, provides the sample 5 x 5 matrix used here.
- Official PDF:
  https://isomer-user-content.by.gov.sg/36/016e3838-a9e5-4c6e-a037-546e8b7ad684/Guide-to-Conducting-Cybersecurity-Risk-Assessment-for-CII.pdf
- CSA reference page:
  https://www.csa.gov.sg/legislation/supplementary-references/

The guide does not provide CyberAI-specific scores for missing headers or
cookie attributes. Those remain project decisions requiring justification.
