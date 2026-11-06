"""Offline regression tests: matrix, input boundaries and uncertainty handling."""

import copy
import json
from pathlib import Path
import unittest

from risk_engine import assess_scan, calculate_likelihood, calculate_risk


ROOT = Path(__file__).parent


def sample_scan():
    return json.loads((ROOT / "sample_scan.json").read_text(encoding="utf-8"))


class ArithmeticTests(unittest.TestCase):
    def test_all_25_csa_matrix_cells(self):
        # Ordered by impact 1-5, with likelihood 1-5 along each row.
        expected = [
            ["Low", "Low", "Low", "Low", "Medium"],
            ["Low", "Low", "Medium", "Medium", "Medium High"],
            ["Low", "Medium", "Medium", "Medium High", "High"],
            ["Low", "Medium", "Medium High", "High", "Very High"],
            ["Medium", "Medium High", "High", "Very High", "Very High"],
        ]
        for impact in range(1, 6):
            for likelihood in range(1, 6):
                with self.subTest(impact=impact, likelihood=likelihood):
                    result = calculate_risk(likelihood, impact, 1, 1)
                    self.assertEqual(result["risk_score"], likelihood * impact)
                    self.assertEqual(
                        result["risk_level"], expected[impact - 1][likelihood - 1]
                    )

    def test_highest_cia_property_is_not_diluted(self):
        for cia in ((4, 1, 1), (1, 4, 1), (1, 1, 4)):
            with self.subTest(cia=cia):
                result = calculate_risk(4, *cia)
                self.assertEqual(result["impact"], 4)
                self.assertEqual(result["risk_score"], 16)

    def test_likelihood_rounds_both_directions(self):
        self.assertEqual(calculate_likelihood(2, 2, 3), 2)
        self.assertEqual(calculate_likelihood(2, 3, 3), 3)
        self.assertEqual(calculate_likelihood(1, 1, 1), 1)
        self.assertEqual(calculate_likelihood(5, 5, 5), 5)

    def test_invalid_ratings_rejected_in_every_position(self):
        for invalid in (0, 6, -1, 2.5, "3", None, True, False):
            for position in range(4):
                values = [3, 3, 3, 3]
                values[position] = invalid
                with self.subTest(value=invalid, position=position):
                    with self.assertRaises(ValueError):
                        calculate_risk(*values)
            for position in range(3):
                values = [3, 3, 3]
                values[position] = invalid
                with self.assertRaises(ValueError):
                    calculate_likelihood(*values)


class ScannerTests(unittest.TestCase):
    def test_metadata_is_not_a_risk(self):
        result = assess_scan(sample_scan())
        self.assertEqual(result["findings"][0]["assessment_status"], "informational")
        self.assertIsNone(result["findings"][0]["risk_score"])

    def test_all_known_security_ids_await_justified_rules(self):
        ids = (
            "https_not_used", "content_security_policy_missing",
            "content_type_options_missing", "referrer_policy_missing",
            "permissions_policy_missing", "hsts_missing",
            "framing_protection_not_detected", "cookie_security_attributes_missing",
        )
        scan = sample_scan()
        scan["findings"] = [{"id": finding_id} for finding_id in ids]
        result = assess_scan(scan)
        self.assertEqual(result["summary"]["findings_needing_rules"], 8)
        for finding in result["findings"]:
            self.assertEqual(finding["assessment_status"], "needs_rule")
            self.assertIsNone(finding["likelihood"])
            self.assertIsNone(finding["risk_score"])

    def test_failed_scan_is_incomplete_not_low_or_high(self):
        scan = json.loads((ROOT / "sample_failed_scan.json").read_text())
        result = assess_scan(scan)
        self.assertEqual(result["findings"][1]["assessment_status"], "incomplete")
        self.assertIsNone(result["overall_risk"]["risk_level"])

    def test_response_not_confirmed_blocks_response_based_findings(self):
        for response_flag in (False, None, "true", 1):
            scan = sample_scan()
            scan["checks"]["http_response_received"] = response_flag
            result = assess_scan(scan)
            self.assertEqual(result["findings"][1]["assessment_status"], "incomplete")

    def test_failure_finding_overrides_conflicting_response_success(self):
        scan = sample_scan()
        scan["findings"].append({"id": "http_request_failed"})
        result = assess_scan(scan)
        self.assertEqual(result["findings"][1]["assessment_status"], "incomplete")

    def test_unknown_id_stays_unsupported(self):
        scan = sample_scan()
        scan["findings"] = [{"id": "future_check", "severity": "critical"}]
        finding = assess_scan(scan)["findings"][0]
        self.assertEqual(finding["assessment_status"], "unsupported")
        self.assertIsNone(finding["risk_score"])

    def test_scanner_severity_and_scores_cannot_drive_engine_ratings(self):
        scan = sample_scan()
        scan["findings"][1].update({
            "severity": "critical", "likelihood": 5, "impact": 5,
            "risk_score": 25, "risk_level": "Very High",
        })
        finding = assess_scan(scan)["findings"][1]
        self.assertEqual(finding["scanner_severity"], "critical")
        for field in ("likelihood", "impact", "risk_score", "risk_level"):
            self.assertIsNone(finding[field])

    def test_empty_findings_do_not_establish_safety(self):
        scan = sample_scan()
        scan["findings"] = []
        result = assess_scan(scan)
        self.assertEqual(result["overall_risk"]["status"], "not_assessed")
        self.assertIsNone(result["overall_risk"]["risk_score"])

    def test_missing_required_data_is_rejected(self):
        invalid_inputs = [None, [], {}, {"url": "x", "findings": {}},
                          {"url": "x", "findings": [None]},
                          {"url": "x", "findings": [{"id": ""}]},
                          {"url": "x", "findings": [], "checks": []}]
        for scan in invalid_inputs:
            with self.subTest(scan=scan):
                with self.assertRaises(ValueError):
                    assess_scan(scan)

    def test_input_is_not_changed(self):
        scan = sample_scan()
        original = copy.deepcopy(scan)
        assess_scan(scan)
        self.assertEqual(scan, original)


if __name__ == "__main__":
    unittest.main()
