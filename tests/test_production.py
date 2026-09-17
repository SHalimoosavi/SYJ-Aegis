import json
import tempfile
import unittest
from pathlib import Path

from aegis.cli import main
from aegis.production import (
    build_sarif,
    create_baseline,
    evaluate_ci,
    finding_fingerprint,
    load_baseline,
    load_suppressions,
    write_baseline,
    write_sarif,
)
from aegis.scanner import scan


class ProductionHardeningTests(unittest.TestCase):
    def _project(self, root: Path) -> Path:
        project = root / "project"
        project.mkdir()
        (project / "app.py").write_text(
            "from openai import OpenAI\n"
            "client = OpenAI()\n"
            "def run(user_input):\n"
            "    return client.chat.completions.create(\n"
            "        model='demo',\n"
            "        messages=[{'role': 'user', 'content': user_input}],\n"
            "    )\n",
            encoding="utf-8",
        )
        return project

    def test_fingerprint_is_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = self._project(Path(tmp))
            _, findings = scan(project)
            self.assertTrue(findings)
            first = finding_fingerprint(findings[0])
            second = finding_fingerprint(findings[0].to_dict())
            self.assertEqual(first, second)
            self.assertEqual(len(first), 64)

    def test_sarif_contains_evidence_locations_and_fingerprints(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = self._project(Path(tmp))
            _, findings = scan(project)
            sarif = build_sarif(findings)

            self.assertEqual(sarif["version"], "2.1.0")
            run = sarif["runs"][0]
            self.assertEqual(run["tool"]["driver"]["name"], "SYJ-AEGIS")
            self.assertTrue(run["results"])

            for result in run["results"]:
                self.assertIn("ruleId", result)
                self.assertIn("locations", result)
                self.assertIn("fingerprints", result)
                location = result["locations"][0]["physicalLocation"]
                self.assertTrue(location["artifactLocation"]["uri"])
                self.assertGreater(location["region"]["startLine"], 0)

    def test_baseline_removes_existing_findings_from_ci_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = self._project(Path(tmp))
            _, findings = scan(project)
            baseline = create_baseline(findings)
            fingerprints = {x["fingerprint"] for x in baseline["findings"]}

            summary = evaluate_ci(findings, fail_on="high", baseline=fingerprints)
            self.assertFalse(summary["failed"])
            self.assertEqual(summary["actionable_findings"], 0)
            self.assertEqual(summary["baseline_findings"], len(findings))

    def test_location_suppression_removes_exact_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = self._project(Path(tmp))
            _, findings = scan(project)
            self.assertTrue(findings)
            first = findings[0].to_dict()
            evidence = first["evidence"]
            location = (
                first["rule_id"],
                evidence["file"],
                evidence["line"],
            )
            summary = evaluate_ci(
                findings,
                fail_on="high",
                suppression_locations={tuple(location)},
            )
            self.assertLess(summary["suppressed_findings"], 1 + len(findings))
            self.assertTrue(summary["suppressed_findings"] >= 1)

    def test_new_high_finding_fails_ci_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = self._project(Path(tmp))
            _, findings = scan(project)
            summary = evaluate_ci(findings, fail_on="high")
            self.assertTrue(summary["failed"])
            self.assertGreaterEqual(summary["actionable_findings"], 1)

    def test_none_threshold_never_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = self._project(Path(tmp))
            _, findings = scan(project)
            summary = evaluate_ci(findings, fail_on="none")
            self.assertFalse(summary["failed"])
            self.assertEqual(summary["actionable_findings"], 0)

    def test_cli_ci_writes_sarif_and_baseline(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = self._project(root)
            baseline = project / "baseline.json"
            sarif = project / "results.sarif"

            rc = main([
                "ci",
                str(project),
                "--baseline",
                str(baseline),
                "--sarif",
                str(sarif),
                "--update-baseline",
                "--fail-on",
                "high",
            ])
            self.assertEqual(rc, 0)
            self.assertTrue(baseline.is_file())
            self.assertTrue(sarif.is_file())

            baseline_fingerprints = load_baseline(baseline)
            self.assertTrue(baseline_fingerprints)
            data = json.loads(sarif.read_text(encoding="utf-8"))
            self.assertEqual(data["version"], "2.1.0")

    def test_suppression_file_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "suppressions.json"
            path.write_text(
                json.dumps(
                    {
                        "version": "phase6",
                        "suppressions": [
                            {
                                "rule_id": "AEGIS-AI-002",
                                "file": "app.py",
                                "line": 4,
                                "reason": "Reviewed test fixture",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            fingerprints, locations, reasons = load_suppressions(path)
            self.assertEqual(fingerprints, set())
            self.assertEqual(locations, {("AEGIS-AI-002", "app.py", 4)})
            self.assertTrue(reasons)


if __name__ == "__main__":
    unittest.main()
