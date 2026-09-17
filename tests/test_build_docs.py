import json
import unittest
from pathlib import Path

from scripts.build_docs import _render_template, compute_metrics


class DashboardBuildTests(unittest.TestCase):
    def test_rendered_dashboard_contains_computed_counts(self):
        fixture = Path(__file__).parent / "fixtures" / "phase4_dashboard" / "findings.json"
        data = json.loads(fixture.read_text(encoding="utf-8"))
        metrics = compute_metrics(data)
        template = (Path(__file__).parents[1] / "docs" / "_template.html").read_text(encoding="utf-8")
        status = {
            "ai_firewall": "merged",
            "agentguard": "merged",
            "aigovern": "planned",
            "phase_4_dashboard": "in_progress",
            "phase_5_aigovern": "planned",
            "phase_6_production_hardening": "planned",
        }
        html = _render_template(template, status, metrics, {"files_scanned": 12})
        self.assertIn(">6</div><div class=\"label\">Total findings", html)
        self.assertIn(">2</div><div class=\"label\">Critical", html)
        self.assertIn(">3</div><div class=\"label\">High", html)
        self.assertIn(">0</div><div class=\"label\">Medium", html)
        self.assertIn(">1</div><div class=\"label\">Low", html)
        self.assertIn("<tr><td>Phase 1</td><td>1</td></tr>", html)
        self.assertIn("<tr><td>Phase 2</td><td>1</td></tr>", html)
        self.assertIn("<tr><td>Phase 3</td><td>4</td></tr>", html)
        self.assertIn(">merged</span>", html)
        self.assertIn(">planned</span>", html)

    def test_template_has_no_external_resources(self):
        template = (Path(__file__).parents[1] / "docs" / "_template.html").read_text(encoding="utf-8").lower()
        self.assertNotIn("<script src=", template)
        self.assertNotIn("<link href=\"http", template)
        self.assertNotIn("https://", template)
        self.assertNotIn("http://", template)

    def test_missing_findings_exits_nonzero_and_fails_cleanly(self):
        import contextlib
        import io
        from unittest import mock
        import scripts.build_docs as build_docs

        missing = build_docs.ROOT / ".aegis" / "missing-findings.json"
        stderr = io.StringIO()
        with (
            mock.patch.object(build_docs, "_run_scan"),
            mock.patch.object(build_docs, "FINDINGS", missing),
            contextlib.redirect_stderr(stderr),
        ):
            rc = build_docs.main()

        self.assertNotEqual(rc, 0)
        self.assertIn("Required scan output missing", stderr.getvalue())
        self.assertIn("Run 'aegis scan .'", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
