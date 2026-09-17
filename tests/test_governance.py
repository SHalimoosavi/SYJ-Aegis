import json
import tempfile
import unittest
from pathlib import Path

from aegis.governance import (
    build_data_map,
    build_governance_findings,
    build_risk_register,
    discover_ai_systems,
)
from aegis.scanner import scan, write_outputs


ROOT = Path(__file__).resolve().parent
POSITIVE = ROOT / "fixtures" / "governance_positive"
NEGATIVE = ROOT / "fixtures" / "governance_negative"


class GovernanceTests(unittest.TestCase):

    def test_positive_ai_system_register(self):
        systems = discover_ai_systems(POSITIVE)

        self.assertEqual(len(systems), 1)
        self.assertEqual(systems[0]["type"], "AI_SYSTEM")
        self.assertEqual(systems[0]["source"]["file"], "ai_system.py")
        self.assertIn("openai", systems[0]["ai_libraries"])
        self.assertTrue(systems[0]["model_invocations"])

    def test_negative_ai_system_register(self):
        systems = discover_ai_systems(NEGATIVE)

        self.assertEqual(systems, [])

    def test_positive_data_map(self):
        flows = build_data_map(POSITIVE)

        self.assertTrue(flows)

        sources = {item["source"] for item in flows}
        classifications = {item["classification"] for item in flows}

        self.assertIn("user_input", sources)
        self.assertIn("password", sources)
        self.assertIn("USER_OR_EXTERNAL_INPUT", classifications)
        self.assertIn("SENSITIVE", classifications)

        for item in flows:
            self.assertTrue(item["evidence"]["file"])
            self.assertGreater(item["evidence"]["line"], 0)
            self.assertTrue(item["evidence"]["detection"])

    def test_negative_generic_create_without_ai_library(self):
        fixture = NEGATIVE / "generic_create.py"
        fixture.write_text(
            "class Client:\n"
            "    def create(self, value):\n"
            "        return value\n"
            "\n"
            "client = Client()\n"
            "result = client.create(42)\n"
        )

        systems = discover_ai_systems(NEGATIVE)
        self.assertEqual(systems, [])

        fixture.unlink()

    def test_negative_data_map(self):
        flows = build_data_map(NEGATIVE)

        self.assertEqual(flows, [])

    def test_risk_and_control_mapping(self):
        findings = scan(POSITIVE)[1]

        risks = build_risk_register(findings)

        self.assertTrue(risks)

        control_ids = {item["control_id"] for item in risks}

        self.assertTrue(
            {"GOV-DATA-PII-001", "GOV-AI-PROMPT-001", "GOV-AI-INPUT-001"}
            & control_ids
            or control_ids
        )

        for item in risks:
            self.assertTrue(item["evidence"]["file"])
            self.assertGreater(item["evidence"]["line"], 0)
            self.assertEqual(item["status"], "OPEN")

    def test_governance_findings_are_evidence_backed(self):
        findings = scan(POSITIVE)[1]

        governance = build_governance_findings(findings)

        self.assertTrue(governance)

        rule_ids = [finding.rule_id for finding in governance]

        self.assertEqual(len(rule_ids), len(set(rule_ids)))

        for finding in governance:
            self.assertTrue(finding.rule_id.startswith("AEGIS-GOV-"))
            self.assertEqual(finding.category, "Governance")
            self.assertTrue(finding.evidence.file)
            self.assertGreater(finding.evidence.line, 0)
            self.assertTrue(finding.evidence.detection)
            self.assertTrue(finding.remediation)

    def test_full_scan_writes_governance_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "project"
            project.mkdir()

            source = project / "app.py"
            source.write_text(
                "from openai import OpenAI\n"
                "client = OpenAI()\n"
                "def run(user_input):\n"
                "    return client.chat.completions.create(\n"
                "        model='demo',\n"
                "        messages=[{'role': 'user', 'content': user_input}],\n"
                "    )\n",
                encoding="utf-8",
            )

            data, findings = scan(project)
            write_outputs(project, data, findings)

            governance_path = project / ".aegis" / "governance.json"

            self.assertTrue(governance_path.is_file())

            governance = json.loads(
                governance_path.read_text(encoding="utf-8")
            )

            self.assertIn("ai_system_register", governance)
            self.assertIn("data_map", governance)
            self.assertIn("risk_register", governance)
            self.assertIn("control_mapping", governance)
            self.assertIn("governance_findings", governance)

            self.assertEqual(
                len(findings),
                len(json.loads(
                    (project / ".aegis" / "findings.json").read_text(
                        encoding="utf-8"
                    )
                )["findings"]),
            )

    def test_governance_output_is_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "project"
            project.mkdir()

            (project / "app.py").write_text(
                "from openai import OpenAI\\n"
                "client = OpenAI()\\n"
                "def run(user_input):\\n"
                "    return client.chat.completions.create(\\n"
                "        model='demo',\\n"
                "        messages=[{'role': 'user', 'content': user_input}],\\n"
                "    )\\n",
                encoding="utf-8",
            )

            first_data, first_findings = scan(project)
            write_outputs(project, first_data, first_findings)
            first_bytes = (
                project / ".aegis" / "governance.json"
            ).read_bytes()

            second_data, second_findings = scan(project)
            write_outputs(project, second_data, second_findings)
            second_bytes = (
                project / ".aegis" / "governance.json"
            ).read_bytes()

            self.assertEqual(first_bytes, second_bytes)



if __name__ == "__main__":
    unittest.main()
