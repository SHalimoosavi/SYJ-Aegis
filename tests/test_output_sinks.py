import tempfile
import unittest
from pathlib import Path
from aegis.ai_firewall import analyze_file

class OutputSinkTests(unittest.TestCase):
    def _scan(self, source):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); path = root / "app.py"; path.write_text(source)
            return analyze_file(path, root)

    def test_positive_llm_output_to_dangerous_sinks(self):
        findings = self._scan('def execute(request):\n    result = client.responses.create(input="fixed prompt")\n    subprocess.run(["sh", "-c", result])\n    cursor.execute(f"SELECT {result}")\n    open(result, "w")\n')
        self.assertTrue(findings)
        self.assertTrue(all(f.rule_id == "AEGIS-AI-017" for f in findings))
        self.assertTrue(all(f.severity == "CRITICAL" for f in findings))
        self.assertTrue(all(f.confidence == "MEDIUM" for f in findings))

    def test_negative_safe_sink(self):
        findings = self._scan('def safe(request):\n    result = client.responses.create(input="fixed prompt")\n    print(result)\n')
        self.assertEqual(findings, [])

if __name__ == "__main__":
    unittest.main()
