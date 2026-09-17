import tempfile
import unittest
from pathlib import Path
from aegis.ai_firewall import analyze_file

class PIIExposureTests(unittest.TestCase):
    def _scan(self, source):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); path = root / "app.py"; path.write_text(source)
            return analyze_file(path, root)

    def test_positive_pii_to_sensitive_sinks(self):
        findings = self._scan('def expose(email):\n    logging.info("customer=%s", email)\n    client.responses.create(input=email)\n    urllib.request.urlopen(email)\n')
        self.assertTrue(any(f.rule_id == "AEGIS-AI-003" for f in findings))
        self.assertTrue(all(f.confidence in {"LOW", "MEDIUM"} for f in findings))

    def test_negative_non_pii(self):
        findings = self._scan('def safe(value):\n    logging.info("status=%s", value)\n    client.responses.create(input="non-sensitive status")\n')
        self.assertEqual(findings, [])

if __name__ == "__main__":
    unittest.main()
