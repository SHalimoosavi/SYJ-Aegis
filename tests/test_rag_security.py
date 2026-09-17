import tempfile
import unittest
from pathlib import Path
from aegis.ai_firewall import analyze_file

class RAGSecurityTests(unittest.TestCase):
    def _scan(self, source):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); path = root / "app.py"; path.write_text(source)
            return analyze_file(path, root)

    def test_positive_unclear_default(self):
        findings = self._scan('import chromadb\ndef retrieve(query):\n    return collection.similarity_search(query)\n')
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "AEGIS-AI-004")
        self.assertIn("Access filtering: UNCLEAR", findings[0].description)
        self.assertIn("REVIEW REQUIRED", findings[0].remediation)

    def test_negative_authorization_indicator(self):
        findings = self._scan('import chromadb\ndef retrieve(query, tenant_id):\n    return collection.similarity_search(query, filter={"tenant_id": tenant_id})\n')
        self.assertEqual(findings, [])

if __name__ == "__main__":
    unittest.main()
