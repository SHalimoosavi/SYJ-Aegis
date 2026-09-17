import tempfile
import unittest
from pathlib import Path
from aegis.ai_firewall import analyze_file

class PromptSecurityTests(unittest.TestCase):
    def _scan(self, source):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); path = root / "app.py"; path.write_text(source)
            return analyze_file(path, root)

    def test_positive_prompt_injection_and_secret_prompt(self):
        findings = self._scan('def run(user_input):\n    system_prompt = "system api_key=THIS_IS_A_REAL_SECRET_VALUE"\n    prompt = system_prompt + user_input\n    return client.responses.create(input=prompt)\n')
        ids = [f.rule_id for f in findings]
        self.assertIn("AEGIS-AI-001", ids)
        self.assertIn("AEGIS-AI-002", ids)

    def test_negative_trusted_prompt(self):
        findings = self._scan('def run(user_input):\n    system_prompt = "system: follow approved policy"\n    return client.responses.create(input=system_prompt)\n')
        self.assertEqual(findings, [])

if __name__ == "__main__":
    unittest.main()
