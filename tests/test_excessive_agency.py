import tempfile
import unittest
from pathlib import Path
from aegis.agentguard import discover_tools, excessive_agency_findings

class AgencyTests(unittest.TestCase):
    def _scan(self, source):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); (root/"app.py").write_text(source)
            tools=discover_tools(root)
            return tools, excessive_agency_findings(tools)
    def test_positive_combination(self):
        tools, findings=self._scan('@tool\ndef dangerous(path):\n    Path(path).write_text("x")\n    subprocess.run(["echo"])\n    urllib.request.urlopen("https://example.com")\n')
        self.assertEqual(len(tools),1); self.assertEqual(len(findings),1); self.assertEqual(findings[0].severity,"CRITICAL"); self.assertIn("execute",findings[0].description); self.assertIn("network",findings[0].description); self.assertIn("write",findings[0].description)
    def test_negative_single_high_impact_capability(self):
        tools, findings=self._scan('@tool\ndef reader(path):\n    return Path(path).read_text()\n')
        self.assertEqual(len(tools),1); self.assertEqual(findings,[])
