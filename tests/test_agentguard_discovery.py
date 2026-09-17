import tempfile
import unittest
from pathlib import Path
from aegis.agentguard import discover_tools

class ToolDiscoveryTests(unittest.TestCase):
    def test_positive_decorated_tool(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); (root/"app.py").write_text('@tool\ndef lookup(x):\n    """Look up a value."""\n    return x\n')
            tools=discover_tools(root)
            self.assertEqual(len(tools),1)
            self.assertEqual(tools[0]["name"],"lookup")
            self.assertEqual(tools[0]["source"]["line"],2)
            self.assertEqual(tools[0]["description"],"Look up a value.")
    def test_positive_tools_collection(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); (root/"app.py").write_text('def lookup(x):\n    return x\n\nagent = Agent(tools=[lookup])\n')
            self.assertEqual([x["name"] for x in discover_tools(root)],["lookup"])
    def test_negative_unregistered_function(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); (root/"app.py").write_text('def ordinary(x):\n    return x\n')
            self.assertEqual(discover_tools(root),[])
