import ast
import tempfile
import unittest
from pathlib import Path
from aegis.agentguard import classify_permissions

class PermissionTests(unittest.TestCase):
    def _classify(self, source):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); path=root/"app.py"; path.write_text(source)
            tree=ast.parse(source); fn=next(n for n in tree.body if isinstance(n, ast.FunctionDef))
            return classify_permissions(fn,path,root)
    def test_positive_permissions(self):
        p=self._classify('def tool_fn(path):\n    value = open(path, "w")\n    subprocess.run(["echo"])\n    urllib.request.urlopen("https://example.com")\n    key = os.getenv("API_KEY")\n    return value\n')
        self.assertTrue(p["write"]); self.assertTrue(p["filesystem"]); self.assertTrue(p["execute"]); self.assertTrue(p["network"]); self.assertTrue(p["credentials"])
    def test_negative_no_permissions(self):
        p=self._classify('def tool_fn(value):\n    return value + 1\n')
        self.assertFalse(any(p.values()))
