import tempfile,unittest
from pathlib import Path
from aegis.discovery import discover
class DiscoveryTests(unittest.TestCase):
    def test_positive(self):
        with tempfile.TemporaryDirectory() as td:
            r=Path(td); (r/"app.py").write_text("from fastapi import FastAPI\n"); (r/"requirements.txt").write_text("fastapi==1.0\n"); (r/"Dockerfile").write_text("FROM python:3.12\n")
            x=discover(r); self.assertEqual(x["languages"],[{"name":"Python","file_count":1}]); self.assertIn("FastAPI",x["frameworks"]); self.assertIn("Docker",x["containers"])
    def test_negative(self):
        with tempfile.TemporaryDirectory() as td:
            r=Path(td); (r/"notes.txt").write_text("plain documentation\n"); x=discover(r)
            self.assertEqual(x["languages"],[]); self.assertEqual(x["frameworks"],[]); self.assertEqual(x["containers"],[]); self.assertEqual(x["ci"],[])
