import tempfile,unittest
from pathlib import Path
from aegis.secrets import scan_file
class SecretScannerTests(unittest.TestCase):
    def test_positive(self):
        with tempfile.TemporaryDirectory() as td:
            r=Path(td); p=r/"config.py"; secret="sk_TEST_1234567890abcdef"; p.write_text(f"OPENAI_API_KEY={secret}\n")
            f=scan_file(p,r); self.assertEqual(len(f),1); self.assertEqual(f[0].evidence.file,"config.py"); self.assertEqual(f[0].evidence.line,1); self.assertNotIn(secret,f[0].description)
    def test_negative_placeholder(self):
        with tempfile.TemporaryDirectory() as td:
            r=Path(td); p=r/"example.env"; p.write_text("OPENAI_API_KEY=your_api_key_here\n"); self.assertEqual(scan_file(p,r),[])
    def test_private_key(self):
        with tempfile.TemporaryDirectory() as td:
            r=Path(td); p=r/"key.txt"; p.write_text("-----BEGIN PRIVATE KEY-----\n"); f=scan_file(p,r); self.assertEqual(len(f),1); self.assertEqual(f[0].evidence.line,1)
