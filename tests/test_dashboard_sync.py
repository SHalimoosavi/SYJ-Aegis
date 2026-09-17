import json
import tempfile
import unittest
from pathlib import Path
import importlib.util

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("build_docs",ROOT/"scripts"/"build_docs.py")
mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)

class DashboardSyncTests(unittest.TestCase):
    def test_phase_mapping_includes_governance(self):
        self.assertEqual(mod.phase_module("AEGIS-GOV-AEGIS-AI-003","Governance")[0],"Phase 5")
    def test_metrics_reads_governance_and_sarif(self):
        findings={"findings":[
            {"rule_id":"AEGIS-SECRET-001","severity":"HIGH","category":"Secrets"},
            {"rule_id":"AEGIS-AI-002","severity":"HIGH","category":"Prompt Security"},
        ]}
        gov={"ai_system_register":[{}],"data_map":[{},{}],"risk_register":[{}],
             "control_mapping":[{}],"governance_findings":[{"severity":"HIGH"},{"severity":"LOW"}]}
        sarif={"version":"2.1.0","runs":[{"results":[{},{}]}]}
        ci={"failed":False,"fail_on":"high","actionable_findings":0,"baseline_findings":2,
            "suppressed_findings":0,"total_findings":2}
        m=mod.build_metrics(findings["findings"],gov,sarif,ci)
        self.assertEqual(m["phase"]["Phase 1"],1)
        self.assertEqual(m["phase"]["Phase 3"],1)
        self.assertEqual(m["phase"]["Phase 5"],2)
        self.assertEqual(m["governance"]["systems"],1)
        self.assertEqual(m["ci"]["sarif_results"],2)
        self.assertFalse(m["ci"]["failed"])
    def test_browser_demo_functions_are_present_and_distinct(self):
        page=mod.render({"total":0,"severity":{},"phase":{f"Phase {i}":0 for i in range(1,7)},
                         "module":{},"governance":{"systems":0,"data_flows":0,"risks":0,"controls":0,"findings":0,"severity":{}},
                         "ci":{"failed":False,"fail_on":"high","actionable_findings":0,"baseline_findings":0,"suppressed_findings":0,"total_findings":0,"sarif_results":0,"sarif_version":"2.1.0"}},0)
        self.assertIn("function browserRules",page)
        self.assertIn("BROWSER-SECRET-001",page)
        self.assertIn("BROWSER-SINK-001",page)
        self.assertIn("Browser demonstration only",page)
        self.assertNotIn('id="runScan"',page)
if __name__=="__main__": unittest.main()
