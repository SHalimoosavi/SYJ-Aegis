#!/usr/bin/env python3
"""Build the deterministic, self-contained SYJ-AEGIS GitHub Pages dashboard."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path


class BuildError(RuntimeError):
    """Raised when dashboard inputs cannot be produced or loaded."""


ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
TEMPLATE = DOCS / "_template.html"
STATUS = DOCS / "status.json"
FINDINGS = ROOT / ".aegis" / "findings.json"
INVENTORY = ROOT / ".aegis" / "inventory.json"
PERMISSIONS = ROOT / ".aegis" / "permissions.json"
REPORT_SOURCE = ROOT / ".aegis" / "report"
REPORT_DEST = DOCS / "report"
INDEX = DOCS / "index.html"

GENERATED_DIRS = {".aegis", "docs"}


def _copy_scan_source(destination: Path) -> None:
    """Copy the repository into a stable scan snapshot.

    Generated scanner/dashboard output is intentionally excluded so repeated
    dashboard builds scan the same source tree.
    """
    for source in ROOT.iterdir():
        if source.name in GENERATED_DIRS:
            continue

        target = destination / source.name

        if source.is_dir():
            shutil.copytree(
                source,
                target,
                ignore=shutil.ignore_patterns(
                    ".git",
                    ".venv",
                    "venv",
                    "node_modules",
                    "__pycache__",
                    ".mypy_cache",
                    ".pytest_cache",
                    ".tox",
                ),
            )
        else:
            shutil.copy2(source, target)


def _run_scan() -> dict:
    """Run aegis against a stable repository snapshot."""
    with tempfile.TemporaryDirectory(prefix="syj-aegis-dashboard-") as temp_dir:
        scan_root = Path(temp_dir) / "project"
        scan_root.mkdir(parents=True, exist_ok=True)

        _copy_scan_source(scan_root)

        try:
            completed = subprocess.run(
                ["aegis", "scan", "."],
                cwd=scan_root,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except OSError as exc:
            raise BuildError(
                f"Unable to run 'aegis scan .': {exc}"
            ) from exc

        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip()
            raise BuildError(
                "aegis scan . failed"
                + (f": {detail}" if detail else ".")
            )

        try:
            summary = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise BuildError(
                "aegis scan . completed but did not return a valid JSON summary."
            ) from exc

        if not isinstance(summary, dict):
            raise BuildError("aegis scan . returned an invalid scan summary.")

        source_aegis = scan_root / ".aegis"

        if not source_aegis.is_dir():
            raise BuildError(
                "aegis scan . completed but did not produce .aegis/."
            )

        if FINDINGS.exists():
            shutil.rmtree(FINDINGS.parent)

        shutil.copytree(source_aegis, FINDINGS.parent)

        return summary


def _display_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return str(path)


def _load_json(path: Path) -> dict:
    if not path.is_file():
        raise BuildError(
            f"Required scan output missing: {_display_path(path)}. "
            "Run 'aegis scan .' before building the dashboard."
        )

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BuildError(
            f"Unable to read {_display_path(path)}: {exc}"
        ) from exc


def _phase_module(rule_id: str, category: str) -> tuple[str, str]:
    if rule_id.startswith("AEGIS-SECRET-"):
        return "Phase 1", "Secret Detection"
    if rule_id.startswith("AEGIS-AGENCY-"):
        return "Phase 2", "AgentGuard"
    if rule_id.startswith("AEGIS-AI-"):
        return "Phase 3", "AI-Firewall"
    return "Other", category or "Other"


def compute_metrics(findings_data: dict) -> dict:
    findings = findings_data.get("findings")

    if not isinstance(findings, list):
        raise BuildError("findings.json has no valid 'findings' array.")

    severities = Counter()
    phases = Counter()
    modules = Counter()

    for finding in findings:
        if not isinstance(finding, dict):
            raise BuildError("findings.json contains a non-object finding.")

        severity = str(finding.get("severity", "UNKNOWN"))
        category = str(finding.get("category", ""))
        rule_id = str(finding.get("rule_id", ""))

        severities[severity] += 1

        phase, module = _phase_module(rule_id, category)
        phases[phase] += 1
        modules[module] += 1

    return {
        "total": len(findings),
        "severity": dict(sorted(severities.items())),
        "phase": dict(sorted(phases.items())),
        "module": dict(sorted(modules.items())),
    }


def _render_template(
    template: str,
    status: dict,
    metrics: dict,
    discovery: dict,
) -> str:
    replacements = {
        "{{PROJECT_NAME}}": "SYJ-AEGIS",
        "{{TOTAL_FINDINGS}}": str(metrics["total"]),
        "{{CRITICAL_FINDINGS}}": str(
            metrics["severity"].get("CRITICAL", 0)
        ),
        "{{HIGH_FINDINGS}}": str(
            metrics["severity"].get("HIGH", 0)
        ),
        "{{MEDIUM_FINDINGS}}": str(
            metrics["severity"].get("MEDIUM", 0)
        ),
        "{{LOW_FINDINGS}}": str(
            metrics["severity"].get("LOW", 0)
        ),
        "{{FILES_SCANNED}}": str(discovery.get("files_scanned", 0)),
        "{{AI_FIREWALL_STATUS}}": str(status["ai_firewall"]),
        "{{AGENTGUARD_STATUS}}": str(status["agentguard"]),
        "{{AIGOVERN_STATUS}}": str(status["aigovern"]),
        "{{DASHBOARD_STATUS}}": str(status["phase_4_dashboard"]),
        "{{PHASE_5_STATUS}}": str(status["phase_5_aigovern"]),
        "{{PHASE_6_STATUS}}": str(
            status["phase_6_production_hardening"]
        ),
        "{{PHASE_1_COUNT}}": str(
            metrics["phase"].get("Phase 1", 0)
        ),
        "{{PHASE_2_COUNT}}": str(
            metrics["phase"].get("Phase 2", 0)
        ),
        "{{PHASE_3_COUNT}}": str(
            metrics["phase"].get("Phase 3", 0)
        ),
        "{{SECRET_COUNT}}": str(
            metrics["module"].get("Secret Detection", 0)
        ),
        "{{AGENT_COUNT}}": str(
            metrics["module"].get("AgentGuard", 0)
        ),
        "{{AI_COUNT}}": str(
            metrics["module"].get("AI-Firewall", 0)
        ),
    }

    for token, value in replacements.items():
        template = template.replace(token, value)

    return template


def build(project_root: Path = ROOT) -> dict:
    project_root = project_root.resolve()

    if project_root != ROOT:
        raise BuildError(
            "Dashboard build must run from the SYJ-AEGIS repository root."
        )

    scan_summary = _run_scan()

    findings_data = _load_json(FINDINGS)
    inventory_data = (
        _load_json(INVENTORY) if INVENTORY.exists() else {}
    )
    permissions_data = (
        _load_json(PERMISSIONS) if PERMISSIONS.exists() else {}
    )
    status = _load_json(STATUS)

    try:
        template = TEMPLATE.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise BuildError(
            f"Unable to read {_display_path(TEMPLATE)}: {exc}"
        ) from exc

    metrics = compute_metrics(findings_data)

    if not REPORT_SOURCE.is_dir():
        raise BuildError(
            "Required scan report missing: .aegis/report/. "
            "The scan did not produce the expected HTML report."
        )

    DOCS.mkdir(parents=True, exist_ok=True)

    if REPORT_DEST.exists():
        shutil.rmtree(REPORT_DEST)

    shutil.copytree(REPORT_SOURCE, REPORT_DEST)

    files_scanned = scan_summary.get("files_scanned")

    if not isinstance(files_scanned, int) or files_scanned < 0:
        raise BuildError(
            "aegis scan . returned no valid files_scanned value."
        )

    discovery = {"files_scanned": files_scanned}

    html = _render_template(
        template,
        status,
        metrics,
        discovery,
    )

    INDEX.write_text(html, encoding="utf-8")

    return {
        "findings": metrics,
        "inventory": inventory_data,
        "permissions": permissions_data,
        "index": str(INDEX.relative_to(ROOT)),
        "report": str(REPORT_DEST.relative_to(ROOT)),
    }


def main(argv: list[str] | None = None) -> int:
    del argv

    try:
        build()
    except BuildError as exc:
        print(
            f"SYJ-AEGIS dashboard build error: {exc}",
            file=sys.stderr,
        )
        return 1
    except (OSError, UnicodeError) as exc:
        print(
            f"SYJ-AEGIS dashboard build error: {exc}",
            file=sys.stderr,
        )
        return 1

    print("SYJ-AEGIS dashboard build: PASS")
    print(f"Generated: {INDEX.relative_to(ROOT)}")
    print(f"Copied: {REPORT_DEST.relative_to(ROOT)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
