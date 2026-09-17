"""Phase 6 production hardening: CI policy, SARIF, baselines, and suppressions."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Iterable

from .models import Finding

PHASE = "phase6"
SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}
FAIL_LEVELS = {"none": None, "low": "LOW", "medium": "MEDIUM", "high": "HIGH", "critical": "CRITICAL"}


def _finding_dict(finding: Finding | dict) -> dict:
    return finding.to_dict() if hasattr(finding, "to_dict") else finding


def finding_fingerprint(finding: Finding | dict) -> str:
    """Return a deterministic identity for one evidence-backed finding."""
    item = _finding_dict(finding)
    evidence = item.get("evidence") or {}
    identity = {
        "rule_id": item.get("rule_id", ""),
        "name": item.get("name", ""),
        "file": evidence.get("file", ""),
        "line": evidence.get("line", 0),
    }
    raw = json.dumps(identity, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _canonical_findings(findings: Iterable[Finding | dict]) -> list[dict]:
    items = [_finding_dict(item) for item in findings]
    return sorted(
        items,
        key=lambda item: (
            str(item.get("rule_id", "")),
            str((item.get("evidence") or {}).get("file", "")),
            int((item.get("evidence") or {}).get("line", 0) or 0),
            str(item.get("name", "")),
            finding_fingerprint(item),
        ),
    )


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid JSON file {path}: {exc}") from exc


def create_baseline(findings: Iterable[Finding | dict]) -> dict:
    records = []
    for finding in _canonical_findings(findings):
        evidence = finding.get("evidence") or {}
        records.append(
            {
                "fingerprint": finding_fingerprint(finding),
                "rule_id": finding.get("rule_id", ""),
                "file": evidence.get("file", ""),
                "line": evidence.get("line", 0),
                "name": finding.get("name", ""),
            }
        )
    records.sort(key=lambda item: (item["fingerprint"], item["rule_id"], item["file"], item["line"], item["name"]))
    return {"version": PHASE, "findings": records}


def write_baseline(path: Path, findings: Iterable[Finding | dict]) -> None:
    _write_json(path, create_baseline(findings))


def load_baseline(path: Path) -> set[str]:
    data = _read_json(path)
    records = data.get("findings", [])
    if not isinstance(records, list):
        raise ValueError(f"baseline {path} has no valid 'findings' array")
    fingerprints = set()
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get("fingerprint"), str):
            raise ValueError(f"baseline {path} contains an invalid finding record")
        fingerprints.add(record["fingerprint"])
    return fingerprints


def _suppression_key(item: dict) -> tuple:
    return (
        item.get("rule_id", ""),
        item.get("file", ""),
        item.get("line", 0),
    )


def load_suppressions(path: Path) -> tuple[set[str], set[tuple], dict[str, str]]:
    data = _read_json(path)
    records = data.get("suppressions", [])
    if not isinstance(records, list):
        raise ValueError(f"suppressions {path} has no valid 'suppressions' array")

    fingerprints = set()
    locations = set()
    reasons = {}

    for record in records:
        if not isinstance(record, dict):
            raise ValueError(f"suppressions {path} contains a non-object record")
        fingerprint = record.get("fingerprint")
        rule_id = record.get("rule_id")
        file = record.get("file")
        line = record.get("line")
        reason = str(record.get("reason", "Explicit suppression"))

        if fingerprint is not None:
            if not isinstance(fingerprint, str) or not fingerprint:
                raise ValueError(f"suppressions {path} contains an invalid fingerprint")
            fingerprints.add(fingerprint)
            reasons[fingerprint] = reason
            continue

        if not (isinstance(rule_id, str) and rule_id and isinstance(file, str) and file and isinstance(line, int) and line >= 1):
            raise ValueError(
                f"suppression in {path} requires fingerprint or rule_id/file/line"
            )
        key = (rule_id, file, line)
        locations.add(key)
        reasons["location:" + "|".join(map(str, key))] = reason

    return fingerprints, locations, reasons


def classify_findings(
    findings: Iterable[Finding | dict],
    baseline: set[str] | None = None,
    suppression_fingerprints: set[str] | None = None,
    suppression_locations: set[tuple] | None = None,
) -> list[dict]:
    baseline = baseline or set()
    suppression_fingerprints = suppression_fingerprints or set()
    suppression_locations = suppression_locations or set()

    result = []
    for finding in _canonical_findings(findings):
        evidence = finding.get("evidence") or {}
        fingerprint = finding_fingerprint(finding)
        location = (
            finding.get("rule_id", ""),
            evidence.get("file", ""),
            evidence.get("line", 0),
        )
        suppressed = fingerprint in suppression_fingerprints or location in suppression_locations
        result.append(
            {
                "finding": finding,
                "fingerprint": fingerprint,
                "baseline": fingerprint in baseline,
                "suppressed": suppressed,
            }
        )
    return result


def _sarif_level(severity: str) -> str:
    if severity in {"CRITICAL", "HIGH"}:
        return "error"
    if severity == "MEDIUM":
        return "warning"
    if severity == "LOW":
        return "note"
    return "none"


def build_sarif(
    findings: Iterable[Finding | dict],
    baseline: set[str] | None = None,
    suppression_fingerprints: set[str] | None = None,
    suppression_locations: set[tuple] | None = None,
) -> dict:
    classified = classify_findings(
        findings,
        baseline=baseline,
        suppression_fingerprints=suppression_fingerprints,
        suppression_locations=suppression_locations,
    )

    rules = {}
    results = []

    for item in classified:
        finding = item["finding"]
        rule_id = str(finding.get("rule_id", "UNKNOWN"))
        severity = str(finding.get("severity", "UNKNOWN"))
        category = str(finding.get("category", ""))
        confidence = str(finding.get("confidence", ""))
        description = str(finding.get("description", ""))
        evidence = finding.get("evidence") or {}
        file = str(evidence.get("file", ""))
        line = int(evidence.get("line", 1) or 1)

        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": str(finding.get("name", rule_id)),
                "shortDescription": {"text": str(finding.get("name", rule_id))},
                "help": {"text": str(finding.get("remediation", "Review the evidence-backed finding."))},
                "properties": {
                    "category": category,
                    "severity": severity,
                    "confidence": confidence,
                },
            },
        )

        result = {
            "ruleId": rule_id,
            "level": _sarif_level(severity),
            "message": {"text": description},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": file},
                        "region": {"startLine": line},
                    }
                }
            ],
            "fingerprints": {"aegis/v1": item["fingerprint"]},
            "baselineState": "unchanged" if item["baseline"] else "new",
        }

        if item["suppressed"]:
            evidence_key = (
                item["fingerprint"]
                if item["fingerprint"] in (suppression_fingerprints or set())
                else "location:" + "|".join(map(str, (
                    finding.get("rule_id", ""), file, line
                )))
            )
            reason = "Explicit suppression"
            if suppression_fingerprints and item["fingerprint"] in suppression_fingerprints:
                reason = "Explicit fingerprint suppression"
            elif suppression_locations and (finding.get("rule_id", ""), file, line) in suppression_locations:
                reason = "Explicit location suppression"
            result["suppressions"] = [{"kind": "external", "justification": reason}]

        results.append(result)

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SYJ-AEGIS",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/SHalimoosavi/SYJ-Aegis",
                        "rules": [rules[key] for key in sorted(rules)],
                    }
                },
                "results": results,
            }
        ],
    }


def write_sarif(
    path: Path,
    findings: Iterable[Finding | dict],
    baseline: set[str] | None = None,
    suppression_fingerprints: set[str] | None = None,
    suppression_locations: set[tuple] | None = None,
) -> None:
    _write_json(
        path,
        build_sarif(
            findings,
            baseline=baseline,
            suppression_fingerprints=suppression_fingerprints,
            suppression_locations=suppression_locations,
        ),
    )


def evaluate_ci(
    findings: Iterable[Finding | dict],
    fail_on: str = "high",
    baseline: set[str] | None = None,
    suppression_fingerprints: set[str] | None = None,
    suppression_locations: set[tuple] | None = None,
) -> dict:
    if fail_on not in FAIL_LEVELS:
        raise ValueError("fail_on must be one of: none, low, medium, high, critical")

    classified = classify_findings(
        findings,
        baseline=baseline,
        suppression_fingerprints=suppression_fingerprints,
        suppression_locations=suppression_locations,
    )
    threshold = FAIL_LEVELS[fail_on]
    actionable = []

    for item in classified:
        finding = item["finding"]
        severity = str(finding.get("severity", "UNKNOWN"))
        if item["baseline"] or item["suppressed"] or threshold is None:
            continue
        if severity in SEVERITY_RANK and SEVERITY_RANK[severity] <= SEVERITY_RANK[threshold]:
            actionable.append(item)

    return {
        "version": PHASE,
        "total_findings": len(classified),
        "baseline_findings": sum(item["baseline"] for item in classified),
        "suppressed_findings": sum(item["suppressed"] for item in classified),
        "actionable_findings": len(actionable),
        "fail_on": fail_on,
        "failed": bool(actionable),
    }
