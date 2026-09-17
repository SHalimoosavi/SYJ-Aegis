# SYJ-AEGIS Phase 6 — Production Hardening

Phase 6 adds CI policy enforcement around the existing local static scanner. It is additive: Phase 1–5 detection logic and the existing finding model remain unchanged.

## CI command

```bash
aegis ci . \
  --sarif .aegis/results.sarif \
  --baseline .github/aegis-baseline.json \
  --suppressions .github/aegis-suppressions.json \
  --fail-on high
```

The command:

1. Performs the normal local static scan.
2. Writes the normal `.aegis/` JSON and HTML artifacts.
3. Writes deterministic SARIF 2.1.0.
4. Loads an optional baseline.
5. Loads optional external suppressions.
6. Applies the selected severity gate.
7. Returns exit code `1` only when an actionable finding meets the configured threshold.

Thresholds are `none`, `low`, `medium`, `high`, and `critical`. `none` never fails the policy gate.

## SARIF

SARIF is written as UTF-8 JSON with stable ordering. Each result contains:

- the existing SYJ-AEGIS rule ID;
- severity mapped to SARIF level;
- original evidence file and line;
- deterministic `aegis/v1` fingerprint;
- `new` or `unchanged` baseline state;
- an external suppression record when a finding is explicitly suppressed.

The SARIF artifact does not execute or import scanned project code.

## Baselines

A baseline records the current evidence-backed finding identities. It is useful when a repository has an accepted existing finding set and CI should focus on newly introduced findings.

Create or refresh a baseline explicitly:

```bash
aegis ci . \
  --baseline .github/aegis-baseline.json \
  --update-baseline \
  --fail-on none
```

Baseline fingerprints are deterministic and are derived from the rule ID, finding name, evidence file, and evidence line. Moving or materially changing evidence therefore requires review rather than silently remaining baseline-matched.

## Suppressions

The suppression file is JSON:

```json
{
  "version": "phase6",
  "suppressions": [
    {
      "rule_id": "AEGIS-AI-002",
      "file": "src/agent.py",
      "line": 42,
      "reason": "Reviewed boundary; tracked separately."
    }
  ]
}
```

An exact fingerprint may be used instead of `rule_id` + `file` + `line`.

Suppressions are external to source code and require an explicit reason. The repository default file is empty.

## GitHub Actions

`.github/workflows/ci.yml` runs:

- package installation;
- the complete `unittest` suite;
- the CI policy scan using the repository baseline and suppression file;
- SARIF upload.

The workflow uses the package's own editable installation and does not add runtime dependencies to SYJ-AEGIS.

## Local-first and safety guarantees

Phase 6 retains the project-wide constraints:

- Python standard library runtime only;
- local static analysis;
- no network access by the scanner by default;
- no execution/import/evaluation of scanned project code;
- deterministic machine-readable output;
- evidence-backed findings only.
