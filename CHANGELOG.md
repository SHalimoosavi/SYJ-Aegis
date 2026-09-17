# Changelog

## Phase 2 — AgentGuard
- Added conservative static Python tool discovery using `ast` for explicit tool decorators, tool-registration calls, and `tools=[...]` collections.
- Added evidence-backed capability classification for read, write, execute, network, filesystem, credentials, and destructive operations.
- Added excessive-agency detection for tools combining two or more high-impact capabilities.
- Added deterministic `.aegis/inventory.json` and `.aegis/permissions.json` outputs and an Agent Capabilities section in the self-contained HTML report.

## Phase 3 — AI-Firewall
- Added conservative static prompt-security checks for hardcoded prompt secrets and direct prompt-injection exposure.
- Added direct PII/data-exposure checks for email/phone literals and PII-looking variables reaching logging, LLM, or network sinks.
- Added documented vector-store/RAG detection with `UNCLEAR` / `REVIEW REQUIRED` authorization-filter findings.
- Added LLM-output-to-dangerous-sink detection using `AEGIS-AI-017`.
- Added deterministic Phase 3 findings integration and updated README/reporting documentation.

## Phase 4 — GitHub Pages Dashboard
- Added a standard-library dashboard build script that dogfoods `aegis scan .` and requires real `.aegis/findings.json` output.
- Added a self-contained GitHub Pages dashboard with programmatically rendered finding/severity/phase/module counts.
- Added hand-maintained structured module and roadmap status in `docs/status.json`.
- Added copying of the generated `.aegis/report/` into `docs/report/`.
- Added dashboard positive and missing-input unit tests.

## Phase 5 — AIGovern
- Added an evidence-backed AI System Register using conservative static AST analysis of observable AI-library imports and model invocation patterns.
- Added a static Data Map for observable user/external-input and sensitive-data flows reaching recognized sinks.
- Added a deterministic Risk Register mapping existing security findings to governance risks and controls.
- Added governance Control Mapping across AI input, prompt, data, RAG, output, agent, and secret-management domains.
- Added separate `AEGIS-GOV-*` evidence-backed governance findings derived from existing scanner findings.
- Added deterministic `.aegis/governance.json` output.
- Integrated AIGovern additively into the existing scanner without rewriting Phase 1–4 detection logic.
- Added positive and negative governance fixtures and unit tests covering AI-system discovery, data mapping, governance mapping, evidence integrity, scanner integration, and deterministic output.

## Phase 6 — Production Hardening
- Added `aegis ci` policy mode with configurable severity gates and deterministic CI summaries.
- Added deterministic SARIF 2.1.0 output with evidence locations, fingerprints, baseline state, and suppression state.
- Added deterministic finding baselines and explicit external suppressions.
- Added a GitHub Actions workflow for installation, full unit tests, CI scanning, and SARIF upload.
- Added Phase 6 production-hardening operational documentation.
