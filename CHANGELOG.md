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
