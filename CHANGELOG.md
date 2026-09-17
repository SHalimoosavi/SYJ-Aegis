# Changelog

## Phase 2 — AgentGuard
- Added conservative static Python tool discovery using `ast` for explicit tool decorators, tool-registration calls, and `tools=[...]` collections.
- Added evidence-backed capability classification for read, write, execute, network, filesystem, credentials, and destructive operations.
- Added excessive-agency detection for tools combining two or more high-impact capabilities.
- Added deterministic `.aegis/inventory.json` and `.aegis/permissions.json` outputs and an Agent Capabilities section in the self-contained HTML report.
