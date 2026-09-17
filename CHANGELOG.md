# Changelog

## Dashboard Sync v1.0.0 — 2026-09-17

- Fixed the GitHub Pages dashboard staleness after Phase 5 and Phase 6.
- Dashboard generation now runs the real scanner and CI pipeline before rendering.
- Added governance register metrics from `.aegis/governance.json`.
- Added CI and SARIF metrics from the real Phase 6 output.
- Rebuilt phase/module metrics through Phase 6 without changing scanner logic.
- Added a self-contained browser demonstration using a deliberately small subset of rules.
- Clearly separates the browser demonstration from the production Python scanner.
- Added a Pages deployment job that rebuilds the dashboard on pushes to `main`.
- No new scanner detection logic or runtime dependencies were added.
