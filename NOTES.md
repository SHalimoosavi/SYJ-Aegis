# SYJ-AEGIS Phase 1 Notes
## Assumptions
1. The pasted specification uses flattened numbering; Phase 1 scope is taken directly from its explicit phase definition.
2. Only populated Phase 1 directories are created.
3. Later-phase CLI commands and configuration controls are not exposed early.
4. Secret detection uses conservative local patterns and records only file/line evidence; detected values are not included in findings or HTML.
5. Technology detection is evidence-based and limited to source extensions, supported manifests, Docker filenames, and GitHub Actions workflow paths.
6. External vulnerability intelligence is not queried in Phase 1.
7. Volatile timestamps are omitted from `findings.json` to preserve deterministic byte-for-byte output.
8. Example report dates/counts are not copied; actual scan results are computed.
