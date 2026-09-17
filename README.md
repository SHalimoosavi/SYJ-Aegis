# SYJ-AEGIS — Phase 1
Local-first, standard-library-only static security scanner.

## Implemented
`aegis --help`, `aegis version`, `aegis scan <project>`, evidence-based project discovery, potential secret detection, JSON outputs, a self-contained static HTML report, and `unittest` coverage.

## Termux
```sh
git clone <your-repository-url>
cd SYJ-Aegis
python -m venv .venv
source .venv/bin/activate
pip install -e .
aegis --help
aegis scan .
```

## Tests
```sh
python -m unittest discover -s tests -v
```

## Output
A scan creates `.aegis/findings.json`, `.aegis/configuration.json`, and `.aegis/report/index.html`.

No scanned project code is imported or executed. Phase 1 makes no network calls.
