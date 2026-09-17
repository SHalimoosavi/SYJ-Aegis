"""Minimal PEP 517/660 backend implemented with the Python standard library."""
from pathlib import Path
import zipfile
NAME = "syj_aegis"
VERSION = "0.1.0"
DIST = f"{NAME}-{VERSION}.dist-info"

def _metadata():
    return f"Metadata-Version: 2.3\nName: syj-aegis\nVersion: {VERSION}\nRequires-Python: >=3.10\n"

def _wheel():
    return "Wheel-Version: 1.0\nGenerator: syj-aegis\nRoot-Is-Purelib: true\nTag: py3-none-any\n"

def _write_dist(z):
    z.writestr(f"{DIST}/METADATA", _metadata())
    z.writestr(f"{DIST}/WHEEL", _wheel())
    z.writestr(f"{DIST}/entry_points.txt", "[console_scripts]\naegis = aegis.cli:main\n")
    z.writestr(f"{DIST}/RECORD", "")

def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    wheel = f"{NAME}-{VERSION}-py3-none-any.whl"
    target = Path(wheel_directory) / wheel
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as z:
        for p in Path(".").rglob("*"):
            if p.is_file() and ".venv" not in p.parts and "__pycache__" not in p.parts:
                z.write(p, p.as_posix())
        _write_dist(z)
    return wheel

def build_editable(wheel_directory, config_settings=None, metadata_directory=None):
    wheel = f"{NAME}-{VERSION}-py3-none-any.whl"
    target = Path(wheel_directory) / wheel
    project_root = str(Path.cwd().resolve())
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("syj_aegis_editable.pth", project_root + "\n")
        _write_dist(z)
    return wheel

def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):
    return _prepare(metadata_directory)

def prepare_metadata_for_build_editable(metadata_directory, config_settings=None):
    return _prepare(metadata_directory)

def _prepare(metadata_directory):
    d = Path(metadata_directory) / DIST
    d.mkdir(parents=True, exist_ok=True)
    (d / "METADATA").write_text(_metadata(), encoding="utf-8")
    (d / "WHEEL").write_text(_wheel(), encoding="utf-8")
    return DIST
