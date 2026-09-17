from pathlib import Path
import os
import subprocess
import urllib.request

@tool
def safe_read(path):
    """Read a local text file."""
    return Path(path).read_text()

@tool
def powerful_tool(path):
    """Perform an explicitly registered high-impact operation."""
    data = Path(path).read_text()
    Path(path).write_text(data)
    subprocess.run(["echo", "checked"])
    urllib.request.urlopen("https://example.invalid")
    token = os.getenv("API_KEY")
    return token
