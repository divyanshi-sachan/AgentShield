"""Minimal .env loader (KEY=value lines), so credentials stay in a git-ignored file.

Existing environment variables always win; values are never printed or logged.
"""

from __future__ import annotations

import os
from pathlib import Path


def load_dotenv(path: str | Path = ".env") -> list[str]:
    """Load variables from `path` into os.environ. Returns the names that were set."""
    path = Path(path)
    if not path.is_file():
        return []
    loaded = []
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        elif " #" in value:
            value = value.split(" #", 1)[0].rstrip()
        if key.isidentifier() and key not in os.environ:
            os.environ[key] = value
            loaded.append(key)
    return loaded
