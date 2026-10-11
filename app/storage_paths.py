"""Resolve persistent application state paths for local and hosted runs."""

import os
from pathlib import Path


_configured_data_dir = Path(os.environ.get("SENTINEL_DATA_DIR", ".")).expanduser()
DATA_DIRECTORY = (
    _configured_data_dir
    if _configured_data_dir.is_absolute()
    else Path.cwd() / _configured_data_dir
)


def data_path(*parts: str) -> Path:
    """Return a path beneath the configured persistent data directory."""
    return DATA_DIRECTORY.joinpath(*parts)
