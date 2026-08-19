"""Utilidades comuns aos adapters de scanner."""
from __future__ import annotations

import shutil


def tool_on_path(binary: str) -> bool:
    """True se o binário existe no PATH. Base do `is_available()` e do `secpipe doctor`."""
    return shutil.which(binary) is not None
