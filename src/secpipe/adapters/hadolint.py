"""Adapter hadolint (lint de Dockerfile, com ShellCheck nas linhas RUN). GRÁTIS (GPL-3.0, invocado
at-arms-length via subprocess — sem linking, não contamina o Apache-2.0). KEYLESS. Emite SARIF no stdout.

hadolint não varre diretórios: o adapter descobre Dockerfiles e passa os caminhos."""
from __future__ import annotations

import os

from secpipe.adapters.base import tool_on_path
from secpipe.adapters.sarif import run_sarif_scanner
from secpipe.domain import ScanResult, ScanStatus

BINARY = "hadolint"
_SKIP_DIRS = {".git", ".venv", "venv", "node_modules", ".tox", "dist", "build", "__pycache__", "tools", "vendor"}


def find_dockerfiles(root: str, limit: int = 200) -> list[str]:
    """Localiza Dockerfiles: 'Dockerfile', 'Dockerfile.*', '*.Dockerfile'. Determinístico e limitado."""
    found: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for name in filenames:
            low = name.lower()
            if low == "dockerfile" or low.startswith("dockerfile.") or low.endswith(".dockerfile"):
                found.append(os.path.join(dirpath, name))
                if len(found) >= limit:
                    return found
    return found


class HadolintScanner:
    name = BINARY

    def is_available(self) -> bool:
        return tool_on_path(BINARY)

    def scan(self, target: str) -> ScanResult:
        if not tool_on_path(BINARY):
            return ScanResult(self.name, ScanStatus.SKIPPED, (), "ferramenta ausente no PATH")
        dockerfiles = find_dockerfiles(target)
        if not dockerfiles:
            return ScanResult(self.name, ScanStatus.SKIPPED, (), "nenhum Dockerfile encontrado")
        return run_sarif_scanner(self.name, BINARY, ["--format", "sarif", *dockerfiles])
