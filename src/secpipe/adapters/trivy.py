"""Adapter Trivy (SCA + IaC + imagem + secret, multi-linguagem) — emite SARIF, normalizado por parse_sarif.

`trivy fs` escaneia o filesystem do projeto. Cross-platform (Windows/Linux)."""
from __future__ import annotations

from secpipe.adapters.base import tool_on_path
from secpipe.adapters.sarif import run_sarif_scanner
from secpipe.domain import ScanResult

BINARY = "trivy"


class TrivyScanner:
    name = BINARY

    def is_available(self) -> bool:
        return tool_on_path(BINARY)

    def scan(self, target: str) -> ScanResult:
        return run_sarif_scanner(
            self.name, BINARY,
            ["fs", "--format", "sarif", "--quiet", target],
        )
