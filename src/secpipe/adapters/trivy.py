"""Adapter Trivy (SCA + IaC + imagem + secret, multi-linguagem). Fase 0: esqueleto."""
from __future__ import annotations

from secpipe.adapters.base import tool_on_path
from secpipe.domain import ScanResult, ScanStatus

BINARY = "trivy"


class TrivyScanner:
    name = BINARY

    def is_available(self) -> bool:
        return tool_on_path(BINARY)

    def scan(self, target: str) -> ScanResult:
        # Fase 1: `trivy fs --format sarif` -> normalizar -> Finding[].
        return ScanResult(self.name, ScanStatus.SKIPPED, (), "execução real: Fase 1")
