"""Adapter Semgrep CE (SAST multi-linguagem). Fase 0: esqueleto (parsing SARIF vem na Fase 1).

Nota (ADR-0003): Semgrep CE é free porém limitado a arquivo único; combinar com Bandit/ASH."""
from __future__ import annotations

from secpipe.adapters.base import tool_on_path
from secpipe.domain import ScanResult, ScanStatus

BINARY = "semgrep"


class SemgrepScanner:
    name = BINARY

    def is_available(self) -> bool:
        return tool_on_path(BINARY)

    def scan(self, target: str) -> ScanResult:
        # Fase 1: `semgrep --sarif` -> normalizar SARIF -> Finding[].
        return ScanResult(self.name, ScanStatus.SKIPPED, (), "execução real: Fase 1")
