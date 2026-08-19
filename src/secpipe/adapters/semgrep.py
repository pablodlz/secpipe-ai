"""Adapter Semgrep CE (SAST multi-linguagem) — emite SARIF, normalizado por parse_sarif.

ADR-0003: Semgrep CE é free porém limitado a arquivo único; combinar com Bandit/ASH. O ruleset é
configurável (`--config`); default `auto` (regras da comunidade). Cross-platform (Windows/Linux)."""
from __future__ import annotations

from secpipe.adapters.base import tool_on_path
from secpipe.adapters.sarif import run_sarif_scanner
from secpipe.domain import ScanResult

BINARY = "semgrep"
_CONFIG = "auto"  # tunável na Fase 2 via .secpipe.yml


class SemgrepScanner:
    name = BINARY

    def is_available(self) -> bool:
        return tool_on_path(BINARY)

    def scan(self, target: str) -> ScanResult:
        return run_sarif_scanner(
            self.name, BINARY,
            ["scan", "--sarif", "--quiet", "--config", _CONFIG, target],
        )
