"""Adapter osv-scanner (SCA multi-ecossistema do Google: npm/pip/go/maven/cargo/... via lockfiles e
OSV.dev). GRÁTIS (Apache-2.0), KEYLESS. Emite SARIF no stdout -> reusa run_sarif_scanner direto.

Alternativa keyless de SCA multi-eco para o container (onde não há Node p/ npm-audit)."""
from __future__ import annotations

from secpipe.adapters.base import tool_on_path
from secpipe.adapters.sarif import run_sarif_scanner
from secpipe.domain import ScanResult

BINARY = "osv-scanner"


class OsvScanner:
    name = BINARY

    def is_available(self) -> bool:
        return tool_on_path(BINARY)

    def scan(self, target: str) -> ScanResult:
        return run_sarif_scanner(self.name, BINARY, ["--format", "sarif", "--recursive", target])
