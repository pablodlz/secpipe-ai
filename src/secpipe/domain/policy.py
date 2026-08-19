"""A RÉGUA (gate). Determinística e fail-closed. Mora no motor referenciado (ver ADR-0008)."""
from __future__ import annotations

from dataclasses import dataclass

from .models import Report, Severity


@dataclass(frozen=True, slots=True)
class GateDecision:
    passed: bool
    reason: str


@dataclass(frozen=True, slots=True)
class GatePolicy:
    """Bloqueia se houver achado com severidade >= block_severity. Default forte, mas tunável (ADR-0009)."""
    block_severity: Severity = Severity.HIGH

    def evaluate(self, report: Report) -> GateDecision:
        # Fail-closed: se algum scanner ERROU, não podemos provar segurança -> bloqueia.
        if report.has_errors:
            return GateDecision(False, "gate fail-closed: um scanner falhou (status=error)")
        blocking = [f for f in report.findings if f.severity >= self.block_severity]
        if blocking:
            worst = max(f.severity for f in blocking)
            return GateDecision(
                False,
                f"{len(blocking)} achado(s) >= {self.block_severity.name} (pior: {worst.name})",
            )
        return GateDecision(True, "nenhum achado bloqueante")
