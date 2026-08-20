"""A RÉGUA (gate). Determinística e fail-closed. Mora no motor referenciado (ver ADR-0008)."""
from __future__ import annotations

from dataclasses import dataclass, field

from .models import Report, ScanStatus, Severity


@dataclass(frozen=True, slots=True)
class GateDecision:
    passed: bool
    reason: str


@dataclass(frozen=True, slots=True)
class GatePolicy:
    """Bloqueia se houver achado com severidade >= block_severity. Default forte, mas tunável (ADR-0009).

    COBERTURA (fail-closed contra falso-verde): 0 scanners rodando faz um Report vazio "passar" verde —
    verde por AUSÊNCIA de análise, não por segurança. `min_scanners`/`require_scanners` fecham esse buraco."""
    block_severity: Severity = Severity.HIGH
    min_scanners: int = 1                                   # <1 seria verde-falso; default exige ≥1
    require_scanners: frozenset[str] = field(default_factory=frozenset)  # nomes que DEVEM ter rodado (opt-in)

    def evaluate(self, report: Report) -> GateDecision:
        # Fail-closed: se algum scanner ERROU, não podemos provar segurança -> bloqueia.
        if report.has_errors:
            return GateDecision(False, "gate fail-closed: um scanner falhou (status=error)")
        # Cobertura mínima: verde sem análise é falso-verde (fail-closed).
        if report.ran < self.min_scanners:
            return GateDecision(
                False,
                f"cobertura insuficiente: {report.ran} scanner(es) rodaram (min {self.min_scanners}) - "
                "gate fail-closed (verde seria por ausencia de analise, nao por seguranca)",
            )
        if self.require_scanners:
            ran = {r.tool for r in report.results if r.status in (ScanStatus.OK, ScanStatus.ERROR)}
            missing = sorted(self.require_scanners - ran)
            if missing:
                return GateDecision(False, f"cobertura insuficiente: exigido(s) nao rodou(aram): {', '.join(missing)}")
        blocking = [f for f in report.findings if f.severity >= self.block_severity]
        if blocking:
            worst = max(f.severity for f in blocking)
            return GateDecision(
                False,
                f"{len(blocking)} achado(s) >= {self.block_severity.name} (pior: {worst.name})",
            )
        return GateDecision(True, "nenhum achado bloqueante")
