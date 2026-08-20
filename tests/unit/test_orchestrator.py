"""Orquestrador: tool ausente vira SKIPPED; scan limpo passa; 0 cobertura falha-fechado (coverage-gate)."""
from __future__ import annotations

from secpipe.application.orchestrator import Orchestrator
from secpipe.domain import GatePolicy, ScanResult, ScanStatus


class _UnavailableScanner:
    name = "ghost"
    def is_available(self) -> bool:
        return False
    def scan(self, target: str) -> ScanResult:  # pragma: no cover - nunca chamado
        raise AssertionError("não deveria rodar")


class _CleanScanner:
    name = "clean"
    def is_available(self) -> bool:
        return True
    def scan(self, target: str) -> ScanResult:
        return ScanResult(self.name, ScanStatus.OK, ())


def test_unavailable_scanner_is_skipped() -> None:
    # min_scanners=0 isola o comportamento de SKIP do coverage-gate
    orch = Orchestrator((_UnavailableScanner(),), GatePolicy(min_scanners=0))
    report, _ = orch.run(".")
    assert report.results[0].status is ScanStatus.SKIPPED


def test_clean_scan_passes_gate() -> None:
    orch = Orchestrator((_CleanScanner(),), GatePolicy())
    _report, decision = orch.run(".")
    assert decision.passed is True


def test_zero_coverage_fails_closed() -> None:
    # só um scanner ausente => ran==0 => coverage-gate bloqueia o falso-verde
    orch = Orchestrator((_UnavailableScanner(),), GatePolicy())
    _report, decision = orch.run(".")
    assert decision.passed is False
