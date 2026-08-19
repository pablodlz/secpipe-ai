"""Orquestrador: tool ausente vira SKIPPED; sem achado/erro o gate passa."""
from __future__ import annotations

from secpipe.application.orchestrator import Orchestrator
from secpipe.domain import GatePolicy, ScanResult, ScanStatus


class _UnavailableScanner:
    name = "ghost"
    def is_available(self) -> bool:
        return False
    def scan(self, target: str) -> ScanResult:  # pragma: no cover - nunca chamado
        raise AssertionError("não deveria rodar")


def test_unavailable_scanner_is_skipped_and_gate_passes() -> None:
    orch = Orchestrator((_UnavailableScanner(),), GatePolicy())
    report, decision = orch.run(".")
    assert report.results[0].status is ScanStatus.SKIPPED
    assert decision.passed is True
