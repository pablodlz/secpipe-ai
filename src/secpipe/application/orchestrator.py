"""Orquestra scanners, agrega/dedup os achados e aplica o gate. Núcleo da Fase 1."""
from __future__ import annotations

from dataclasses import dataclass

from secpipe.application.ports import ScannerPort
from secpipe.domain import GateDecision, GatePolicy, Report, ScanResult, ScanStatus


@dataclass(frozen=True, slots=True)
class Orchestrator:
    scanners: tuple[ScannerPort, ...]
    policy: GatePolicy

    def run(self, target: str) -> tuple[Report, GateDecision]:
        results: list[ScanResult] = []
        for scanner in self.scanners:
            if scanner.is_available():
                results.append(scanner.scan(target))
            else:
                results.append(
                    ScanResult(scanner.name, ScanStatus.SKIPPED, (), "ferramenta ausente no PATH")
                )
        report = Report(tuple(results))
        return report, self.policy.evaluate(report)
