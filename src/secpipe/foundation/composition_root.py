"""Composition Root — único lugar que conhece adapters concretos. Monta o motor a partir da config."""
from __future__ import annotations

from secpipe.adapters.gitleaks import GitleaksScanner
from secpipe.adapters.semgrep import SemgrepScanner
from secpipe.adapters.trivy import TrivyScanner
from secpipe.application.orchestrator import Orchestrator
from secpipe.application.ports import ScannerPort
from secpipe.domain import GatePolicy, Severity
from secpipe.foundation.config import Config

# Registro nome -> fábrica de adapter. Novo scanner entra aqui (ponto de extensão).
_SCANNER_REGISTRY: dict[str, type] = {
    "gitleaks": GitleaksScanner,
    "semgrep": SemgrepScanner,
    "trivy": TrivyScanner,
}


def build_scanners(config: Config) -> tuple[ScannerPort, ...]:
    scanners: list[ScannerPort] = []
    for name in config.scanners:
        factory = _SCANNER_REGISTRY.get(name)
        if factory is not None:
            scanners.append(factory())
    return tuple(scanners)


def build_policy(config: Config) -> GatePolicy:
    return GatePolicy(block_severity=Severity.parse(config.block_severity))


def build(config: Config | None = None) -> Orchestrator:
    cfg = config or Config.load()
    return Orchestrator(scanners=build_scanners(cfg), policy=build_policy(cfg))
