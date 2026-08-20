"""Composition Root — único lugar que conhece adapters concretos. Monta o motor a partir da config."""
from __future__ import annotations

from secpipe.adapters.bandit import BanditScanner
from secpipe.adapters.codemodder import CodemodderFixer
from secpipe.adapters.dast_zap import ZapDastScanner
from secpipe.adapters.gitleaks import GitleaksScanner
from secpipe.adapters.pip_audit import PipAuditScanner
from secpipe.adapters.semgrep import SemgrepScanner
from secpipe.adapters.trivy import TrivyScanner
from secpipe.application.orchestrator import Orchestrator
from secpipe.application.ports import ScannerPort
from secpipe.domain import GatePolicy, Severity
from secpipe.foundation.config import Config

# Registro nome -> fábrica de adapter. Novo scanner entra aqui (ponto de extensão).
# multi-linguagem: gitleaks/semgrep/trivy. Específicos de Python: bandit/pip-audit (opt-in via config;
# a Fase 2 habilita por auto-detecção de linguagem).
_SCANNER_REGISTRY: dict[str, type] = {
    "gitleaks": GitleaksScanner,
    "semgrep": SemgrepScanner,
    "trivy": TrivyScanner,
    "bandit": BanditScanner,
    "pip-audit": PipAuditScanner,
    "dast": ZapDastScanner,   # DAST (ZAP baseline) — opt-in; precisa de dast_target na config
}


def build_scanners(config: Config) -> tuple[ScannerPort, ...]:
    scanners: list[ScannerPort] = []
    for name in config.scanners:
        if name == "dast":   # DAST recebe a URL alvo da config (demais scanners são zero-arg)
            scanners.append(ZapDastScanner(config.dast_target))
            continue
        factory = _SCANNER_REGISTRY.get(name)
        if factory is not None:
            scanners.append(factory())
    return tuple(scanners)


def build_policy(config: Config) -> GatePolicy:
    return GatePolicy(
        block_severity=Severity.parse(config.block_severity),
        min_scanners=config.min_scanners,
        require_scanners=frozenset(config.require_scanners),
    )


def build(config: Config | None = None) -> Orchestrator:
    cfg = config or Config.load()
    return Orchestrator(scanners=build_scanners(cfg), policy=build_policy(cfg))


def build_fixer() -> CodemodderFixer:
    """Fixer determinístico (Codemodder). Ponto de extensão p/ outros fixers no futuro."""
    return CodemodderFixer()
