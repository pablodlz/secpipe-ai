"""Composition Root — único lugar que conhece adapters concretos. Monta o motor a partir da config."""
from __future__ import annotations

import os

from secpipe.adapters.ai import MultiProvider, NullProvider
from secpipe.adapters.ai_providers import AnthropicProvider, OpenAICompatibleProvider
from secpipe.adapters.bandit import BanditScanner
from secpipe.adapters.checkov import CheckovScanner
from secpipe.adapters.codemodder import CodemodderFixer
from secpipe.adapters.dast_zap import ZapDastScanner
from secpipe.adapters.gitleaks import GitleaksScanner
from secpipe.adapters.gitleaks_history import GitleaksHistoryScanner
from secpipe.adapters.gosec import GosecScanner
from secpipe.adapters.hadolint import HadolintScanner
from secpipe.adapters.license_scan import LicenseScanner
from secpipe.adapters.malicious_deps import MaliciousDepsScanner
from secpipe.adapters.npm_audit import NpmAuditScanner
from secpipe.adapters.osv_scanner import OsvScanner
from secpipe.adapters.pip_audit import PipAuditScanner
from secpipe.adapters.semgrep import SemgrepScanner
from secpipe.adapters.trivy import TrivyScanner
from secpipe.adapters.trivy_image import TrivyImageScanner
from secpipe.application.orchestrator import Orchestrator
from secpipe.application.ports import AIProviderPort, ScannerPort
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
    "checkov": CheckovScanner,      # IaC SAST (Terraform/K8s/CFN/Dockerfile) — SARIF
    "hadolint": HadolintScanner,    # lint de Dockerfile — SARIF
    "gosec": GosecScanner,          # SAST de Go (precisa do toolchain go) — SARIF
    "osv-scanner": OsvScanner,      # SCA multi-eco (OSV.dev) — SARIF
    "npm-audit": NpmAuditScanner,   # SCA JS (precisa de npm + package-lock.json)
    "gitleaks-history": GitleaksHistoryScanner,   # segredos no HISTORICO git (opt-in)
    "dast": ZapDastScanner,   # DAST (ZAP baseline) — opt-in; precisa de dast_target na config
    "image": TrivyImageScanner,     # scan de imagem de container (trivy image) — opt-in; precisa image_target
    "license": LicenseScanner,      # conformidade de licencas (trivy) — opt-in; precisa politica licenses
    "malicious-deps": MaliciousDepsScanner,  # typosquat/dependency-confusion (offline) — usa internal_prefixes
}


def build_scanners(config: Config) -> tuple[ScannerPort, ...]:
    scanners: list[ScannerPort] = []
    for name in config.scanners:
        # Scanners PARAMETRIZADOS recebem alvo/politica da config (os demais sao zero-arg).
        if name == "dast":
            scanners.append(ZapDastScanner(config.dast_target, mode=config.dast_mode,
                                           timeout=config.dast_timeout))
        elif name == "image":
            scanners.append(TrivyImageScanner(config.image_target))
        elif name == "license":
            scanners.append(LicenseScanner(config.license_policy))
        elif name == "malicious-deps":
            scanners.append(MaliciousDepsScanner(config.internal_prefixes))
        else:
            factory = _SCANNER_REGISTRY.get(name)
            if factory is not None:
                scanners.append(factory())
    return tuple(scanners)


def build_policy(config: Config) -> GatePolicy:
    return GatePolicy(
        block_severity=Severity.parse(config.block_severity),
        min_scanners=config.min_scanners,
        require_scanners=frozenset(config.require_scanners),
        kev_blocks=config.kev_blocks,
    )


def build(config: Config | None = None) -> Orchestrator:
    cfg = config or Config.load()
    return Orchestrator(scanners=build_scanners(cfg), policy=build_policy(cfg))


def build_fixer() -> CodemodderFixer:
    """Fixer determinístico (Codemodder). Ponto de extensão p/ outros fixers no futuro."""
    return CodemodderFixer()


def build_ai_provider(config: Config | None = None) -> AIProviderPort:
    """Monta o provedor de IA do modo HEADLESS a partir do AMBIENTE (única fonte de chave). Sem chave/
    provedor => NullProvider (available False => autofix escala, fail-closed). ÚNICO ponto com adapters de IA."""
    which = os.environ.get("SECPIPE_AI_PROVIDER", "").lower()
    model = os.environ.get("SECPIPE_AI_MODEL", "")
    base_url = os.environ.get("SECPIPE_AI_BASE_URL", "")
    try:
        timeout = int(os.environ.get("SECPIPE_AI_TIMEOUT", "60"))
    except ValueError:
        timeout = 60
    providers: list[AIProviderPort] = []
    if which in ("", "anthropic", "multi"):
        anthropic = AnthropicProvider(model=model or "claude-sonnet-4-5", timeout=timeout)
        if anthropic.available():
            providers.append(anthropic)
    if which in ("", "openai", "local", "multi") or base_url:
        openai = OpenAICompatibleProvider(
            base_url=base_url or "https://api.openai.com/v1", model=model or "gpt-4o-mini", timeout=timeout)
        if openai.available():
            providers.append(openai)
    if not providers:
        return NullProvider()
    return providers[0] if len(providers) == 1 else MultiProvider(providers)
