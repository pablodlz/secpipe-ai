"""Ports = fronteiras substituíveis. Adapters concretos vivem em adapters/. typing.Protocol.

Fase 0 define ScannerPort e ReporterPort (usados pelo esqueleto). FixerPort/VerifierPort/
AIProviderPort são o contrato da Fase 3 (auto-fix DRV) — declarados para fixar a arquitetura."""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from secpipe.domain import Finding, Report, ScanResult


@runtime_checkable
class ScannerPort(Protocol):
    name: str
    def is_available(self) -> bool:
        """True se a ferramenta está utilizável (ex.: binário no PATH)."""
        ...

    def scan(self, target: str) -> ScanResult:
        """Roda o scanner sobre `target` e devolve achados normalizados."""
        ...


@runtime_checkable
class ReporterPort(Protocol):
    name: str
    def render(self, report: Report) -> str:
        """Serializa o Report (ex.: JSON para a IA, SARIF para interop)."""
        ...


# ── Fase 3 (auto-fix DRV) — contrato declarado, ainda não implementado ──────────
@runtime_checkable
class FixerPort(Protocol):
    name: str
    def propose(self, finding: Finding) -> str:
        """Propõe um patch para o achado. Determinístico (codemod) ou por IA (ADR-0008)."""
        ...


@runtime_checkable
class VerifierPort(Protocol):
    def verify(self, finding: Finding, patch: str) -> bool:
        """Valida INDEPENDENTEMENTE o fix (rerun + testes). Quem corrige não aprova (ADR-0008)."""
        ...
