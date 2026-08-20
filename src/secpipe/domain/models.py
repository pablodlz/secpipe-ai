"""O contrato normalizado que a IA consome (ver ADR-0004). Estável e versionado."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import IntEnum, StrEnum


class Severity(IntEnum):
    """Ordenável de propósito (comparações no gate)."""
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> Severity:
        """Fail-closed: severidade desconhecida é tratada como a MAIS alta (não subestimar risco)."""
        try:
            return cls[value.strip().upper()]
        except (KeyError, AttributeError):
            return cls.CRITICAL


class ScanStatus(StrEnum):
    OK = "ok"
    SKIPPED = "skipped"   # ferramenta ausente / Fase 0
    ERROR = "error"       # falha ao rodar -> gate fail-closed


@dataclass(frozen=True, slots=True)
class Finding:
    """Achado normalizado (independente do scanner de origem)."""
    tool: str
    rule_id: str
    severity: Severity
    message: str
    file: str = ""
    line: int = 0
    cwe: str = ""         # ex.: "CWE-79"
    epss: float | None = None  # prob. de exploração (EPSS, FIRST.org) quando enriquecido; None = sem dado
    kev: bool = False          # está no CISA KEV (exploração ativa conhecida)? enrichment só ELEVA, nunca rebaixa
    reachable: bool | None = None  # dep vulnerável é IMPORTADA? None = não avaliado. Só ANOTA (nunca relaxa o gate)

    @property
    def fingerprint(self) -> str:
        """Chave determinística para deduplicação entre tools. sha256 (não é uso de segurança).
        NÃO inclui epss/kev (são anotações, não identidade do achado)."""
        raw = f"{self.rule_id}|{self.cwe}|{self.file}|{self.line}".encode()
        return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True, slots=True)
class ScanResult:
    tool: str
    status: ScanStatus
    findings: tuple[Finding, ...] = ()
    detail: str = ""


# Dirs de dependências/artefatos INSTALADOS (terceiros), não código do projeto. Regra DO MOTOR (FEAT-003).
# Conservador: só dirs inequivocamente de terceiros/instalados. NÃO inclui 'tools/build/dist/vendor' — esses
# costumam ser código PRIMEIRO-PARTIDO e não podem ser escondidos do gate (achado de review).
_EXCLUDED_SEGMENTS = frozenset({
    ".venv", "venv", "node_modules", ".git", ".tox",
    "__pycache__", ".mypy_cache", ".ruff_cache", ".pytest_cache", ".cache", "site-packages",
})
# NUNCA excluídos por caminho, mesmo em dir de terceiros: segredo/CRITICAL/KEV (invariante "nunca escondido").
_NEVER_EXCLUDE_CWES = frozenset({"CWE-798"})


def _in_excluded_path(path: str) -> bool:
    return any(seg in _EXCLUDED_SEGMENTS for seg in path.replace("\\", "/").split("/"))


def _never_exclude(finding: Finding) -> bool:
    return finding.severity >= Severity.CRITICAL or finding.kev or finding.cwe.upper() in _NEVER_EXCLUDE_CWES


@dataclass(frozen=True, slots=True)
class Report:
    results: tuple[ScanResult, ...]

    @property
    def findings(self) -> list[Finding]:
        """Achados agregados, com dirs vendored/venv EXCLUÍDOS (FEAT-003) e DEDUP por fingerprint."""
        seen: set[str] = set()
        out: list[Finding] = []
        for result in self.results:
            for finding in result.findings:
                # exclui dir de terceiros — MAS nunca esconde segredo/CRITICAL/KEV (fail-closed).
                if finding.file and _in_excluded_path(finding.file) and not _never_exclude(finding):
                    continue
                fp = finding.fingerprint
                if fp not in seen:
                    seen.add(fp)
                    out.append(finding)
        return out

    @property
    def has_errors(self) -> bool:
        return any(r.status is ScanStatus.ERROR for r in self.results)

    @property
    def ran(self) -> int:
        """Quantos scanners REALMENTE rodaram (OK ou ERROR). 0 = nada escaneado (gate verde é falso)."""
        return sum(1 for r in self.results if r.status in (ScanStatus.OK, ScanStatus.ERROR))
