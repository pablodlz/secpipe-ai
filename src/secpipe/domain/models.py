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

    @property
    def fingerprint(self) -> str:
        """Chave determinística para deduplicação entre tools. sha256 (não é uso de segurança)."""
        raw = f"{self.rule_id}|{self.cwe}|{self.file}|{self.line}".encode()
        return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True, slots=True)
class ScanResult:
    tool: str
    status: ScanStatus
    findings: tuple[Finding, ...] = ()
    detail: str = ""


@dataclass(frozen=True, slots=True)
class Report:
    results: tuple[ScanResult, ...]

    @property
    def findings(self) -> list[Finding]:
        """Achados agregados e DEDUPLICADOS por fingerprint (preserva a 1ª ocorrência)."""
        seen: set[str] = set()
        out: list[Finding] = []
        for result in self.results:
            for finding in result.findings:
                fp = finding.fingerprint
                if fp not in seen:
                    seen.add(fp)
                    out.append(finding)
        return out

    @property
    def has_errors(self) -> bool:
        return any(r.status is ScanStatus.ERROR for r in self.results)
