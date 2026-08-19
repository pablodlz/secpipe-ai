"""Adapter gitleaks (secret scanning). Parsing já implementado e TESTADO (fixture).

Fase 0: `scan()` ainda não executa o binário (isso é Fase 1); mas `parse_gitleaks` — a lógica que
converte a saída do tool no contrato normalizado — já existe e tem teste, demonstrando o padrão."""
from __future__ import annotations

import json

from secpipe.adapters.base import tool_on_path
from secpipe.domain import Finding, ScanResult, ScanStatus, Severity

BINARY = "gitleaks"


def parse_gitleaks(raw: str) -> list[Finding]:
    """Converte o JSON de report do gitleaks em Findings normalizados. Segredo vazado => HIGH."""
    if not raw.strip():
        return []
    data = json.loads(raw)
    findings: list[Finding] = []
    for item in data:
        findings.append(
            Finding(
                tool="gitleaks",
                rule_id=str(item.get("RuleID", "generic-secret")),
                severity=Severity.HIGH,
                message=str(item.get("Description", "potential secret")),
                file=str(item.get("File", "")),
                line=int(item.get("StartLine", 0) or 0),
                cwe="CWE-798",  # Use of Hard-coded Credentials
            )
        )
    return findings


class GitleaksScanner:
    name = BINARY

    def is_available(self) -> bool:
        return tool_on_path(BINARY)

    def scan(self, target: str) -> ScanResult:
        # Fase 1 fará: rodar o binário e passar a saída por parse_gitleaks().
        return ScanResult(self.name, ScanStatus.SKIPPED, (), "execução real: Fase 1")
