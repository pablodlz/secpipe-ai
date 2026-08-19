"""Adapter gitleaks (secret scanning). Parsing já implementado e TESTADO (fixture).

Fase 0: `scan()` ainda não executa o binário (isso é Fase 1); mas `parse_gitleaks` — a lógica que
converte a saída do tool no contrato normalizado — já existe e tem teste, demonstrando o padrão."""
from __future__ import annotations

import json
import os
import tempfile

from secpipe.adapters.base import run_tool, tool_on_path
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
        # gitleaks escreve o report num arquivo (cross-platform: evita /dev/stdout, funciona no Windows).
        fd, report_path = tempfile.mkstemp(prefix="secpipe-gitleaks-", suffix=".json")
        os.close(fd)
        try:
            run = run_tool(
                BINARY,
                ["detect", "--source", target, "--no-git", "--report-format", "json",
                 "--report-path", report_path, "--exit-code", "0"],
            )
            if run.missing:
                return ScanResult(self.name, ScanStatus.SKIPPED, (), "ferramenta ausente no PATH")
            if run.timed_out:
                return ScanResult(self.name, ScanStatus.ERROR, (), "timeout")
            try:
                with open(report_path, encoding="utf-8") as fh:
                    findings = parse_gitleaks(fh.read())
            except (OSError, json.JSONDecodeError) as exc:
                return ScanResult(self.name, ScanStatus.ERROR, (), f"report ilegível: {exc}")
            return ScanResult(self.name, ScanStatus.OK, tuple(findings), "")
        finally:
            try:
                os.unlink(report_path)
            except OSError:
                pass
