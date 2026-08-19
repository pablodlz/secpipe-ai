"""Adapter Bandit (SAST específico de Python). Emite JSON próprio. Complementa o Semgrep (ADR-0003)."""
from __future__ import annotations

import json

from secpipe.adapters.base import run_tool, tool_on_path
from secpipe.domain import Finding, ScanResult, ScanStatus, Severity

BINARY = "bandit"
_SEV = {"LOW": Severity.LOW, "MEDIUM": Severity.MEDIUM, "HIGH": Severity.HIGH}
# dirs de ruído que não são código do projeto (a filtragem fina fica no FEAT-003)
_EXCLUDE = ".venv,venv,node_modules,.git,dist,build,.tox"


def parse_bandit(raw: str) -> list[Finding]:
    """Converte o JSON do Bandit em Findings normalizados."""
    if not raw.strip():
        return []
    data = json.loads(raw)
    findings: list[Finding] = []
    for item in data.get("results", []) or []:
        cwe = ""
        cwe_obj = item.get("issue_cwe")
        if isinstance(cwe_obj, dict) and cwe_obj.get("id"):
            cwe = f"CWE-{cwe_obj['id']}"
        findings.append(
            Finding(
                tool="bandit",
                rule_id=str(item.get("test_id", "bandit")),
                severity=_SEV.get(str(item.get("issue_severity", "")).upper(), Severity.MEDIUM),
                message=str(item.get("issue_text", "")),
                file=str(item.get("filename", "")),
                line=int(item.get("line_number", 0) or 0),
                cwe=cwe,
            )
        )
    return findings


class BanditScanner:
    name = BINARY

    def is_available(self) -> bool:
        return tool_on_path(BINARY)

    def scan(self, target: str) -> ScanResult:
        run = run_tool(BINARY, ["-r", target, "-f", "json", "-q", "--exclude", _EXCLUDE])
        if run.missing:
            return ScanResult(self.name, ScanStatus.SKIPPED, (), "ferramenta ausente no PATH")
        if run.timed_out:
            return ScanResult(self.name, ScanStatus.ERROR, (), "timeout")
        try:
            findings = parse_bandit(run.stdout)
        except (json.JSONDecodeError, ValueError) as exc:
            return ScanResult(self.name, ScanStatus.ERROR, (), f"saida bandit invalida: {exc}")
        return ScanResult(self.name, ScanStatus.OK, tuple(findings), "")
