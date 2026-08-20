"""Adapter npm-audit (SCA de dependências JS/Node). GRÁTIS, KEYLESS. Saída JSON própria (não-SARIF)
-> parser dedicado (modelo bandit/pip-audit). Exige package-lock.json; SKIP sem lockfile (SCA multi-eco
fica por trivy/osv-scanner). Formato npm v7+ (auditReportVersion 2)."""
from __future__ import annotations

import json
import os

from secpipe.adapters.base import run_tool, tool_on_path
from secpipe.domain import Finding, ScanResult, ScanStatus, Severity

BINARY = "npm"
NAME = "npm-audit"
_LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json")
_SEV = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "moderate": Severity.MEDIUM,
        "low": Severity.LOW, "info": Severity.INFO}


def parse_npm_audit(raw: str) -> list[Finding]:
    """JSON do `npm audit --json` (v7+) -> Finding[]. Uma dependência vulnerável por advisory `via`."""
    if not raw.strip():
        return []
    data = json.loads(raw)
    vulns = data.get("vulnerabilities") if isinstance(data, dict) else None
    if not isinstance(vulns, dict):
        return []   # formato v6 (advisories) ou vazio -> nada (degrada em vez de crashar)
    findings: list[Finding] = []
    for pkg, info in vulns.items():
        if not isinstance(info, dict):
            continue
        severity = _SEV.get(str(info.get("severity", "")).lower(), Severity.MEDIUM)
        cwe, title = "", ""
        for via in info.get("via", []) or []:
            if isinstance(via, dict):
                cwes = via.get("cwe")
                if not cwe and isinstance(cwes, list) and cwes:
                    cwe = str(cwes[0])
                title = title or str(via.get("title", ""))
        msg = f"{pkg}: {title or 'dependencia vulneravel'}"
        findings.append(Finding(tool=NAME, rule_id=f"npm/{pkg}", severity=severity,
                                message=msg[:300], file="package-lock.json", line=0, cwe=cwe))
    return findings


class NpmAuditScanner:
    name = NAME

    def is_available(self) -> bool:
        return tool_on_path(BINARY)

    def scan(self, target: str) -> ScanResult:
        if not tool_on_path(BINARY):
            return ScanResult(self.name, ScanStatus.SKIPPED, (), "npm ausente no PATH")
        if not any(os.path.isfile(os.path.join(target, lf)) for lf in _LOCKFILES):
            return ScanResult(self.name, ScanStatus.SKIPPED, (), "sem package-lock.json (SCA via trivy/osv)")
        run = run_tool(BINARY, ["audit", "--json"], timeout=300, cwd=target)
        if run.timed_out:
            return ScanResult(self.name, ScanStatus.ERROR, (), "timeout")
        try:
            findings = parse_npm_audit(run.stdout)
        except (json.JSONDecodeError, ValueError, TypeError) as exc:
            return ScanResult(self.name, ScanStatus.ERROR, (), f"saida npm audit invalida: {str(exc)[:200]}")
        return ScanResult(self.name, ScanStatus.OK, tuple(findings), "")
