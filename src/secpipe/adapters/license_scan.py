"""Adapter License — conformidade de licenças SPDX via trivy (já embutido; sem dep nova). GRÁTIS, KEYLESS.

Opt-in: precisa de uma política `licenses:` na config. Sem política -> SKIPPED. A avaliação deny/allow é
determinística e mora no domínio (domain/licenses.py)."""
from __future__ import annotations

import json

from secpipe.adapters.base import run_tool, tool_on_path
from secpipe.domain import Finding, ScanResult, ScanStatus
from secpipe.domain.licenses import LicensePolicy, classify_license

NAME = "license"
BINARY = "trivy"
_SKIP_DIRS = ".venv,venv,node_modules,tools,dist,build,.tox,vendor"


def parse_trivy_licenses(raw: str, policy: LicensePolicy) -> list[Finding]:
    """JSON do `trivy fs --scanners license` -> Finding[] segundo a política deny/allow."""
    if not raw.strip():
        return []
    data = json.loads(raw)
    findings: list[Finding] = []
    for result in data.get("Results") or []:
        if not isinstance(result, dict):
            continue
        target = str(result.get("Target") or "")
        for lic in result.get("Licenses") or []:
            if not isinstance(lic, dict):
                continue
            name = str(lic.get("Name") or "")
            sev = classify_license(name, policy)
            if sev is None:
                continue
            pkg = str(lic.get("PkgName") or "")
            fpath = str(lic.get("FilePath") or target)
            findings.append(Finding(
                tool=NAME, rule_id=f"license/{name or 'unknown'}", severity=sev,
                message=f"licenca {name or 'desconhecida'}{f' em {pkg}' if pkg else ''}",
                file=fpath, line=0, cwe="",
            ))
    return findings


class LicenseScanner:
    name = NAME

    def __init__(self, policy: LicensePolicy | None = None) -> None:
        self.policy = policy

    def is_available(self) -> bool:
        return tool_on_path(BINARY)

    def scan(self, target: str) -> ScanResult:
        if self.policy is None:
            return ScanResult(self.name, ScanStatus.SKIPPED, (), "sem politica 'licenses:' no .secpipe.yml")
        if not tool_on_path(BINARY):
            return ScanResult(self.name, ScanStatus.SKIPPED, (), "trivy ausente no PATH")
        run = run_tool(BINARY, ["fs", "--scanners", "license", "--format", "json", "--quiet",
                                "--skip-dirs", _SKIP_DIRS, target], timeout=600)
        if run.timed_out:
            return ScanResult(self.name, ScanStatus.ERROR, (), "timeout")
        try:
            findings = parse_trivy_licenses(run.stdout, self.policy)
        except (json.JSONDecodeError, ValueError, TypeError) as exc:
            return ScanResult(self.name, ScanStatus.ERROR, (), f"saida trivy license invalida: {str(exc)[:200]}")
        return ScanResult(self.name, ScanStatus.OK, tuple(findings), "")
