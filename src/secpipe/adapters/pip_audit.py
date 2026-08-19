"""Adapter pip-audit (SCA específico de Python). Audita um requirements.txt do alvo, se existir.

Complementa o Trivy (que já faz SCA multi-linguagem). Se não houver requirements.txt, fica SKIPPED
(a cobertura de dependências Python vem do Trivy). A dedup por fingerprint lida com sobreposição."""
from __future__ import annotations

import json
import os

from secpipe.adapters.base import run_tool, tool_on_path
from secpipe.domain import Finding, ScanResult, ScanStatus, Severity

BINARY = "pip-audit"


def parse_pip_audit(raw: str, req_file: str = "requirements.txt") -> list[Finding]:
    """Converte o JSON do pip-audit em Findings. Uma dependência vulnerável => HIGH (default)."""
    if not raw.strip():
        return []
    data = json.loads(raw)
    deps = data.get("dependencies", []) if isinstance(data, dict) else data
    findings: list[Finding] = []
    for dep in deps or []:
        if not isinstance(dep, dict):
            continue
        name = str(dep.get("name", ""))
        version = str(dep.get("version", ""))
        for vuln in dep.get("vulns", []) or []:
            if not isinstance(vuln, dict):
                continue
            vid = str(vuln.get("id", "VULN"))
            fixes = ", ".join(str(f) for f in (vuln.get("fix_versions") or []))
            desc = str(vuln.get("description", "")).replace("\n", " ")
            msg = f"{name} {version}: {vid} (fix: {fixes or 'n/a'}) {desc}"
            findings.append(
                Finding(
                    tool="pip-audit", rule_id=vid, severity=Severity.HIGH,
                    message=msg[:300], file=req_file, line=0, cwe="",
                )
            )
    return findings


class PipAuditScanner:
    name = BINARY

    def is_available(self) -> bool:
        return tool_on_path(BINARY)

    def scan(self, target: str) -> ScanResult:
        req = os.path.join(target, "requirements.txt")
        if not os.path.isfile(req):
            return ScanResult(self.name, ScanStatus.SKIPPED, (), "sem requirements.txt (SCA via Trivy)")
        run = run_tool(BINARY, ["-r", req, "-f", "json", "--progress-spinner", "off"])
        if run.missing:
            return ScanResult(self.name, ScanStatus.SKIPPED, (), "ferramenta ausente no PATH")
        if run.timed_out:
            return ScanResult(self.name, ScanStatus.ERROR, (), "timeout")
        try:
            findings = parse_pip_audit(run.stdout, req)
        except (json.JSONDecodeError, ValueError) as exc:
            return ScanResult(self.name, ScanStatus.ERROR, (), f"saida pip-audit invalida: {exc}")
        return ScanResult(self.name, ScanStatus.OK, tuple(findings), "")
