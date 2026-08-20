"""Reporters: serializam o Report. JsonReporter é o contrato machine-first para a IA; SarifReporter é a
interop (GitHub code scanning). Ambos ADR-0004."""
from __future__ import annotations

import json

from secpipe.domain import Report, Severity
from secpipe.domain.abstention import escalates
from secpipe.domain.correlation import correlate
from secpipe.domain.triage import triage

# nossa severidade -> SARIF level + security-severity numérica (convenção GitHub)
_LEVEL = {
    Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning",
    Severity.LOW: "note", Severity.INFO: "note",
}
_SCORE = {
    Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.0",
    Severity.LOW: "2.0", Severity.INFO: "0.0",
}


class JsonReporter:
    name = "json"

    def render(self, report: Report) -> str:
        findings = report.findings
        correlations = correlate(findings)
        correlated_cwes = {c.cwe for c in correlations}
        payload = {
            "schema_version": "1",   # 1: findings ganham epss/kev opcionais (enrichment)
            "scanners_ran": report.ran,   # 0 => nada escaneado; gate verde NAO significa seguro
            "correlations": [
                {"cwe": c.cwe, "dast_rule": c.dast_rule, "static_refs": list(c.static_refs),
                 "severity": c.severity.name}
                for c in correlations
            ],
            "results": [
                {"tool": r.tool, "status": r.status.value, "detail": r.detail}
                for r in report.results
            ],
            "findings": [
                {
                    "tool": f.tool,
                    "rule_id": f.rule_id,
                    "severity": f.severity.name,
                    "cwe": f.cwe,
                    "file": f.file,
                    "line": f.line,
                    "message": f.message,
                    "fingerprint": f.fingerprint,
                    "escalate": escalates(f.cwe, f.severity),
                    **({"epss": f.epss} if f.epss is not None else {}),
                    **({"kev": True} if f.kev else {}),
                    **({"correlated": True} if f.cwe in correlated_cwes else {}),
                    "triage": triage(f),   # contexto p/ priorizar (NUNCA muda o gate)
                }
                for f in findings
            ],
        }
        return json.dumps(payload, ensure_ascii=False, indent=2)


class SarifReporter:
    """Emite o Report como SARIF 2.1.0 — para o GitHub code scanning (Security tab)."""
    name = "sarif"

    def render(self, report: Report) -> str:
        findings = report.findings
        rule_ids = list(dict.fromkeys(f.rule_id for f in findings))
        rules = [{"id": rid, "name": rid} for rid in rule_ids]
        results = [
            {
                "ruleId": f.rule_id,
                "level": _LEVEL.get(f.severity, "warning"),
                "message": {"text": f.message or f.rule_id},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file or "UNKNOWN"},
                            "region": {"startLine": max(1, f.line)},
                        }
                    }
                ],
                "partialFingerprints": {"secpipe/v1": f.fingerprint},
                "properties": {"cwe": f.cwe, "security-severity": _SCORE.get(f.severity, "5.0")},
            }
            for f in findings
        ]
        doc = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "secpipe", "rules": rules}}, "results": results}],
        }
        return json.dumps(doc, ensure_ascii=False, indent=2)
