"""Reporters: serializam o Report. JsonReporter é o contrato machine-first para a IA (ADR-0004)."""
from __future__ import annotations

import json

from secpipe.domain import Report


class JsonReporter:
    name = "json"

    def render(self, report: Report) -> str:
        payload = {
            "schema_version": "0",
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
                }
                for f in report.findings
            ],
        }
        return json.dumps(payload, ensure_ascii=False, indent=2)
