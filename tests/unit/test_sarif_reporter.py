"""SarifReporter emite SARIF 2.1.0 válido; round-trip recupera os campos-chave."""
from __future__ import annotations

import json

from secpipe.adapters.reporters import SarifReporter
from secpipe.adapters.sarif import parse_sarif
from secpipe.domain import Finding, Report, ScanResult, ScanStatus, Severity


def _report() -> Report:
    f = Finding("semgrep", "python.sqli", Severity.HIGH, "SQL injection", "app/db.py", 12, "CWE-89")
    return Report((ScanResult("semgrep", ScanStatus.OK, (f,)),))


def test_sarif_reporter_emits_valid_sarif() -> None:
    doc = json.loads(SarifReporter().render(_report()))
    assert doc["version"] == "2.1.0"
    result = doc["runs"][0]["results"][0]
    assert result["ruleId"] == "python.sqli"
    assert result["level"] == "error"                       # HIGH -> error
    assert result["properties"]["cwe"] == "CWE-89"
    assert "secpipe/v1" in result["partialFingerprints"]


def test_round_trip_recovers_finding() -> None:
    sarif = SarifReporter().render(_report())
    recovered = parse_sarif(sarif, "secpipe")
    assert len(recovered) == 1
    assert recovered[0].cwe == "CWE-89"
    assert recovered[0].severity is Severity.HIGH           # 8.0 security-severity -> HIGH
    assert recovered[0].file == "app/db.py" and recovered[0].line == 12
