"""Parser SARIF genérico (Semgrep/Trivy) -> contrato normalizado. Testado com fixtures reais."""
from __future__ import annotations

import json

import pytest

from secpipe.adapters.sarif import parse_sarif, run_sarif_scanner
from secpipe.domain import ScanStatus, Severity

_SEMGREP_LIKE = json.dumps({
    "version": "2.1.0",
    "runs": [{
        "tool": {"driver": {"name": "semgrep", "rules": [
            {"id": "python.sqli", "name": "SQL Injection",
             "properties": {"cwe": ["CWE-89: SQL Injection"], "security-severity": "8.5"}}
        ]}},
        "results": [{
            "ruleId": "python.sqli",
            "level": "error",
            "message": {"text": "possible SQL injection"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "app/db.py"}, "region": {"startLine": 12}}}],
        }],
    }],
})

_TRIVY_LIKE = json.dumps({
    "version": "2.1.0",
    "runs": [{
        "tool": {"driver": {"name": "Trivy", "rules": [{"id": "CVE-2024-0001"}]}},
        "results": [{
            "ruleId": "CVE-2024-0001",
            "level": "warning",
            "message": {"text": "vulnerable dependency"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "requirements.txt"}, "region": {"startLine": 3}}}],
            "properties": {"security-severity": "5.0"},
        }],
    }],
})


def test_parse_semgrep_like_maps_cwe_and_severity() -> None:
    fs = parse_sarif(_SEMGREP_LIKE, "semgrep")
    assert len(fs) == 1
    f = fs[0]
    assert f.tool == "semgrep"
    assert f.rule_id == "python.sqli"
    assert f.cwe == "CWE-89"
    assert f.severity is Severity.HIGH      # security-severity 8.5 -> HIGH
    assert f.file == "app/db.py" and f.line == 12


def test_parse_trivy_like_uses_security_severity() -> None:
    fs = parse_sarif(_TRIVY_LIKE, "trivy")
    assert len(fs) == 1
    assert fs[0].severity is Severity.MEDIUM  # 5.0 -> MEDIUM
    assert fs[0].rule_id == "CVE-2024-0001"


def test_level_fallback_when_no_security_severity() -> None:
    doc = json.dumps({"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "x"}},
        "results": [{"ruleId": "r", "level": "warning", "message": {"text": "m"}}]}]})
    assert parse_sarif(doc, "x")[0].severity is Severity.MEDIUM


def test_empty_is_safe_and_invalid_raises() -> None:
    assert parse_sarif("", "x") == []
    with pytest.raises(json.JSONDecodeError):
        parse_sarif("{not json", "x")


def test_missing_tool_is_skipped_not_error() -> None:
    # cross-platform: which() de um binário inexistente retorna None -> SKIPPED (não ERROR)
    res = run_sarif_scanner("ghost", "secpipe-nonexistent-binary-xyz", ["--x"])
    assert res.status is ScanStatus.SKIPPED
