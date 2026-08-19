"""A lógica de parsing já é real e testada (o padrão dos adapters)."""
from __future__ import annotations

from secpipe.adapters.gitleaks import parse_gitleaks
from secpipe.domain import Severity

_FIXTURE = """
[{"RuleID": "aws-access-key", "Description": "AWS key", "File": "app/config.py", "StartLine": 42}]
"""


def test_parse_gitleaks_maps_to_normalized_finding() -> None:
    findings = parse_gitleaks(_FIXTURE)
    assert len(findings) == 1
    f = findings[0]
    assert f.tool == "gitleaks"
    assert f.severity is Severity.HIGH
    assert f.cwe == "CWE-798"
    assert f.file == "app/config.py"
    assert f.line == 42


def test_parse_empty_is_safe() -> None:
    assert parse_gitleaks("") == []
