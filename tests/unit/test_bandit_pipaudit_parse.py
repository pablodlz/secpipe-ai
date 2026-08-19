"""Parsers dos adapters Python-específicos (Bandit SAST, pip-audit SCA), testados com fixtures."""
from __future__ import annotations

import json

from secpipe.adapters.bandit import parse_bandit
from secpipe.adapters.pip_audit import parse_pip_audit
from secpipe.domain import Severity

_BANDIT = json.dumps({
    "results": [{
        "test_id": "B602", "issue_severity": "HIGH", "issue_text": "subprocess with shell=True",
        "filename": "app.py", "line_number": 5, "issue_cwe": {"id": 78},
    }]
})

_PIP_AUDIT = json.dumps({
    "dependencies": [{
        "name": "requests", "version": "2.19.0",
        "vulns": [{"id": "PYSEC-2018-28", "fix_versions": ["2.20.0"], "description": "CRLF injection"}],
    }, {
        "name": "pyyaml", "version": "6.0.1", "vulns": [],
    }]
})


def test_parse_bandit_maps_cwe_and_severity() -> None:
    fs = parse_bandit(_BANDIT)
    assert len(fs) == 1
    f = fs[0]
    assert f.tool == "bandit" and f.rule_id == "B602"
    assert f.severity is Severity.HIGH
    assert f.cwe == "CWE-78"
    assert f.file == "app.py" and f.line == 5


def test_parse_pip_audit_one_vuln() -> None:
    fs = parse_pip_audit(_PIP_AUDIT)
    assert len(fs) == 1                       # só a dependência com vuln
    assert fs[0].tool == "pip-audit"
    assert fs[0].rule_id == "PYSEC-2018-28"
    assert fs[0].severity is Severity.HIGH
    assert "requests" in fs[0].message


def test_empty_inputs_are_safe() -> None:
    assert parse_bandit("") == []
    assert parse_pip_audit("") == []
