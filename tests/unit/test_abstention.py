"""Abstention: categorias sensíveis/CRITICAL são escaladas; o resto não."""
from __future__ import annotations

import json

from secpipe.adapters.reporters import JsonReporter
from secpipe.domain import Finding, Report, ScanResult, ScanStatus, Severity
from secpipe.domain.abstention import escalates


def test_sensitive_cwe_escalates() -> None:
    assert escalates("CWE-798", Severity.LOW) is True    # credencial hardcoded
    assert escalates("CWE-327", Severity.MEDIUM) is True  # cripto fraca


def test_critical_always_escalates() -> None:
    assert escalates("CWE-79", Severity.CRITICAL) is True


def test_ordinary_does_not_escalate() -> None:
    assert escalates("CWE-79", Severity.MEDIUM) is False


def test_reporter_surfaces_escalate_flag() -> None:
    f = Finding("gitleaks", "r", Severity.HIGH, "m", "a.py", 1, "CWE-798")
    doc = json.loads(JsonReporter().render(Report((ScanResult("s", ScanStatus.OK, (f,)),))))
    assert doc["findings"][0]["escalate"] is True
