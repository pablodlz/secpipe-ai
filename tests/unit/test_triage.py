"""Triage hints: sinaliza test-path/gerado/prioridade; NUNCA muda severidade nem o gate."""
from __future__ import annotations

import json

from secpipe.adapters.reporters import JsonReporter
from secpipe.domain import Finding, GatePolicy, Report, ScanResult, ScanStatus, Severity
from secpipe.domain.triage import triage


def test_in_test_path() -> None:
    assert triage(Finding("t", "r", Severity.HIGH, "m", "tests/test_x.py", 1))["in_test_path"] is True
    assert triage(Finding("t", "r", Severity.HIGH, "m", "src/app.py", 1))["in_test_path"] is False


def test_generated_file() -> None:
    assert triage(Finding("t", "r", Severity.HIGH, "m", "static/app.min.js", 1))["generated_file"] is True
    assert triage(Finding("t", "r", Severity.HIGH, "m", "dist/bundle.js", 1))["generated_file"] is True


def test_priority_kev_highest() -> None:
    assert triage(Finding("t", "r", Severity.MEDIUM, "m", "a.py", 1, kev=True))["priority"] == 5
    assert triage(Finding("t", "r", Severity.HIGH, "m", "a.py", 1))["priority"] == int(Severity.HIGH)
    # em test-path a prioridade cai (mas continua visível/no gate)
    assert triage(Finding("t", "r", Severity.HIGH, "m", "tests/x.py", 1))["priority"] < int(Severity.HIGH)


def test_triage_never_changes_gate() -> None:
    # um HIGH em tests/ AINDA bloqueia o gate (triage é só ordem de trabalho)
    f = Finding("bandit", "B1", Severity.HIGH, "m", "tests/test_x.py", 1, cwe="CWE-79")
    rep = Report((ScanResult("bandit", ScanStatus.OK, (f,)),))
    assert GatePolicy().evaluate(rep).passed is False


def test_reporter_includes_triage() -> None:
    f = Finding("bandit", "B1", Severity.HIGH, "m", "a.py", 1, cwe="CWE-79")
    doc = json.loads(JsonReporter().render(Report((ScanResult("bandit", ScanStatus.OK, (f,)),))))
    assert "triage" in doc["findings"][0] and "priority" in doc["findings"][0]["triage"]
