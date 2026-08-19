"""O gate é determinístico e fail-closed — testado (é a régua do produto)."""
from __future__ import annotations

from secpipe.domain import Finding, GatePolicy, Report, ScanResult, ScanStatus, Severity


def _report(*findings: Finding, status: ScanStatus = ScanStatus.OK) -> Report:
    return Report((ScanResult("t", status, tuple(findings)),))


def test_high_finding_blocks() -> None:
    f = Finding("t", "r1", Severity.HIGH, "x", "a.py", 1)
    assert GatePolicy().evaluate(_report(f)).passed is False


def test_medium_passes_under_high_threshold() -> None:
    f = Finding("t", "r2", Severity.MEDIUM, "x", "a.py", 2)
    assert GatePolicy().evaluate(_report(f)).passed is True


def test_scanner_error_fails_closed() -> None:
    assert GatePolicy().evaluate(_report(status=ScanStatus.ERROR)).passed is False


def test_unknown_severity_is_treated_as_critical() -> None:
    assert Severity.parse("definitely-not-a-severity") is Severity.CRITICAL
