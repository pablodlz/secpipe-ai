"""Dedup por fingerprint entre scanners (evita ruído para a IA)."""
from __future__ import annotations

from secpipe.domain import Finding, Report, ScanResult, ScanStatus, Severity


def test_findings_are_deduped_by_fingerprint() -> None:
    a = Finding("gitleaks", "r", Severity.HIGH, "m", "a.py", 10, "CWE-798")
    b = Finding("semgrep", "r", Severity.HIGH, "m2", "a.py", 10, "CWE-798")  # mesmo rule/cwe/file/line
    report = Report((
        ScanResult("gitleaks", ScanStatus.OK, (a,)),
        ScanResult("semgrep", ScanStatus.OK, (b,)),
    ))
    assert len(report.findings) == 1
