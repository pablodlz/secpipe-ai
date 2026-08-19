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


def test_findings_in_vendored_dirs_are_excluded() -> None:
    from secpipe.domain import Finding, Report, ScanResult, ScanStatus, Severity
    real = Finding("bandit", "B1", Severity.HIGH, "m", "src/app.py", 1)
    venv = Finding("trivy", "CVE", Severity.HIGH, "m", ".venv/Lib/site-packages/x/METADATA", 1)
    node = Finding("trivy", "CVE2", Severity.HIGH, "m", "node_modules/y/index.js", 2)
    rep = Report((ScanResult("s", ScanStatus.OK, (real, venv, node)),))
    files = [f.file for f in rep.findings]
    assert files == ["src/app.py"]   # só o código do projeto
