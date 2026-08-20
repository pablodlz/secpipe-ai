"""Reporters humanos: HTML/MD/github/badge. FOCO em ESCAPING (message vem de terceiros = XSS/injeção)."""
from __future__ import annotations

from secpipe.adapters.reporters_human import (
    GithubAnnotationsReporter,
    HtmlReporter,
    MarkdownReporter,
    render_badge,
)
from secpipe.domain import Finding, Report, ScanResult, ScanStatus, Severity


def _report(*findings: Finding) -> Report:
    return Report((ScanResult("t", ScanStatus.OK, tuple(findings)),))


_XSS = Finding("semgrep", "xss", Severity.HIGH, "<script>alert(1)</script>", "a|b.py", 5, cwe="CWE-79")


def test_html_escapes_payload() -> None:
    out = HtmlReporter().render(_report(_XSS))
    assert "<script>alert(1)</script>" not in out
    assert "&lt;script&gt;" in out


def test_markdown_neutralizes_pipes() -> None:
    out = MarkdownReporter().render(_report(_XSS))
    assert "a\\|b.py" in out           # pipe escapado (nao quebra a tabela)
    assert "FAIL" in out               # HIGH -> FAIL


def test_markdown_passes_when_clean() -> None:
    clean = Finding("t", "r", Severity.LOW, "ok", "a.py", 1)
    assert "PASS" in MarkdownReporter().render(_report(clean))


def test_github_annotations_escape_newlines() -> None:
    f = Finding("t", "r", Severity.HIGH, "line1\nline2", "a.py", 3)
    out = GithubAnnotationsReporter().render(_report(f))
    assert out.startswith("::error ") and "%0A" in out and "\n" not in out.split("::")[1]


def test_badge_reflects_gate() -> None:
    assert "PASS" in render_badge(_report(Finding("t", "r", Severity.LOW, "x")))
    assert "blocking" in render_badge(_report(_XSS)) and "<svg" in render_badge(_report(_XSS))
