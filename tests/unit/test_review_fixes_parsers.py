"""Fixes da revisão: guardas de tipo nos parsers, severidade INFO no SARIF, escaping em anotações/markdown."""
from __future__ import annotations

import json

import pytest

from secpipe.adapters.dast_zap import parse_zap_report
from secpipe.adapters.gitleaks import parse_gitleaks
from secpipe.adapters.reporters_human import GithubAnnotationsReporter
from secpipe.adapters.sarif import parse_sarif
from secpipe.application.use_cases.threat_model import ThreatModel, render_markdown
from secpipe.domain import Finding, Report, ScanResult, ScanStatus, Severity


# ── #11/#12: JSON válido não-objeto/não-lista -> ValueError (ERROR fail-closed), não AttributeError ──
@pytest.mark.parametrize("raw", ["[]", "null", "42", '"x"'])
def test_sarif_nonobject_raises_valueerror(raw: str) -> None:
    with pytest.raises(ValueError):
        parse_sarif(raw, "t")


@pytest.mark.parametrize("raw", ["[]", "null", "42"])
def test_zap_nonobject_raises_valueerror(raw: str) -> None:
    with pytest.raises(ValueError):
        parse_zap_report(raw)


@pytest.mark.parametrize("raw", ["{}", "null", "42"])
def test_gitleaks_nonlist_raises_valueerror(raw: str) -> None:
    with pytest.raises(ValueError):
        parse_gitleaks(raw)


# ── #13: security-severity 0.0 -> INFO (não é descartado pela truthiness) ──
def test_sarif_zero_score_is_info() -> None:
    doc = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "t", "rules": []}}, "results": [
        {"ruleId": "r", "message": {"text": "x"}, "properties": {"security-severity": "0.0"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.py"}, "region": {"startLine": 1}}}]}]}]}
    findings = parse_sarif(json.dumps(doc), "t")
    assert findings[0].severity is Severity.INFO


# ── #8: anotação GitHub escapa \n em file/rule_id (sem injeção de workflow-command) ──
def test_github_annotation_escapes_file_and_rule() -> None:
    f = Finding("t", "rule\n::error::x", Severity.HIGH, "m", "weird\n::error::forged", 1)
    out = GithubAnnotationsReporter().render(Report((ScanResult("t", ScanStatus.OK, (f,)),)))
    assert "\n" not in out                    # uma única linha (nenhuma quebra injetada)
    assert "%0A" in out                       # newline escapado
    assert "::error::forged" not in out       # comando forjado neutralizado


# ── #9: threat-model markdown escapa pipe/backtick nas células ──
def test_threat_model_markdown_escapes_cells() -> None:
    f = Finding("t", "rule|pipe", Severity.HIGH, "m", "a|b.py", 1, cwe="CWE-79")
    md = render_markdown(ThreatModel("app", (), (f,)))
    assert "rule\\|pipe" in md                 # pipe escapado no rule_id
    assert "a\\|b.py" in md                    # pipe escapado no local
