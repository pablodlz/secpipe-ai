"""DAST depth: seleção baseline/full + timeout por modo; correlação DAST<->SAST no JsonReporter."""
from __future__ import annotations

import json

import secpipe.adapters.dast_zap as dz
from secpipe.adapters.base import ToolRun
from secpipe.adapters.dast_zap import _zap_script
from secpipe.adapters.reporters import JsonReporter
from secpipe.domain import Finding, Report, ScanResult, ScanStatus, Severity
from secpipe.domain.correlation import correlate
from secpipe.foundation.config import Config


def test_zap_script_selection() -> None:
    assert _zap_script("full") == "zap-full-scan.py"
    assert _zap_script("baseline") == "zap-baseline.py"
    assert _zap_script("xpto") == "zap-baseline.py"


def test_full_mode_argv_and_timeout(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_run_tool(binary, args, *, timeout=300, cwd=None):
        captured["args"] = args
        captured["timeout"] = timeout
        return ToolRun(missing=False, timed_out=False, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(dz, "tool_on_path", lambda b: b == "docker")
    monkeypatch.setattr(dz, "run_tool", fake_run_tool)
    dz._run_zap("http://x", mode="full", timeout=0)
    assert "zap-full-scan.py" in captured["args"] and captured["timeout"] == 3600


def test_config_parses_dast_mode_timeout() -> None:
    cfg = Config.from_dict({"dast": {"target_url": "http://x", "mode": "full", "timeout": 600}})
    assert cfg.dast_mode == "full" and cfg.dast_timeout == 600
    assert Config.from_dict({"dast": {"mode": "xpto"}}).dast_mode == "baseline"


def test_correlate_dast_and_sast() -> None:
    findings = [
        Finding("dast", "zap-40012", Severity.HIGH, "xss", "http://x/q", 0, cwe="CWE-79"),
        Finding("semgrep", "xss.rule", Severity.MEDIUM, "x", "a.py", 1, cwe="CWE-79"),
    ]
    corr = correlate(findings)
    assert len(corr) == 1 and corr[0].cwe == "CWE-79" and corr[0].severity is Severity.HIGH
    assert corr[0].static_refs == ("xss.rule",)


def test_no_correlation_single_side() -> None:
    assert correlate([Finding("dast", "z", Severity.HIGH, "x", "/q", 0, cwe="CWE-79")]) == []
    assert correlate([Finding("semgrep", "r", Severity.HIGH, "x", "a.py", 1, cwe="CWE-79")]) == []


def test_reporter_emits_correlations() -> None:
    rep = Report((ScanResult("m", ScanStatus.OK, (
        Finding("dast", "z", Severity.HIGH, "x", "/q", 0, cwe="CWE-89"),
        Finding("bandit", "B608", Severity.HIGH, "sqli", "a.py", 1, cwe="CWE-89"),
    )),))
    doc = json.loads(JsonReporter().render(rep))
    assert doc["correlations"] and doc["correlations"][0]["cwe"] == "CWE-89"
    assert all(f.get("correlated") for f in doc["findings"])
