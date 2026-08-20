"""DAST (ZAP baseline): parser do relatório (fixture), gating opt-in e a ponte `dast-import` do CI.

O ZAP em si não roda no teste (é grande / precisa de docker) — validamos o PARSER, o SKIP e o GATE,
que é onde mora a lógica do secpipe (mesmo padrão do Codemodder, Linux-only)."""
from __future__ import annotations

import json
from pathlib import Path

from secpipe.adapters.dast_zap import ZapDastScanner, parse_zap_report, runner_available
from secpipe.cli import main
from secpipe.domain import ScanStatus, Severity

_ZAP_REPORT = {
    "@version": "2.14.0",
    "site": [
        {
            "@name": "http://localhost:8080",
            "alerts": [
                {"alertRef": "40012", "pluginid": "40012", "alert": "Cross Site Scripting (Reflected)",
                 "riskcode": "3", "cweid": "79",
                 "instances": [{"uri": "http://localhost:8080/q", "method": "GET"}]},
                {"alertRef": "10096", "pluginid": "10096", "alert": "Timestamp Disclosure",
                 "riskcode": "1", "cweid": "200", "instances": [{"uri": "http://localhost:8080/"}]},
                {"alertRef": "10021", "alert": "Sem CWE", "riskcode": "0", "cweid": "-1", "instances": []},
            ],
        }
    ],
}


def test_parse_zap_report_maps_risk_and_cwe() -> None:
    findings = parse_zap_report(json.dumps(_ZAP_REPORT))
    assert len(findings) == 3
    xss = next(f for f in findings if f.rule_id == "40012")
    assert xss.severity is Severity.HIGH and xss.cwe == "CWE-79" and "/q" in xss.file
    ts = next(f for f in findings if f.rule_id == "10096")
    assert ts.severity is Severity.LOW and ts.cwe == "CWE-200"
    nocwe = next(f for f in findings if f.rule_id == "10021")
    assert nocwe.cwe == "" and nocwe.severity is Severity.INFO   # cweid -1 -> sem cwe


def test_parse_empty_is_empty() -> None:
    assert parse_zap_report("") == []
    assert parse_zap_report('{"site": []}') == []


def test_scanner_skips_without_target() -> None:
    result = ZapDastScanner(target_url="").scan(".")
    assert result.status is ScanStatus.SKIPPED
    assert "target_url" in result.detail


def test_is_available_reflects_runner() -> None:
    assert ZapDastScanner("http://x").is_available() == runner_available()


def test_dast_import_gate_fails_on_high(tmp_path: Path, capsys) -> None:
    report = tmp_path / "report.json"
    report.write_text(json.dumps(_ZAP_REPORT), encoding="utf-8")
    code = main(["dast-import", str(report)])
    assert code == 1   # há um HIGH (XSS) -> gate FAIL
    out = capsys.readouterr()
    assert "CWE-79" in out.out


def test_dast_import_gate_passes_without_high(tmp_path: Path) -> None:
    low_only = {"site": [{"@name": "http://x", "alerts": [
        {"alertRef": "10096", "alert": "Timestamp", "riskcode": "1", "cweid": "200", "instances": []}]}]}
    report = tmp_path / "report.json"
    report.write_text(json.dumps(low_only), encoding="utf-8")
    assert main(["dast-import", str(report)]) == 0   # só LOW -> gate PASS
