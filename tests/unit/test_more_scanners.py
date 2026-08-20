"""npm-audit (parser), gitleaks-history (skip fora de git) e o `import` genérico de SARIF."""
from __future__ import annotations

import json
from pathlib import Path

from secpipe.adapters.gitleaks_history import GitleaksHistoryScanner
from secpipe.adapters.npm_audit import parse_npm_audit
from secpipe.cli import main
from secpipe.domain import ScanStatus, Severity

_NPM = {
    "auditReportVersion": 2,
    "vulnerabilities": {
        "minimist": {"name": "minimist", "severity": "high",
                     "via": [{"title": "Prototype Pollution", "cwe": ["CWE-1321"]}]},
        "lodash": {"name": "lodash", "severity": "critical", "via": [{"title": "RCE", "cwe": ["CWE-94"]}]},
    },
}


def test_parse_npm_audit_maps_severity_and_cwe() -> None:
    findings = parse_npm_audit(json.dumps(_NPM))
    by = {f.rule_id: f for f in findings}
    assert by["npm/minimist"].severity is Severity.HIGH and by["npm/minimist"].cwe == "CWE-1321"
    assert by["npm/lodash"].severity is Severity.CRITICAL and "lodash" in by["npm/lodash"].message


def test_parse_npm_audit_empty_and_v6() -> None:
    assert parse_npm_audit("") == []
    assert parse_npm_audit('{"advisories": {}}') == []   # formato v6 -> degrada para vazio


def test_gitleaks_history_skips_outside_git(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x=1\n", encoding="utf-8")
    # sem gitleaks/git no PATH OU sem .git -> SKIPPED (nunca ERROR)
    assert GitleaksHistoryScanner().scan(str(tmp_path)).status is ScanStatus.SKIPPED


def _sarif(rule: str, level: str) -> str:
    return json.dumps({"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "codeql", "rules": [{"id": rule}]}},
        "results": [{"ruleId": rule, "level": level, "message": {"text": "x"},
                     "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.py"},
                                                         "region": {"startLine": 1}}}]}]}]})


def test_import_gate_fails_on_error_level(tmp_path: Path, capsys) -> None:
    p = tmp_path / "ext.sarif"
    p.write_text(_sarif("js/sql-injection", "error"), encoding="utf-8")   # error -> HIGH -> block
    assert main(["import", str(p), "--tool", "codeql"]) == 1
    assert "js/sql-injection" in capsys.readouterr().out


def test_import_gate_passes_on_note_level(tmp_path: Path) -> None:
    p = tmp_path / "ext.sarif"
    p.write_text(_sarif("style/x", "note"), encoding="utf-8")   # note -> LOW -> pass
    assert main(["import", str(p), "--tool", "codeql"]) == 0
