"""Novos scanners SARIF (checkov/hadolint/gosec/osv-scanner): normalização via parse_sarif + SKIP honesto.

O binário real não roda no teste (mesmo padrão do dast/codemodder): validamos o PARSER (fixture SARIF) e
o comportamento de disponibilidade/skip, que é onde mora a lógica do secpipe."""
from __future__ import annotations

import json
from pathlib import Path

from secpipe.adapters.checkov import CheckovScanner
from secpipe.adapters.gosec import GosecScanner
from secpipe.adapters.hadolint import HadolintScanner, find_dockerfiles
from secpipe.adapters.osv_scanner import OsvScanner
from secpipe.adapters.sarif import parse_sarif
from secpipe.domain import ScanStatus, Severity


def _sarif(rule_id: str, level: str, uri: str, line: int = 1) -> str:
    return json.dumps({
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "t", "rules": [{"id": rule_id, "name": rule_id}]}},
            "results": [{
                "ruleId": rule_id, "level": level,
                "message": {"text": f"{rule_id} issue"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": uri}, "region": {"startLine": line}}}],
            }],
        }],
    })


def test_checkov_sarif_normalizes() -> None:
    f = parse_sarif(_sarif("CKV_AWS_20", "error", "terraform/s3.tf"), "checkov")
    assert len(f) == 1 and f[0].rule_id == "CKV_AWS_20" and f[0].severity is Severity.HIGH
    assert f[0].file == "terraform/s3.tf"


def test_hadolint_sarif_normalizes() -> None:
    f = parse_sarif(_sarif("DL3008", "warning", "Dockerfile", 3), "hadolint")
    assert f[0].rule_id == "DL3008" and f[0].severity is Severity.MEDIUM and f[0].line == 3


def test_gosec_and_osv_sarif_normalize() -> None:
    assert parse_sarif(_sarif("G404", "warning", "main.go"), "gosec")[0].severity is Severity.MEDIUM
    assert parse_sarif(_sarif("CVE-2021-23337", "warning", "package-lock.json"), "osv")[0].rule_id == "CVE-2021-23337"


def test_scanners_skip_when_tool_absent() -> None:
    # checkov/osv não estão instalados no ambiente de teste -> SKIPPED (nunca ERROR)
    assert CheckovScanner().scan(".").status is ScanStatus.SKIPPED
    assert OsvScanner().scan(".").status is ScanStatus.SKIPPED


def test_hadolint_skips_without_dockerfile(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("x=1\n", encoding="utf-8")
    assert HadolintScanner().scan(str(tmp_path)).status is ScanStatus.SKIPPED


def test_find_dockerfiles(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text("FROM x\n", encoding="utf-8")
    (tmp_path / "api.Dockerfile").write_text("FROM y\n", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("hi\n", encoding="utf-8")
    names = {Path(p).name for p in find_dockerfiles(str(tmp_path))}
    assert names == {"Dockerfile", "api.Dockerfile"}


def test_gosec_requires_go_toolchain(monkeypatch) -> None:
    import secpipe.adapters.gosec as g
    monkeypatch.setattr(g, "tool_on_path", lambda b: b == "gosec")  # gosec presente, go ausente
    assert GosecScanner().is_available() is False
