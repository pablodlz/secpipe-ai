"""Reachability-lite: mapeamento pacote->modulo, anotação (só SCA), índice de imports; nunca muda o gate."""
from __future__ import annotations

import json
from pathlib import Path

from secpipe.adapters.reporters import JsonReporter
from secpipe.application.use_cases.reachability import build_import_index
from secpipe.domain import Finding, GatePolicy, Report, ScanResult, ScanStatus, Severity
from secpipe.domain.reachability import annotate, module_of, package_of


def test_module_of_aliases() -> None:
    assert module_of("PyYAML") == "yaml"
    assert module_of("beautifulsoup4") == "bs4"
    assert module_of("requests") == "requests"
    assert module_of("python-dateutil") == "dateutil"


def test_package_of() -> None:
    assert package_of(Finding("npm-audit", "npm/express", Severity.HIGH, "x")) == "express"
    assert package_of(Finding("pip-audit", "PYSEC-1", Severity.HIGH, "requests 2.0: CVE-x")) == "requests"


def test_annotate_reachable_and_unreachable() -> None:
    imported = {"requests"}
    used = Finding("pip-audit", "P1", Severity.HIGH, "requests 2.0: vuln", "requirements.txt", 0)
    unused = Finding("pip-audit", "P2", Severity.HIGH, "leftpad 1.0: vuln", "requirements.txt", 0)
    sast = Finding("bandit", "B602", Severity.HIGH, "shell", "a.py", 1)
    out = annotate([used, unused, sast], imported)
    assert out[0].reachable is True and out[1].reachable is False
    assert out[2].reachable is None   # não-SCA -> não avaliado


def test_build_import_index(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("import yaml\nfrom requests import get\n", encoding="utf-8")
    (tmp_path / "b.js").write_text("const e = require('express')\n", encoding="utf-8")
    idx = build_import_index(str(tmp_path))
    assert {"yaml", "requests", "express"} <= idx


def test_reachability_never_changes_gate() -> None:
    f = Finding("pip-audit", "P1", Severity.HIGH, "leftpad 1.0: vuln", "requirements.txt", 0)
    annotated = annotate([f], set())[0]   # reachable=False
    rep = Report((ScanResult("pip-audit", ScanStatus.OK, (annotated,)),))
    assert GatePolicy().evaluate(rep).passed is False   # HIGH ainda bloqueia (reachable só anota)


def test_reporter_emits_reachable() -> None:
    f = annotate([Finding("npm-audit", "npm/express", Severity.HIGH, "x", "package-lock.json", 0)], {"express"})[0]
    doc = json.loads(JsonReporter().render(Report((ScanResult("npm-audit", ScanStatus.OK, (f,)),))))
    assert doc["findings"][0]["reachable"] is True
