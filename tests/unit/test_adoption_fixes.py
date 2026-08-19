"""Correções do teste de adoção: Report.ran (falso-verde), scanners_ran no JSON, integração pre-commit."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from secpipe.adapters.reporters import JsonReporter
from secpipe.application.use_cases.init import init
from secpipe.domain import Report, ScanResult, ScanStatus


def test_report_ran_counts_only_executed() -> None:
    rep = Report((
        ScanResult("a", ScanStatus.SKIPPED),
        ScanResult("b", ScanStatus.OK, ()),
        ScanResult("c", ScanStatus.ERROR),
    ))
    assert rep.ran == 2


def test_all_skipped_flags_zero_in_json() -> None:
    rep = Report((ScanResult("a", ScanStatus.SKIPPED), ScanResult("b", ScanStatus.SKIPPED)))
    assert rep.ran == 0
    assert json.loads(JsonReporter().render(rep))["scanners_ran"] == 0


def _hookspath(root: Path) -> str:
    return subprocess.run(["git", "-C", str(root), "config", "--get", "core.hooksPath"],
                          capture_output=True, text=True, check=False).stdout.strip()


def test_init_integrates_with_existing_precommit_without_clobbering(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / ".pre-commit-config.yaml").write_text(
        "repos:\n  - repo: local\n    hooks: []\n", encoding="utf-8")
    init(str(tmp_path))
    cfg = (tmp_path / ".pre-commit-config.yaml").read_text(encoding="utf-8")
    assert "secpipe hook" in cfg          # hook integrado ao pre-commit existente
    assert _hookspath(tmp_path) == ""     # NÃO sequestrou core.hooksPath


def test_init_precommit_integration_is_idempotent(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / ".pre-commit-config.yaml").write_text("repos: []\n", encoding="utf-8")
    init(str(tmp_path))
    init(str(tmp_path))
    assert (tmp_path / ".pre-commit-config.yaml").read_text(encoding="utf-8").count("id: secpipe") == 1
