"""config-validate: pega misconfig silenciosa (typo de chave, scanner/severidade inválidos)."""
from __future__ import annotations

from pathlib import Path

from secpipe.application.use_cases.config_validate import validate_config

_KNOWN = frozenset({"gitleaks", "semgrep", "trivy", "bandit", "pip-audit", "dast"})


def _write(tmp_path: Path, text: str) -> str:
    p = tmp_path / ".secpipe.yml"
    p.write_text(text, encoding="utf-8")
    return str(p)


def test_valid_config_has_no_errors(tmp_path: Path) -> None:
    path = _write(tmp_path, "scanners: [gitleaks, bandit]\nblock_severity: HIGH\nmin_scanners: 1\n")
    assert validate_config(path, _KNOWN) == []


def test_unknown_key_detected(tmp_path: Path) -> None:
    path = _write(tmp_path, "scaners: [gitleaks]\n")  # typo
    errors = validate_config(path, _KNOWN)
    assert any("desconhecida" in e and "scaners" in e for e in errors)


def test_unknown_scanner_detected(tmp_path: Path) -> None:
    path = _write(tmp_path, "scanners: [gitleaks, nao-existe]\n")
    assert any("nao-existe" in e for e in validate_config(path, _KNOWN))


def test_invalid_block_severity(tmp_path: Path) -> None:
    path = _write(tmp_path, "block_severity: SEVERE\n")
    assert any("block_severity" in e for e in validate_config(path, _KNOWN))


def test_require_not_in_scanners(tmp_path: Path) -> None:
    path = _write(tmp_path, "scanners: [gitleaks]\nrequire: [trivy]\n")
    assert any("require" in e and "trivy" in e for e in validate_config(path, _KNOWN))


def test_bad_min_scanners(tmp_path: Path) -> None:
    path = _write(tmp_path, "min_scanners: -1\n")
    assert any("min_scanners" in e for e in validate_config(path, _KNOWN))


def test_missing_file(tmp_path: Path) -> None:
    missing = str(tmp_path / "nope.yml")
    assert validate_config(missing, _KNOWN) == [f"arquivo nao encontrado: {missing}"]


def test_empty_file_is_valid(tmp_path: Path) -> None:
    assert validate_config(_write(tmp_path, ""), _KNOWN) == []
