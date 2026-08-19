"""Detecção de linguagem -> scanners recomendados."""
from __future__ import annotations

from secpipe.domain.languages import detect_from_paths, scanners_for


def test_detect_python_via_ext_and_marker() -> None:
    assert detect_from_paths(["src/app.py", "pyproject.toml"]) == {"python"}


def test_detect_multi() -> None:
    langs = detect_from_paths(["a.js", "package.json", "svc/main.go"])
    assert langs == {"javascript", "go"}


def test_scanners_for_python_adds_bandit_and_pip_audit() -> None:
    s = scanners_for({"python"})
    assert "bandit" in s and "pip-audit" in s
    assert s[:3] == ["gitleaks", "semgrep", "trivy"]


def test_scanners_for_empty_is_core_only() -> None:
    assert scanners_for(set()) == ["gitleaks", "semgrep", "trivy"]
