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


def test_detects_iac_terraform_and_docker() -> None:
    langs = detect_from_paths(["infra/main.tf", "Dockerfile", "src/app.py"])
    assert {"terraform", "docker", "python"} <= langs


def test_scanners_for_iac_adds_checkov_hadolint() -> None:
    s = scanners_for({"docker"})
    assert "checkov" in s and "hadolint" in s and s[:3] == ["gitleaks", "semgrep", "trivy"]
    assert "checkov" in scanners_for({"terraform"})


def test_scanners_for_go_adds_gosec() -> None:
    assert "gosec" in scanners_for({"go"})


def test_scanners_for_core_unchanged() -> None:
    assert scanners_for(set()) == ["gitleaks", "semgrep", "trivy"]
    assert scanners_for({"python"}) == ["gitleaks", "semgrep", "trivy", "bandit", "pip-audit"]
