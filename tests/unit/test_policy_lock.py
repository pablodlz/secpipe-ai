"""Gate-integrity: detecta enfraquecimento da política; endurecer é permitido; lock ausente reprova."""
from __future__ import annotations

from pathlib import Path

from secpipe.application.use_cases.policy_guard import check_lock, write_lock
from secpipe.domain.policy_lock import make_snapshot, policy_hash, weaknesses

_BASE = make_snapshot("HIGH", ("gitleaks", "semgrep", "trivy"), ("gitleaks",), 1, True)


def test_hash_stable() -> None:
    reordered = make_snapshot("HIGH", ("trivy", "semgrep", "gitleaks"), ("gitleaks",), 1, True)
    assert policy_hash(_BASE) == policy_hash(reordered)   # ordem dos scanners não muda o hash


def test_block_severity_loosened_is_weaker() -> None:
    weaker = make_snapshot("CRITICAL", ("gitleaks", "semgrep", "trivy"), ("gitleaks",), 1, True)
    assert any("block_severity" in w for w in weaknesses(_BASE, weaker))


def test_stronger_is_ok() -> None:
    stronger = make_snapshot("MEDIUM", ("gitleaks", "semgrep", "trivy", "bandit"), ("gitleaks", "trivy"), 2, True)
    assert weaknesses(_BASE, stronger) == []


def test_removed_scanner_and_require_and_kev() -> None:
    weaker = make_snapshot("HIGH", ("gitleaks", "semgrep"), (), 1, False)
    problems = weaknesses(_BASE, weaker)
    assert any("scanners removidos" in p for p in problems)
    assert any("require removido" in p for p in problems)
    assert any("kev_blocks" in p for p in problems)


def test_min_scanners_lowered() -> None:
    weaker = make_snapshot("HIGH", ("gitleaks", "semgrep", "trivy"), ("gitleaks",), 0, True)
    assert any("min_scanners" in p for p in weaknesses(_BASE, weaker))


def test_check_lock_roundtrip(tmp_path: Path) -> None:
    lock = str(tmp_path / ".secpipe.lock")
    write_lock(lock, _BASE)
    ok, problems = check_lock(lock, _BASE)
    assert ok and problems == []


def test_check_lock_detects_weakening(tmp_path: Path) -> None:
    lock = str(tmp_path / ".secpipe.lock")
    write_lock(lock, _BASE)
    weaker = make_snapshot("CRITICAL", ("gitleaks",), (), 1, False)
    ok, problems = check_lock(lock, weaker)
    assert not ok and problems


def test_check_lock_missing(tmp_path: Path) -> None:
    ok, problems = check_lock(str(tmp_path / "nope.lock"), _BASE)
    assert not ok and "ausente" in problems[0]
