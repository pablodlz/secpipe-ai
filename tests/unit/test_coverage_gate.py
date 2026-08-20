"""Coverage gate: 0 scanners (ou 'require' ausente) NÃO pode passar verde — é falso-verde (fail-closed)."""
from __future__ import annotations

from secpipe.domain import Finding, GatePolicy, Report, ScanResult, ScanStatus, Severity


def _rep(*results: ScanResult) -> Report:
    return Report(tuple(results))


def test_zero_scanners_fails_closed() -> None:
    decision = GatePolicy().evaluate(_rep())  # nenhum resultado -> ran==0
    assert decision.passed is False
    assert "cobertura" in decision.reason.lower()


def test_all_skipped_fails_closed() -> None:
    rep = _rep(ScanResult("gitleaks", ScanStatus.SKIPPED), ScanResult("trivy", ScanStatus.SKIPPED))
    assert GatePolicy().evaluate(rep).passed is False  # ran==0


def test_one_scanner_ran_and_clean_passes() -> None:
    rep = _rep(ScanResult("bandit", ScanStatus.OK, ()))
    assert GatePolicy().evaluate(rep).passed is True


def test_require_scanner_not_run_fails() -> None:
    rep = _rep(ScanResult("bandit", ScanStatus.OK, ()), ScanResult("gitleaks", ScanStatus.SKIPPED))
    policy = GatePolicy(require_scanners=frozenset({"gitleaks"}))
    decision = policy.evaluate(rep)
    assert decision.passed is False and "gitleaks" in decision.reason


def test_require_scanner_satisfied_passes() -> None:
    rep = _rep(ScanResult("gitleaks", ScanStatus.OK, ()))
    assert GatePolicy(require_scanners=frozenset({"gitleaks"})).evaluate(rep).passed is True


def test_min_scanners_two_with_one_fails() -> None:
    rep = _rep(ScanResult("bandit", ScanStatus.OK, ()))
    assert GatePolicy(min_scanners=2).evaluate(rep).passed is False


def test_high_finding_still_blocks_with_coverage_ok() -> None:
    f = Finding("bandit", "B602", Severity.HIGH, "x", "a.py", 1)
    rep = _rep(ScanResult("bandit", ScanStatus.OK, (f,)))
    assert GatePolicy().evaluate(rep).passed is False  # cobertura OK, mas HIGH bloqueia
