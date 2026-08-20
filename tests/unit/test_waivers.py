"""Waivers: expiração obrigatória, invariantes (CRITICAL/segredo/KEV nunca waivable), store fail-closed."""
from __future__ import annotations

from datetime import date
from pathlib import Path

from secpipe.adapters.waiver_store import load_waivers
from secpipe.domain import Finding, Severity
from secpipe.domain.waivers import Waiver, is_waivable, partition

_TODAY = date(2026, 8, 19)
_FUTURE = "2099-12-31"
_PAST = "2000-01-01"


def test_is_active() -> None:
    assert Waiver("fp", expires=_FUTURE).is_active(_TODAY) is True
    assert Waiver("fp", expires=_PAST).is_active(_TODAY) is False
    assert Waiver("fp", expires="").is_active(_TODAY) is False        # expiração obrigatória
    assert Waiver("fp", expires="nao-e-data").is_active(_TODAY) is False


def test_is_waivable_invariants() -> None:
    assert is_waivable(Finding("t", "r", Severity.HIGH, "m", "a.py", 1, cwe="CWE-79")) is True
    assert is_waivable(Finding("t", "r", Severity.CRITICAL, "m", "a.py", 1)) is False
    assert is_waivable(Finding("t", "r", Severity.HIGH, "m", "a.py", 1, cwe="CWE-798")) is False   # segredo
    assert is_waivable(Finding("t", "r", Severity.HIGH, "m", "a.py", 1, kev=True)) is False        # KEV


def test_partition() -> None:
    waivable = Finding("bandit", "B1", Severity.HIGH, "m", "a.py", 1, cwe="CWE-79")
    critical = Finding("bandit", "B2", Severity.CRITICAL, "m", "b.py", 2, cwe="CWE-89")
    waivers = [Waiver(waivable.fingerprint, expires=_FUTURE), Waiver(critical.fingerprint, expires=_FUTURE)]
    remaining, waived = partition([waivable, critical], waivers, _TODAY)
    assert waived == [waivable]                       # o waivable foi isento
    assert critical in remaining and len(remaining) == 1   # CRITICAL NUNCA isenta, mesmo com waiver ativo


def test_expired_waiver_does_not_apply() -> None:
    f = Finding("bandit", "B1", Severity.HIGH, "m", "a.py", 1, cwe="CWE-79")
    remaining, waived = partition([f], [Waiver(f.fingerprint, expires=_PAST)], _TODAY)
    assert waived == [] and remaining == [f]


def test_load_waivers_skips_malformed(tmp_path: Path) -> None:
    p = tmp_path / "waivers.yml"
    p.write_text(
        "waivers:\n"
        "  - fingerprint: abc123\n    expires: 2099-01-01\n    owner: sec\n"
        "  - reason: sem fingerprint\n"          # malformado -> ignorado
        "  - fingerprint: def456\n",             # sem expires -> ignorado
        encoding="utf-8",
    )
    waivers = load_waivers(str(p))
    assert len(waivers) == 1 and waivers[0].fingerprint == "abc123"


def test_load_waivers_missing_file(tmp_path: Path) -> None:
    assert load_waivers(str(tmp_path / "nope.yml")) == []
