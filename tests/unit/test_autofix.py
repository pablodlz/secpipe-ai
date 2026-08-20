"""Loop headless de auto-fix: patch bom->fixed; REJECT->revertido; sensível->abstained; sem provedor->
escalated (fail-closed); dry-run não aplica. Mocka scan/verify/patch (sem rede, sem scanners reais)."""
from __future__ import annotations

import secpipe.application.use_cases.autofix as af
from secpipe.application.use_cases.autofix import run_autofix
from secpipe.cli import main
from secpipe.domain import Finding, Report, ScanResult, ScanStatus, Severity


class _Orch:
    def __init__(self, findings: list[Finding]) -> None:
        self._f = findings

    def run(self, target: str) -> tuple[Report, None]:
        return Report((ScanResult("t", ScanStatus.OK, tuple(self._f)),)), None


class _Prov:
    name = "fake"

    def __init__(self, *, up: bool = True, diff: str = "--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n") -> None:
        self._up = up
        self._diff = diff
        self.called = False

    def available(self) -> bool:
        return self._up

    def complete(self, prompt: str) -> str:
        self.called = True
        return self._diff


class _Verdict:
    def __init__(self, ok: bool) -> None:
        self.accepted = ok
        self.reasons: list[str] = []


_HIGH = Finding("bandit", "B602", Severity.HIGH, "subprocess shell=True", "app.py", 1, cwe="CWE-78")


def _OK_APPLY(t: str, d: str) -> tuple[bool, str]:
    return (True, "")


def _OK_REVERT(t: str, d: str) -> bool:
    return True


def test_fixed_when_verify_accepts(monkeypatch) -> None:
    monkeypatch.setattr(af, "run_verify", lambda *a, **k: _Verdict(True))
    out = run_autofix(_Orch([_HIGH]), _Prov(), ".", apply_fn=_OK_APPLY, revert_fn=_OK_REVERT)
    assert out.count("fixed") == 1 and out.resolved


def test_rejected_reverts(monkeypatch) -> None:
    reverted: dict[str, bool] = {}
    monkeypatch.setattr(af, "run_verify", lambda *a, **k: _Verdict(False))
    out = run_autofix(_Orch([_HIGH]), _Prov(), ".", apply_fn=_OK_APPLY,
                      revert_fn=lambda t, d: reverted.setdefault("r", True) is not None)
    assert out.count("rejected") == 1 and reverted.get("r") and not out.resolved


def test_abstains_on_critical_without_calling_provider() -> None:
    crit = Finding("t", "r", Severity.CRITICAL, "auth bypass", "a.py", 1, cwe="CWE-287")
    prov = _Prov()
    out = run_autofix(_Orch([crit]), prov, ".", apply_fn=_OK_APPLY, revert_fn=_OK_REVERT)
    assert out.count("abstained") == 1 and prov.called is False   # provider NUNCA chamado


def test_no_provider_is_failclosed() -> None:
    out = run_autofix(_Orch([_HIGH]), _Prov(up=False), ".", apply_fn=_OK_APPLY, revert_fn=_OK_REVERT)
    assert out.count("escalated") == 1 and not out.resolved


def test_dry_run_does_not_apply() -> None:
    applied: dict[str, bool] = {}
    out = run_autofix(_Orch([_HIGH]), _Prov(), ".", dry_run=True,
                      apply_fn=lambda t, d: (applied.setdefault("a", True), (True, ""))[1],
                      revert_fn=_OK_REVERT)
    assert out.count("would_fix") == 1 and "a" not in applied


def test_cli_autofix_requires_headless(capsys) -> None:
    assert main(["autofix", "."]) == 2   # sem --headless: erro, zero efeito
    assert "headless" in capsys.readouterr().err.lower()
