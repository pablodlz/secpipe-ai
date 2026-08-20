"""Fixes da revisão adversarial (integridade do gate): diff-scope fail-closed, path-exclusion, waivers."""
from __future__ import annotations

from datetime import date
from pathlib import Path

from secpipe.application.use_cases.diff import get_added_lines
from secpipe.domain import Finding, Report, ScanResult, ScanStatus, Severity
from secpipe.domain.waivers import Waiver, partition_results


def _rep(*findings: Finding) -> Report:
    return Report((ScanResult("t", ScanStatus.OK, tuple(findings)),))


# ── fix #1/#10: get_added_lines sinaliza falha do git com None (nao {} silencioso) ──
def test_get_added_lines_none_on_git_failure(tmp_path: Path) -> None:
    # tmp_path nao e repo git -> git diff falha -> None (fail-closed no chamador)
    assert get_added_lines(str(tmp_path), "HEAD") is None


# ── fix #2: path-exclusion nao esconde primeiro-partido nem segredo/CRITICAL/KEV ──
def test_first_party_dirs_not_excluded() -> None:
    # 'tools/'/'build/'/'dist/'/'vendor/' voltaram a ser escaneados (primeiro-partido)
    f = Finding("gitleaks", "k", Severity.HIGH, "key", "tools/deploy.py", 1, cwe="CWE-798")
    assert len(_rep(f).findings) == 1


def test_third_party_noise_still_excluded() -> None:
    noise = Finding("semgrep", "r", Severity.HIGH, "x", "node_modules/lib/a.js", 1, cwe="CWE-79")
    assert _rep(noise).findings == []


def test_secret_and_critical_never_excluded_even_in_thirdparty() -> None:
    secret = Finding("gitleaks", "k", Severity.HIGH, "key", "node_modules/x.js", 1, cwe="CWE-798")
    crit = Finding("t", "r", Severity.CRITICAL, "x", ".venv/lib/a.py", 1, cwe="CWE-89")
    kev = Finding("trivy", "CVE-1", Severity.MEDIUM, "x", "node_modules/y.js", 1, kev=True)
    assert len(_rep(secret).findings) == 1   # segredo em node_modules NUNCA escondido
    assert len(_rep(crit).findings) == 1     # CRITICAL idem
    assert len(_rep(kev).findings) == 1      # KEV idem


# ── fix #3: waiver por fingerprint nao dropa CRITICAL/KEV co-localizado ──
def test_partition_results_keeps_colocated_critical() -> None:
    high = Finding("osv", "CVE-1", Severity.HIGH, "vuln", "lock.json", 5, cwe="CWE-400")
    crit = Finding("trivy", "CVE-1", Severity.CRITICAL, "vuln", "lock.json", 5, cwe="CWE-400")
    assert high.fingerprint == crit.fingerprint          # colidem (fingerprint omite severity)
    results = (ScanResult("osv", ScanStatus.OK, (high,)), ScanResult("trivy", ScanStatus.OK, (crit,)))
    new_results, waived = partition_results(results, [Waiver(high.fingerprint, expires="2099-01-01")],
                                            date(2026, 8, 20))
    kept = [f for r in new_results for f in r.findings]
    assert waived == [high] and crit in kept and high not in kept   # CRITICAL sobrevive
