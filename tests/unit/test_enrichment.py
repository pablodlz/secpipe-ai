"""Enrichment EPSS/KEV: extração de CVE, merge (só ELEVA), KEV bloqueia o gate, fetch fail-open."""
from __future__ import annotations

import json

from secpipe.adapters import epss_kev
from secpipe.adapters.epss_kev import enrich_report
from secpipe.adapters.reporters import JsonReporter
from secpipe.domain import Finding, GatePolicy, Report, ScanResult, ScanStatus, Severity
from secpipe.domain.enrichment import apply_enrichment, extract_cves


def _f(rule: str = "CVE-2021-44228", sev: Severity = Severity.MEDIUM, msg: str = "log4j") -> Finding:
    return Finding("trivy", rule, sev, msg, "pom.xml", 1, cwe="CWE-502")


def test_extract_cves() -> None:
    assert extract_cves(_f("CVE-2021-44228")) == ["CVE-2021-44228"]
    assert extract_cves(Finding("t", "B602", Severity.HIGH, "no cve here")) == []


def test_apply_enrichment_sets_epss_and_kev() -> None:
    out = apply_enrichment([_f()], {"CVE-2021-44228": 0.97}, {"CVE-2021-44228"})
    assert out[0].epss == 0.97 and out[0].kev is True
    assert out[0].severity is Severity.MEDIUM  # NUNCA rebaixa/eleva a severidade nominal


def test_apply_enrichment_no_cve_untouched() -> None:
    f = Finding("bandit", "B602", Severity.HIGH, "shell=True")
    assert apply_enrichment([f], {"CVE-X": 0.5}, set())[0] is f


def test_kev_blocks_even_below_threshold() -> None:
    kev_finding = _f(sev=Severity.MEDIUM)
    kev_finding = apply_enrichment([kev_finding], {}, {"CVE-2021-44228"})[0]
    rep = Report((ScanResult("trivy", ScanStatus.OK, (kev_finding,)),))
    assert GatePolicy().evaluate(rep).passed is False                 # KEV bloqueia
    assert GatePolicy(kev_blocks=False).evaluate(rep).passed is True  # desligado -> MEDIUM passa


def test_enrich_report_fail_open(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(epss_kev, "fetch_kev", lambda cache_dir, timeout=20: set())
    monkeypatch.setattr(epss_kev, "fetch_epss", lambda cves, timeout=20: {})
    rep = Report((ScanResult("trivy", ScanStatus.OK, (_f(),)),))
    assert enrich_report(rep, str(tmp_path)) is rep  # sem dados -> inalterado, nunca derruba


def test_enrich_report_annotates(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(epss_kev, "fetch_kev", lambda cache_dir, timeout=20: {"CVE-2021-44228"})
    monkeypatch.setattr(epss_kev, "fetch_epss", lambda cves, timeout=20: {"CVE-2021-44228": 0.9})
    rep = Report((ScanResult("trivy", ScanStatus.OK, (_f(),)),))
    enriched = enrich_report(rep, str(tmp_path))
    assert enriched.findings[0].kev is True and enriched.findings[0].epss == 0.9


def test_get_rejects_non_https() -> None:
    import pytest
    with pytest.raises(ValueError, match="https"):
        epss_kev._get("http://insecure.example/x", 5)


def test_reporter_emits_epss_kev() -> None:
    f = apply_enrichment([_f()], {"CVE-2021-44228": 0.5}, {"CVE-2021-44228"})[0]
    rep = Report((ScanResult("trivy", ScanStatus.OK, (f,)),))
    doc = json.loads(JsonReporter().render(rep))
    assert doc["schema_version"] == "1"
    assert doc["findings"][0]["epss"] == 0.5 and doc["findings"][0]["kev"] is True
