"""STRIDE: o mapa CWE->STRIDE e o fallback por palavra-chave são determinísticos e auditáveis."""
from __future__ import annotations

from secpipe.domain.stride import Stride, categorize, cwe_number


def test_cwe_number_extraction() -> None:
    assert cwe_number("CWE-89") == 89
    assert cwe_number("cwe-306") == 306
    assert cwe_number("") is None
    assert cwe_number("nao-e-cwe") is None


def test_known_cwe_maps_to_expected_category() -> None:
    assert Stride.TAMPERING in categorize("CWE-89")            # SQLi
    assert Stride.INFO_DISCLOSURE in categorize("CWE-200")     # info exposure
    assert Stride.ELEVATION in categorize("CWE-306")           # missing auth
    assert categorize("CWE-78") == frozenset({Stride.TAMPERING, Stride.ELEVATION})  # OS command injection


def test_hardcoded_secret_is_both_disclosure_and_spoofing() -> None:
    cats = categorize("CWE-798")
    assert Stride.INFO_DISCLOSURE in cats and Stride.SPOOFING in cats


def test_keyword_fallback_when_no_cwe() -> None:
    assert Stride.TAMPERING in categorize("", "sql-injection", "user input in query")
    cats = categorize("", "B602", "subprocess call with shell=True")
    assert Stride.TAMPERING in cats and Stride.ELEVATION in cats
    assert Stride.INFO_DISCLOSURE in categorize("", "hardcoded_password", "api_key found")


def test_unknown_returns_empty() -> None:
    assert categorize("CWE-99999") == frozenset()
    assert categorize("", "totally-unrelated-rule") == frozenset()


def test_stride_titles_cover_all_six() -> None:
    assert len(list(Stride)) == 6
    assert all(s.label for s in Stride)
