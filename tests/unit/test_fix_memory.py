"""Memória de fixes verificados: record (dedup) + recall por CWE (case-insensitive)."""
from __future__ import annotations

from pathlib import Path

from secpipe.adapters.fix_memory import FixMemory
from secpipe.domain.fix_memory import VerifiedFix


def test_record_dedup_and_recall(tmp_path: Path) -> None:
    mem = FixMemory(str(tmp_path / "fm.json"))
    vf = VerifiedFix("CWE-89", "semgrep", "sqli", "usar query parametrizada")
    assert mem.record(vf) is True
    assert mem.record(vf) is False                 # dedup
    got = mem.recall("cwe-89")                      # case-insensitive
    assert len(got) == 1
    assert got[0].note == "usar query parametrizada"
    assert mem.recall("CWE-79") == []
