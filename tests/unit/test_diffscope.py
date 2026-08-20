"""Diff-scope: parse do git diff, is_in_diff, e o gate diff-scoped (bloqueia novo; sempre-bloqueia sensível)."""
from __future__ import annotations

from secpipe.domain import Finding, GatePolicy, Report, ScanResult, ScanStatus, Severity
from secpipe.domain.diffscope import is_in_diff, parse_added_lines

_DIFF = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -10,0 +11,2 @@
+linha nova 1
+linha nova 2
diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -5 +5 @@
+trocada
"""


def test_parse_added_lines() -> None:
    added = parse_added_lines(_DIFF)
    assert added["app.py"] == {11, 12} and added["x.py"] == {5}


def test_is_in_diff() -> None:
    added = {"app.py": {11, 12}}
    assert is_in_diff(Finding("t", "r", Severity.HIGH, "m", "app.py", 11), added) is True
    assert is_in_diff(Finding("t", "r", Severity.HIGH, "m", "app.py", 99), added) is False
    assert is_in_diff(Finding("t", "r", Severity.HIGH, "m", "outro.py", 11), added) is False
    assert is_in_diff(Finding("t", "r", Severity.HIGH, "m", "", 0), added) is True   # sem loc -> novo (fail-safe)


def _rep(*findings: Finding) -> Report:
    return Report((ScanResult("bandit", ScanStatus.OK, tuple(findings)),))


_NEW = Finding("bandit", "B1", Severity.HIGH, "novo", "app.py", 11, cwe="CWE-79")
_OLD = Finding("bandit", "B2", Severity.HIGH, "velho", "app.py", 99, cwe="CWE-79")


def test_diff_gate_blocks_new_only() -> None:
    rep = _rep(_NEW, _OLD)
    only = frozenset({_NEW.fingerprint})
    assert GatePolicy().evaluate(rep, only=only).passed is False   # novo HIGH bloqueia
    # sem o novo em escopo: só o velho -> passa (backlog não-bloqueante)
    assert GatePolicy().evaluate(_rep(_OLD), only=frozenset()).passed is True


def test_diff_gate_always_blocks_sensitive_preexisting() -> None:
    old_secret = Finding("gitleaks", "s", Severity.HIGH, "key", "app.py", 99, cwe="CWE-798")
    # pré-existente (fora do escopo) mas SENSÍVEL (segredo) -> nunca escondido
    assert GatePolicy().evaluate(_rep(old_secret), only=frozenset()).passed is False


def test_full_mode_unchanged() -> None:
    assert GatePolicy().evaluate(_rep(_OLD)).passed is False   # sem only -> comportamento normal (HIGH bloqueia)
