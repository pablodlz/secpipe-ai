"""Fitness function: a regra de dependência é testada. Domínio é puro; application não vaza p/ infra."""
from __future__ import annotations

import ast
import pathlib

SRC = pathlib.Path(__file__).resolve().parents[2] / "src" / "secpipe"


def _imports(pyfile: pathlib.Path) -> set[str]:
    tree = ast.parse(pyfile.read_text(encoding="utf-8"))
    mods: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            mods.add(node.module)
    return mods


def test_domain_is_pure() -> None:
    for pyfile in (SRC / "domain").rglob("*.py"):
        for mod in _imports(pyfile):
            assert not mod.startswith("secpipe.application"), f"{pyfile}: domínio->application"
            assert not mod.startswith("secpipe.adapters"), f"{pyfile}: domínio->adapters"
            assert not mod.startswith("secpipe.foundation"), f"{pyfile}: domínio->foundation"


def test_application_does_not_import_adapters_or_foundation() -> None:
    for pyfile in (SRC / "application").rglob("*.py"):
        for mod in _imports(pyfile):
            assert not mod.startswith("secpipe.adapters"), f"{pyfile}: application->adapters"
            assert not mod.startswith("secpipe.foundation"), f"{pyfile}: application->foundation"
