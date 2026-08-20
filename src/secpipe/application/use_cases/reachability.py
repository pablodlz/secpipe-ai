"""Constrói o índice de módulos IMPORTADOS no código-fonte (para reachability-lite). I/O na application;
a lógica de anotação é pura no domínio. Multi-linguagem básico: Python import/from, JS require/import."""
from __future__ import annotations

import os
import re

_SKIP_DIRS = {".git", ".venv", "venv", "node_modules", ".tox", "dist", "build", "__pycache__", "tools", "vendor"}
_EXT = {".py", ".js", ".ts", ".tsx", ".jsx"}
_PY = re.compile(r"^\s*(?:import|from)\s+([A-Za-z0-9_]+)", re.MULTILINE)
_JS = re.compile(r"""require\(\s*['"]([^'"]+)['"]\s*\)|from\s+['"]([^'"]+)['"]""")
_MAX_FILES = 4000
_MAX_BYTES = 1_500_000


def _top_module(name: str) -> str:
    # '@scope/pkg' -> '@scope/pkg'; 'pkg/sub' -> 'pkg'; 'a.b' -> 'a'
    name = name.strip()
    if name.startswith("@"):
        return "/".join(name.split("/")[:2])
    return name.split("/")[0].split(".")[0]


def build_import_index(root: str) -> set[str]:
    """Conjunto de módulos/pacotes importados (top-level). Determinístico, limitado."""
    modules: set[str] = set()
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for name in filenames:
            if os.path.splitext(name)[1].lower() not in _EXT:
                continue
            path = os.path.join(dirpath, name)
            try:
                if os.path.getsize(path) > _MAX_BYTES:
                    continue
                with open(path, encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                continue
            for m in _PY.finditer(text):
                modules.add(m.group(1).lower())
            for m in _JS.finditer(text):
                mod = m.group(1) or m.group(2) or ""
                if not mod.startswith("."):   # ignora imports relativos
                    modules.add(_top_module(mod).lower())
            count += 1
            if count >= _MAX_FILES:
                return modules
    return modules
