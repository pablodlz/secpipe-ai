"""Fixer determinístico (Codemodder/Pixee) — aplica codemods seguros (FEAT-008, opcional).

Roda no container Linux/CI (não roda nativo no Windows, como o semgrep). Skip gracioso se ausente/erro.
Preferir fix determinístico ao fix por IA quando existir (mais seguro/barato — RN-04)."""
from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass

from secpipe.adapters.base import run_tool, tool_on_path

BINARY = "codemodder"
_EXCLUDE = ".venv/**,venv/**,node_modules/**,tools/**,dist/**,build/**,.tox/**"


@dataclass(frozen=True, slots=True)
class FixOutcome:
    ran: bool
    files_changed: int = 0
    changes: int = 0
    codemods: tuple[str, ...] = ()
    detail: str = ""


def parse_codetf(raw: str) -> FixOutcome:
    """Conta as mudanças do relatório codetf do codemodder (schema real: results[].changeset[].changes)."""
    if not raw.strip():
        return FixOutcome(ran=True, detail="sem alteracoes")
    doc = json.loads(raw)
    files: set[str] = set()
    changes = 0
    codemods: list[str] = []
    for result in doc.get("results") or []:
        changeset = result.get("changeset") or []
        if changeset:
            codemods.append(str(result.get("codemod", "")))
        for cset in changeset:
            files.add(str(cset.get("path", "")))
            changes += len(cset.get("changes") or [])
    return FixOutcome(
        ran=True, files_changed=len(files), changes=changes,
        codemods=tuple(c for c in codemods if c),
    )


class CodemodderFixer:
    name = BINARY

    def is_available(self) -> bool:
        return tool_on_path(BINARY)

    def run(self, target: str, *, dry_run: bool = False) -> FixOutcome:
        fd, out = tempfile.mkstemp(prefix="secpipe-codetf-", suffix=".json")
        os.close(fd)
        try:
            args = [target, "--output", out, "--output-format", "codetf", "--path-exclude", _EXCLUDE]
            if dry_run:
                args.append("--dry-run")
            res = run_tool(BINARY, args, timeout=600)
            if res.missing:
                return FixOutcome(ran=False, detail="codemodder ausente (roda no container Linux)")
            try:
                with open(out, encoding="utf-8") as fh:
                    raw = fh.read()
            except OSError:
                raw = ""
            if not raw.strip():
                return FixOutcome(ran=False, detail=f"codemodder sem saida (rc={res.returncode})")
            return parse_codetf(raw)
        finally:
            try:
                os.unlink(out)
            except OSError:
                pass
