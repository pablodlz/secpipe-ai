"""Diff-scope (adoção incremental SEM baixar a régua): bloquear só achados que tocam linhas ADICIONADAS
pelo PR, deixando o backlog pré-existente visível porém não-bloqueante. NÃO é allowlist/baseline (proibido
por ADR-0008) — é 'código novo entra limpo', derivado do git diff em tempo real, sem supressão persistente.

Domínio PURO: parseia o texto de um `git diff -U0`. Achado sem file/line -> considerado NOVO (fail-safe)."""
from __future__ import annotations

import re

from secpipe.domain.models import Finding

_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def parse_added_lines(diff_text: str) -> dict[str, set[int]]:
    """`git diff -U0` -> {arquivo: {linhas adicionadas}}. Usa o lado '+++ b/<file>' e os hunks."""
    added: dict[str, set[int]] = {}
    current = ""
    for line in diff_text.splitlines():
        if line.startswith("+++ b/"):
            current = line[6:].strip().replace("\\", "/")
            added.setdefault(current, set())
            continue
        m = _HUNK.match(line)
        if m and current:
            start = int(m.group(1))
            count = int(m.group(2)) if m.group(2) is not None else 1
            for i in range(start, start + max(count, 1)):
                added[current].add(i)
    return {f: lines for f, lines in added.items() if lines}


def _norm(path: str) -> str:
    return path.replace("\\", "/").lstrip("./")


def is_in_diff(finding: Finding, added: dict[str, set[int]]) -> bool:
    """True se o achado toca uma linha adicionada. Sem file/line -> True (fail-safe: trata como novo)."""
    if not finding.file or finding.line <= 0:
        return True
    fnorm = _norm(finding.file)
    for gitpath, lines in added.items():
        gnorm = _norm(gitpath)
        if (fnorm == gnorm or fnorm.endswith("/" + gnorm) or gnorm.endswith("/" + fnorm)) and finding.line in lines:
            return True
    return False
