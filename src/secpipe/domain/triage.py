"""Triage hints — CONTEXTO determinístico para a IA priorizar, SEM silenciar. Anexa sinais (em test/fixture,
arquivo gerado/minificado, prioridade) a cada achado. NUNCA altera severidade nem o gate — só orienta a
ordem de trabalho (complementa o `escalate`). Domínio PURO."""
from __future__ import annotations

import re

from secpipe.domain.models import Finding, Severity

_TEST = re.compile(r"(^|/)(tests?|__tests__|spec|specs|fixtures?|testdata)(/|$)")
_GENERATED = re.compile(
    r"\.(min\.js|min\.css|bundle\.js|pb\.go|pb2\.py|generated\.\w+)$|(^|/)(dist|build|vendor|node_modules)/"
)


def triage(finding: Finding) -> dict[str, object]:
    """Hints de triagem. `priority`: KEV=5; senão a severidade (0-4); -2 em test/gerado (ainda visível)."""
    path = finding.file.replace("\\", "/")
    in_test = bool(_TEST.search(path))
    generated = bool(_GENERATED.search(path))
    priority = 5 if finding.kev else int(finding.severity)
    if in_test or generated:
        priority = max(0, priority - 2)
    return {
        "in_test_path": in_test,
        "generated_file": generated,
        "priority": priority,   # ordem de trabalho, NUNCA permissão para não corrigir
    }


def priority_of(finding: Finding) -> int:
    p = triage(finding)["priority"]
    return p if isinstance(p, int) else int(Severity.INFO)
