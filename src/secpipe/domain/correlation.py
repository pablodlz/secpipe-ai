"""Domínio puro: correlação DAST<->SAST por CWE. Cross-valida o que é ao mesmo tempo ALCANÇÁVEL em runtime
(DAST) E presente no código (SAST) -> sinal de PRIORIDADE (não muda o gate, não mascara nada).

Espelha abstention.py: módulo puro consumido pelo reporter. HEURÍSTICA (muitos achados dividem CWE-79) —
rotular como prioridade, não prova do mesmo bug."""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from secpipe.domain.models import Finding, Severity


@dataclass(frozen=True, slots=True)
class Correlation:
    cwe: str
    dast_rule: str
    static_refs: tuple[str, ...]
    severity: Severity


def correlate(findings: Sequence[Finding]) -> list[Correlation]:
    """Emite uma Correlation por CWE que tem >=1 achado DAST E >=1 estático. severity = max dos dois lados."""
    by_cwe: dict[str, list[Finding]] = {}
    for f in findings:
        if f.cwe:
            by_cwe.setdefault(f.cwe, []).append(f)
    out: list[Correlation] = []
    for cwe, group in by_cwe.items():
        dast = [f for f in group if f.tool == "dast"]
        static = [f for f in group if f.tool != "dast"]
        if dast and static:
            out.append(Correlation(
                cwe=cwe, dast_rule=dast[0].rule_id,
                static_refs=tuple(sorted({f.rule_id for f in static})),
                severity=max(f.severity for f in group),
            ))
    return out
