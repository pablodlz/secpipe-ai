"""`secpipe verify` — juiz DETERMINÍSTICO do fix (FEAT-005, keyless).

O AGENTE de IA (que já opera o projeto) corrige com o próprio modelo; a MÁQUINA aprova. Aceita só se:
(1) gate passa (os achados foram resolvidos), (2) o diff NÃO adiciona supressão, (3) os testes passam
(se `test_command` estiver configurado). É a "verificação independente" sem depender de 2º LLM nem chave."""
from __future__ import annotations

import subprocess
from dataclasses import dataclass, field

from secpipe.application.orchestrator import Orchestrator
from secpipe.application.use_cases.precommit import find_suppressions


@dataclass(slots=True)
class VerifyVerdict:
    accepted: bool
    reasons: list[str] = field(default_factory=list)


def _diff(target: str, base_ref: str) -> str:
    proc = subprocess.run(
        ["git", "-C", target, "diff", "--no-color", "-U0", base_ref],
        capture_output=True, text=True, encoding="utf-8", errors="replace", check=False,
    )
    return proc.stdout


def verify(
    orchestrator: Orchestrator, target: str = ".", *,
    base_ref: str = "HEAD", test_command: tuple[str, ...] = (),
) -> VerifyVerdict:
    """Verdito determinístico sobre o estado atual do repo (após o fix do agente)."""
    reasons: list[str] = []

    # 1. anti-supressão — o fix não pode silenciar o achado (ADR-0008)
    suppressions = find_suppressions(_diff(target, base_ref))
    if suppressions:
        reasons.append(f"supressao adicionada ({len(suppressions)}) — resolva a causa, nao silencie")

    # 2. gate — os achados bloqueantes precisam ter sumido (evidência do scanner, não a palavra do agente)
    _report, decision = orchestrator.run(target)
    if not decision.passed:
        reasons.append(f"gate FAIL: {decision.reason}")

    # 3. testes — sem regressão (execution-grounded); só se configurado
    if test_command:
        code = subprocess.run(list(test_command), cwd=target, check=False).returncode
        if code != 0:
            reasons.append("testes falharam (possivel regressao)")

    return VerifyVerdict(accepted=not reasons, reasons=reasons or ["ok: fix verificado"])
