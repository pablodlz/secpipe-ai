"""Loop headless de auto-fix (FEAT-006) — o ÚNICO modo com chave, opt-in/default-off. Escaneia, pede patch
ao provedor, aplica, roda o `verify` DETERMINÍSTICO, e SÓ mantém se ACCEPT (senão REVERTE). Abstém em CWE
sensível (auth/cripto/segredo/CRITICAL). Fail-closed: sem provedor => escala tudo, nunca fecha às cegas.

Camada application: recebe orchestrator + apply/revert INJETADOS (não importa foundation/adapters — a
regra de dependência é testada). A defesa real é o verify determinístico; este loop é orquestração."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from secpipe.application.orchestrator import Orchestrator
from secpipe.application.ports import AIProviderPort
from secpipe.application.use_cases._fix_prompt import build_fix_prompt
from secpipe.application.use_cases.verify import verify as run_verify
from secpipe.domain import Finding, Severity
from secpipe.domain.abstention import escalates

ApplyFn = Callable[[str, str], tuple[bool, str]]
RevertFn = Callable[[str, str], bool]


@dataclass(frozen=True, slots=True)
class FindingFixResult:
    fingerprint: str
    rule_id: str
    status: str   # fixed | rejected | abstained | escalated | would_fix


@dataclass(frozen=True, slots=True)
class AutofixOutcome:
    results: list[FindingFixResult] = field(default_factory=list)

    def count(self, status: str) -> int:
        return sum(1 for r in self.results if r.status == status)

    @property
    def resolved(self) -> bool:
        """True se nada ficou pendente (nenhum rejected/escalated/abstained)."""
        return not any(r.status in ("rejected", "escalated", "abstained") for r in self.results)


def run_autofix(
    orchestrator: Orchestrator, provider: AIProviderPort, target: str, *,
    apply_fn: ApplyFn, revert_fn: RevertFn,
    block_severity: Severity = Severity.HIGH, test_command: tuple[str, ...] = (),
    base_ref: str = "HEAD", max_findings: int = 10, dry_run: bool = False,
) -> AutofixOutcome:
    report, _ = orchestrator.run(target)
    blocking: list[Finding] = [f for f in report.findings if f.severity >= block_severity or f.kev][:max_findings]

    # Fail-closed: sem provedor de IA, NADA é corrigido às cegas — tudo escala (exit != 0 no CLI).
    if not provider.available():
        return AutofixOutcome([FindingFixResult(f.fingerprint, f.rule_id, "escalated") for f in blocking])

    results: list[FindingFixResult] = []
    seen: set[str] = set()
    for f in blocking:
        if f.fingerprint in seen:
            continue
        seen.add(f.fingerprint)
        # Abstention: categorias sensíveis NUNCA são auto-corrigidas — escala p/ humano (provider nem é chamado).
        if escalates(f.cwe, f.severity):
            results.append(FindingFixResult(f.fingerprint, f.rule_id, "abstained"))
            continue
        try:
            diff = provider.complete(build_fix_prompt(f))
        except Exception:  # provider falhou p/ este finding -> escala
            results.append(FindingFixResult(f.fingerprint, f.rule_id, "escalated"))
            continue
        if not diff.strip():
            results.append(FindingFixResult(f.fingerprint, f.rule_id, "escalated"))
            continue
        if dry_run:
            results.append(FindingFixResult(f.fingerprint, f.rule_id, "would_fix"))
            continue
        applied, _detail = apply_fn(target, diff)
        if not applied:
            results.append(FindingFixResult(f.fingerprint, f.rule_id, "rejected"))
            continue
        # JUIZ determinístico e independente: gate + anti-supressão (bloqueia # nosec) + testes.
        verdict = run_verify(orchestrator, target, base_ref=base_ref, test_command=test_command)
        if verdict.accepted:
            results.append(FindingFixResult(f.fingerprint, f.rule_id, "fixed"))
        else:
            revert_fn(target, diff)   # não aceito -> desfaz (repo intacto)
            results.append(FindingFixResult(f.fingerprint, f.rule_id, "rejected"))
    return AutofixOutcome(results)
