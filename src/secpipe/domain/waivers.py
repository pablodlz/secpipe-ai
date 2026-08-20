"""Waivers — a alternativa PRINCIPIADA ao `# nosec`: exceção time-boxed, auditável e reviewada (não um
silenciador inline). Invariantes DUROS: expiração OBRIGATÓRIA; CRITICAL, segredo (CWE-798) e KEV NUNCA são
waivable; waiver expirado é inativo; toda exceção é sempre reportada. Domínio PURO."""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from datetime import date

from secpipe.domain.models import Finding, ScanResult, Severity

_NEVER_WAIVABLE_CWES = frozenset({"CWE-798"})   # segredos hard-coded


@dataclass(frozen=True, slots=True)
class Waiver:
    fingerprint: str
    reason: str = ""
    owner: str = ""
    ticket: str = ""
    expires: str = ""   # ISO YYYY-MM-DD (OBRIGATÓRIO — sem isso o waiver é inválido)

    def is_active(self, today: date) -> bool:
        if not self.fingerprint or not self.expires:
            return False   # sem fingerprint/expiração -> inválido (fail-closed)
        try:
            return date.fromisoformat(self.expires) >= today
        except ValueError:
            return False


def is_waivable(f: Finding) -> bool:
    """False p/ o que NUNCA se isenta: CRITICAL, KEV, ou segredo. Invariante de segurança."""
    return not (f.severity >= Severity.CRITICAL or f.kev or f.cwe.upper() in _NEVER_WAIVABLE_CWES)


def partition(findings: list[Finding], waivers: list[Waiver], today: date) -> tuple[list[Finding], list[Finding]]:
    """Separa (remaining, waived). Só isenta achado com waiver ATIVO E que seja waivable."""
    active = {w.fingerprint for w in waivers if w.is_active(today)}
    remaining: list[Finding] = []
    waived: list[Finding] = []
    for f in findings:
        if f.fingerprint in active and is_waivable(f):
            waived.append(f)
        else:
            remaining.append(f)
    return remaining, waived


def partition_results(
    results: tuple[ScanResult, ...], waivers: list[Waiver], today: date
) -> tuple[tuple[ScanResult, ...], list[Finding]]:
    """Aplica waivers por achado RAW (re-checa is_waivable em CADA achado): um achado co-localizado com o
    mesmo fingerprint mas CRITICAL/KEV NUNCA é isento (o fingerprint omite severity/kev). Devolve
    (results_sem_os_isentos, isentos). Espinha dorsal correta do fix de segurança."""
    active = {w.fingerprint for w in waivers if w.is_active(today)}
    waived: list[Finding] = []
    new_results: list[ScanResult] = []
    for r in results:
        kept: list[Finding] = []
        for f in r.findings:
            if f.fingerprint in active and is_waivable(f):
                waived.append(f)
            else:
                kept.append(f)
        new_results.append(dataclasses.replace(r, findings=tuple(kept)))
    return tuple(new_results), waived
