"""Enrichment de achados com EPSS (probabilidade de exploração, FIRST.org) e CISA KEV (exploração ATIVA
conhecida). Domínio PURO: só a lógica de extrair CVE e mesclar; o fetch por rede vive no adapter.

REGRA DURA: enrichment só ELEVA prioridade/bloqueio (KEV). NUNCA rebaixa severidade nem remove do gate."""
from __future__ import annotations

import dataclasses
import re
from collections.abc import Iterable, Sequence

from secpipe.domain.models import Finding

_CVE_RE = re.compile(r"CVE-\d{4}-\d{3,7}", re.IGNORECASE)


def extract_cves(finding: Finding) -> list[str]:
    """CVEs mencionados no rule_id/mensagem do achado (SCA costuma trazer o CVE aí)."""
    text = f"{finding.rule_id} {finding.message}"
    return [m.group(0).upper() for m in _CVE_RE.finditer(text)]


def apply_enrichment(
    findings: Sequence[Finding], epss_map: dict[str, float], kev_set: Iterable[str]
) -> list[Finding]:
    """Anota cada achado com CVE conhecido: epss = MAIOR epss dos seus CVEs; kev = qualquer CVE no KEV."""
    kev = {c.upper() for c in kev_set}
    out: list[Finding] = []
    for f in findings:
        cves = extract_cves(f)
        if not cves:
            out.append(f)
            continue
        scores = [epss_map[c] for c in cves if c in epss_map]
        epss = max(scores) if scores else None
        is_kev = any(c in kev for c in cves)
        if epss is None and not is_kev:
            out.append(f)
        else:
            out.append(dataclasses.replace(f, epss=epss, kev=is_kev or f.kev))
    return out
