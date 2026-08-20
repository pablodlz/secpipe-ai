"""Policy-as-code: regras declarativas e auditáveis que ELEVAM o bloqueio (ex.: 'injeção sempre bloqueia',
'nada passa em src/auth/'). SÓ endurecem — NUNCA relaxam (senão virariam supressão, proibida por ADR-0008).
Domínio PURO. Uma regra casa por cwe / tool / path-glob / severidade-mínima; casou => bloqueia."""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass

from secpipe.domain.models import Finding, Severity


@dataclass(frozen=True, slots=True)
class PolicyRule:
    """Campos vazios = 'qualquer'. Todos os campos definidos precisam casar (AND). action é sempre 'block'."""
    cwe: str = ""
    tool: str = ""
    path_glob: str = ""
    min_severity: str = ""   # ex.: 'MEDIUM' -> casa achados >= MEDIUM

    def matches(self, f: Finding) -> bool:
        if self.cwe and f.cwe.upper() != self.cwe.upper():
            return False
        if self.tool and f.tool != self.tool:
            return False
        if self.path_glob and not fnmatch.fnmatch(f.file.replace("\\", "/"), self.path_glob):
            return False
        if self.min_severity and f.severity < Severity.parse(self.min_severity):
            return False
        return True


def blocked_by_rules(rules: tuple[PolicyRule, ...], f: Finding) -> bool:
    """True se ALGUMA regra casa o achado (=> bloqueia, mesmo abaixo de block_severity). Elevação only."""
    return any(rule.matches(f) for rule in rules)
