"""Domínio puro: política de licenças SPDX + avaliação deny/allow. Determinístico, sem I/O.

Não é vuln de código, mas risco legal/compliance — reusa o mesmo gate. Espelha o estilo de abstention.py."""
from __future__ import annotations

from dataclasses import dataclass

from secpipe.domain.models import Severity

_UNKNOWN = frozenset({"", "UNKNOWN", "NONE", "NOASSERTION"})


@dataclass(frozen=True, slots=True)
class LicensePolicy:
    """deny bloqueia; allow libera; unknown_is = severidade do não-classificado."""
    deny: tuple[str, ...] = ()
    allow: tuple[str, ...] = ()
    unknown_is: str = "MEDIUM"


def classify_license(name: str, policy: LicensePolicy) -> Severity | None:
    """Severidade a atribuir a uma licença, ou None se permitida. Case-insensitive.

    - deny  -> HIGH (bloqueia)
    - allow -> None (ok)
    - desconhecida/vazia -> unknown_is
    - allowlist ativo e licença fora do allow -> unknown_is (conservador, não HIGH)
    - senão (modo denylist, não negada) -> None
    """
    norm = name.strip().upper()
    deny = {d.upper() for d in policy.deny}
    allow = {a.upper() for a in policy.allow}
    if norm in _UNKNOWN:
        return Severity.parse(policy.unknown_is)
    if norm in deny:
        return Severity.HIGH
    if norm in allow:
        return None
    if allow:  # allowlist ativo e a licença não está nela
        return Severity.parse(policy.unknown_is)
    return None
