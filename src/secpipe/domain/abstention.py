"""Abstention (FEAT-008): categorias que a IA NÃO deve corrigir sozinha — escala ao humano.

Puro. Aproximação por CWE + severidade: auth/authz, criptografia, credenciais e severidade CRITICAL
são o "último caso" — o agente sinaliza para revisão humana em vez de auto-corrigir (ADR-0008 §5)."""
from __future__ import annotations

from secpipe.domain.models import Severity

# CWEs sensíveis (autenticação/autorização · criptografia · credenciais). Escalar, não auto-corrigir.
_SENSITIVE_CWES = frozenset({
    "CWE-287", "CWE-306", "CWE-862", "CWE-863", "CWE-284", "CWE-285", "CWE-639",  # auth/authz
    "CWE-327", "CWE-328", "CWE-326", "CWE-330", "CWE-916", "CWE-347", "CWE-759",  # cripto
    "CWE-798", "CWE-259", "CWE-321",                                              # credenciais/segredos
})


def escalates(cwe: str, severity: Severity) -> bool:
    """True quando o achado deve ser ESCALADO (não auto-corrigido): categoria sensível ou CRITICAL."""
    return severity is Severity.CRITICAL or cwe.strip().upper() in _SENSITIVE_CWES
