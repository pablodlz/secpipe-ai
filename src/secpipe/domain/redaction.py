"""Redação de segredo/PII (RS-01 do headless PR-bot): mascara material sensível ANTES de qualquer texto
ir a um provedor de IA. Puro, determinístico, idempotente, sem dependência. Defesa em profundidade —
não substitui não-vazar chave, mas evita mandar segredo do código pro modelo."""
from __future__ import annotations

import re

_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL), "[REDACTED-PEM]"),
    (re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"), "[REDACTED-JWT]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED-AWS-KEY]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "[REDACTED-GH-TOKEN]"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "[REDACTED-SLACK-TOKEN]"),
    (re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), "[REDACTED-API-KEY]"),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "[REDACTED-EMAIL]"),
    # token genérico longo (base64/hex) — por último p/ não comer os específicos acima
    (re.compile(r"\b[A-Za-z0-9+/_-]{40,}={0,2}\b"), "[REDACTED-TOKEN]"),
)


def redact(text: str) -> str:
    """Substitui segredo/PII provável por marcadores. Idempotente (rodar 2x = mesmo resultado)."""
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text
