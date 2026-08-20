"""STRIDE no domínio: classificação DETERMINÍSTICA de risco por categoria (FEAT-011).

Não é IA nem heurística "mágica": é um mapa auditável CWE -> STRIDE (com fallback por palavra-chave
quando o achado não traz CWE). É o alicerce keyless do `secpipe threat-model` — o motor categoriza os
achados REAIS e a superfície descoberta; o agente completa o raciocínio. Sem I/O, sem libs externas."""
from __future__ import annotations

import re
from enum import StrEnum


class Stride(StrEnum):
    """As seis categorias de ameaça do STRIDE (Microsoft). Ordem canônica."""
    SPOOFING = "S"            # falsificação de identidade  (autenticação)
    TAMPERING = "T"           # adulteração de dados/código (integridade)
    REPUDIATION = "R"         # negar ter feito algo        (auditoria/log)
    INFO_DISCLOSURE = "I"     # vazamento de informação     (confidencialidade)
    DENIAL_OF_SERVICE = "D"   # indisponibilidade           (disponibilidade)
    ELEVATION = "E"           # elevação de privilégio      (autorização)

    @property
    def label(self) -> str:
        """Nome legível (não usar `title`: colidiria com o método `str.title`)."""
        return {
            Stride.SPOOFING: "Spoofing (identidade)",
            Stride.TAMPERING: "Tampering (integridade)",
            Stride.REPUDIATION: "Repudiation (auditoria)",
            Stride.INFO_DISCLOSURE: "Information Disclosure (confidencialidade)",
            Stride.DENIAL_OF_SERVICE: "Denial of Service (disponibilidade)",
            Stride.ELEVATION: "Elevation of Privilege (autorização)",
        }[self]


# Mapa AUDITÁVEL CWE -> categorias STRIDE. Um CWE pode implicar mais de uma categoria.
# Fonte: catálogo MITRE CWE + convenção de threat modeling. Extensível (é dado, não código).
_CWE_STRIDE: dict[int, tuple[Stride, ...]] = {
    # Spoofing / autenticação
    287: (Stride.SPOOFING,), 290: (Stride.SPOOFING,), 384: (Stride.SPOOFING,),
    345: (Stride.SPOOFING, Stride.TAMPERING), 347: (Stride.SPOOFING, Stride.TAMPERING),
    295: (Stride.SPOOFING,),  # improper certificate validation
    # Tampering / injeção / integridade
    89: (Stride.TAMPERING,), 79: (Stride.TAMPERING,), 78: (Stride.TAMPERING, Stride.ELEVATION),
    77: (Stride.TAMPERING, Stride.ELEVATION), 94: (Stride.TAMPERING, Stride.ELEVATION),
    502: (Stride.TAMPERING, Stride.ELEVATION), 434: (Stride.TAMPERING,),
    611: (Stride.TAMPERING, Stride.INFO_DISCLOSURE),
    91: (Stride.TAMPERING,), 1321: (Stride.TAMPERING,), 352: (Stride.TAMPERING,), 74: (Stride.TAMPERING,),
    98: (Stride.TAMPERING, Stride.ELEVATION), 943: (Stride.TAMPERING,),
    # Repudiation / auditoria
    778: (Stride.REPUDIATION,), 117: (Stride.REPUDIATION,), 223: (Stride.REPUDIATION,), 390: (Stride.REPUDIATION,),
    # Information Disclosure / confidencialidade
    200: (Stride.INFO_DISCLOSURE,), 209: (Stride.INFO_DISCLOSURE,), 532: (Stride.INFO_DISCLOSURE,),
    798: (Stride.INFO_DISCLOSURE, Stride.SPOOFING), 312: (Stride.INFO_DISCLOSURE,), 319: (Stride.INFO_DISCLOSURE,),
    327: (Stride.INFO_DISCLOSURE,), 328: (Stride.INFO_DISCLOSURE,), 326: (Stride.INFO_DISCLOSURE,),
    311: (Stride.INFO_DISCLOSURE,), 522: (Stride.INFO_DISCLOSURE, Stride.SPOOFING), 359: (Stride.INFO_DISCLOSURE,),
    22: (Stride.INFO_DISCLOSURE, Stride.TAMPERING),  # path traversal
    # Denial of Service / disponibilidade
    400: (Stride.DENIAL_OF_SERVICE,), 770: (Stride.DENIAL_OF_SERVICE,), 1333: (Stride.DENIAL_OF_SERVICE,),
    834: (Stride.DENIAL_OF_SERVICE,), 409: (Stride.DENIAL_OF_SERVICE,), 776: (Stride.DENIAL_OF_SERVICE,),
    # Elevation of Privilege / autorização
    269: (Stride.ELEVATION,), 306: (Stride.ELEVATION,), 862: (Stride.ELEVATION,), 863: (Stride.ELEVATION,),
    732: (Stride.ELEVATION, Stride.INFO_DISCLOSURE), 250: (Stride.ELEVATION,), 276: (Stride.ELEVATION,),
    284: (Stride.ELEVATION,), 285: (Stride.ELEVATION,),
}

# Fallback por palavra-chave (rule_id/mensagem) quando não há CWE. Ordem importa: primeiro match vence.
_KEYWORD_STRIDE: tuple[tuple[re.Pattern[str], tuple[Stride, ...]], ...] = tuple(
    (re.compile(pat, re.IGNORECASE), cats)
    for pat, cats in (
        (r"sql|injection|inject", (Stride.TAMPERING,)),
        (r"xss|cross.site.script", (Stride.TAMPERING,)),
        (r"command|os\.system|subprocess|shell|rce|exec\b|eval\b", (Stride.TAMPERING, Stride.ELEVATION)),
        (r"deserial|pickle|yaml\.load|marshal", (Stride.TAMPERING, Stride.ELEVATION)),
        (r"path.travers|directory.travers|\.\./", (Stride.INFO_DISCLOSURE, Stride.TAMPERING)),
        (r"ssrf|server.side.request", (Stride.TAMPERING, Stride.ELEVATION)),
        (r"csrf|cross.site.request", (Stride.TAMPERING,)),
        (r"secret|password|passwd|credential|api.?key|token|private.key", (Stride.INFO_DISCLOSURE, Stride.SPOOFING)),
        (r"crypto|cipher|tls|ssl|md5|sha1|weak.hash|insecure.random", (Stride.INFO_DISCLOSURE,)),
        (r"auth(entication|z|orization)?|login|session|jwt", (Stride.SPOOFING, Stride.ELEVATION)),
        (r"privilege|permission|chmod|setuid|sudo|access.control", (Stride.ELEVATION,)),
        (r"\bdos\b|redos|resource.exhaust|denial.of.service|unbounded", (Stride.DENIAL_OF_SERVICE,)),
        (r"\blog(ging)?\b|audit", (Stride.REPUDIATION,)),
        (r"disclosure|leak|exposure|verbose.error|stack.trace", (Stride.INFO_DISCLOSURE,)),
    )
)

_CWE_NUM_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)


def cwe_number(cwe: str) -> int | None:
    """Extrai o número do CWE (ex.: 'CWE-89' -> 89). None se não for um CWE reconhecível."""
    match = _CWE_NUM_RE.search(cwe or "")
    return int(match.group(1)) if match else None


def categorize(cwe: str = "", *hints: str) -> frozenset[Stride]:
    """Categorias STRIDE de um risco. Primeiro tenta o CWE (mapa auditável); se ausente/desconhecido,
    cai para heurística de palavra-chave sobre `hints` (rule_id, mensagem). Vazio = não classificado."""
    num = cwe_number(cwe)
    if num is not None and num in _CWE_STRIDE:
        return frozenset(_CWE_STRIDE[num])
    haystack = " ".join(h for h in hints if h)
    if haystack:
        for pattern, cats in _KEYWORD_STRIDE:
            if pattern.search(haystack):
                return frozenset(cats)
    return frozenset()
