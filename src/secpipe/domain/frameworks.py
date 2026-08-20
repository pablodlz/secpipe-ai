"""Detecção de framework (por manifesto) + marcadores de superfície ESPECÍFICOS (aprofunda o threat-model).
Domínio PURO: `detect` recebe o conteúdo já lido (sem I/O). Marcadores retornam tuplas cruas (kind, label,
regex, STRIDE) — não referenciam SurfaceElement (mantém dominio->application desacoplado)."""
from __future__ import annotations

import re
from enum import StrEnum

from secpipe.domain.stride import Stride

Marker = tuple[str, str, "re.Pattern[str]", tuple[Stride, ...]]


class Framework(StrEnum):
    DJANGO = "django"
    FASTAPI = "fastapi"
    FLASK = "flask"
    EXPRESS = "express"
    SPRING = "spring"
    RAILS = "rails"
    LARAVEL = "laravel"


# framework -> [(substring do nome do manifesto, regex no conteúdo)]. Auditável.
_SIGS: dict[Framework, tuple[tuple[str, str], ...]] = {
    Framework.DJANGO: (("requirements", r"(?i)\bdjango\b"), ("pyproject", r"(?i)django"), ("manage.py", r".")),
    Framework.FASTAPI: (("requirements", r"(?i)fastapi"), ("pyproject", r"(?i)fastapi")),
    Framework.FLASK: (("requirements", r"(?i)\bflask\b"), ("pyproject", r"(?i)flask")),
    Framework.EXPRESS: (("package.json", r'"express"'),),
    Framework.SPRING: (("pom.xml", r"spring-boot"), ("build.gradle", r"spring-boot")),
    Framework.RAILS: (("gemfile", r"(?i)\brails\b"),),
    Framework.LARAVEL: (("composer.json", r"laravel/framework"),),
}


def detect(manifests: dict[str, str]) -> frozenset[Framework]:
    """Frameworks presentes, a partir de {nome_do_manifesto: conteúdo}. Sem I/O."""
    found: set[Framework] = set()
    for fw, sigs in _SIGS.items():
        for name_sub, pattern in sigs:
            if any(name_sub in name.lower() and re.search(pattern, content)
                   for name, content in manifests.items()):
                found.add(fw)
                break
    return frozenset(found)


_FW_MARKERS: dict[Framework, tuple[tuple[str, str, str, tuple[Stride, ...]], ...]] = {
    Framework.DJANGO: (
        ("entrypoint", "django-route", r"\bpath\(|\bre_path\(|urlpatterns", (Stride.SPOOFING, Stride.TAMPERING)),
        ("sink", "django-raw-sql", r"\.raw\(|RawSQL|\.extra\(", (Stride.TAMPERING,)),
    ),
    Framework.FASTAPI: (
        ("entrypoint", "fastapi-route", r"@(?:app|router)\.(?:get|post|put|delete)|APIRouter", (Stride.TAMPERING,)),
        ("asset", "fastapi-depends", r"Depends\(", (Stride.SPOOFING, Stride.ELEVATION)),
    ),
    Framework.FLASK: (("entrypoint", "flask-route", r"@(?:app|bp)\.route|Blueprint\(", (Stride.TAMPERING,)),),
    Framework.EXPRESS: (
        ("entrypoint", "express-route", r"\b(?:app|router)\.(?:get|post|put|delete)\s*\(|req\.(?:params|query|body)",
         (Stride.TAMPERING,)),
    ),
    Framework.SPRING: (
        ("entrypoint", "spring-mapping", r"@(?:Get|Post|Put|Delete|Request)Mapping", (Stride.TAMPERING,)),
        ("sink", "spring-query", r"createQuery\(|@Query\(", (Stride.TAMPERING,)),
    ),
    Framework.RAILS: (("entrypoint", "rails-params", r"params\[|\.where\(", (Stride.TAMPERING,)),),
    Framework.LARAVEL: (("sink", "laravel-dbraw", r"DB::raw\(|->whereRaw\(", (Stride.TAMPERING,)),),
}


def markers_for(frameworks: frozenset[Framework]) -> tuple[Marker, ...]:
    """Marcadores regex compilados dos frameworks detectados (aditivo aos genéricos)."""
    out: list[Marker] = []
    for fw in frameworks:
        for kind, label, pattern, cats in _FW_MARKERS.get(fw, ()):
            out.append((kind, label, re.compile(pattern), cats))
    return tuple(out)
