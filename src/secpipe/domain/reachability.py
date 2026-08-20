"""Reachability-lite: a dependência vulnerável (SCA) é de fato IMPORTADA no código? Priorização keyless e
barata. SÓ ANOTA (`reachable`) — NUNCA relaxa o gate por padrão (import dinâmico/reflection escapam; um
falso 'não-reachable' que baixasse a régua seria perigoso). Domínio PURO."""
from __future__ import annotations

import dataclasses
import re

from secpipe.domain.models import Finding

# nome-de-distribuição -> nome-de-módulo (casos comuns onde diferem).
_ALIASES = {
    "pyyaml": "yaml", "beautifulsoup4": "bs4", "pillow": "pil", "scikit-learn": "sklearn",
    "python-dateutil": "dateutil", "msgpack-python": "msgpack", "opencv-python": "cv2",
    "setuptools": "setuptools", "attrs": "attr",
}
# só tools cuja extração de nome de pacote é confiável (evita falso-negativo em formato ambíguo).
_SCA_TOOLS = frozenset({"pip-audit", "npm-audit"})
_PKG_RE = re.compile(r"^([A-Za-z0-9._-]+)")


def package_of(finding: Finding) -> str:
    """Nome do pacote de um achado de SCA. npm-audit: rule_id 'npm/<pkg>'. pip-audit: 1º token da mensagem."""
    if finding.rule_id.startswith("npm/"):
        return finding.rule_id[4:]
    match = _PKG_RE.match(finding.message)
    return match.group(1) if match else ""


def module_of(pkg: str) -> str:
    p = pkg.strip().lower().replace("_", "-")
    return _ALIASES.get(p, p.replace("-", "_"))


def annotate(findings: list[Finding], imported: set[str]) -> list[Finding]:
    """Marca `reachable` nos achados de SCA cujo pacote foi (ou não) importado. Demais ficam inalterados."""
    out: list[Finding] = []
    for f in findings:
        pkg = package_of(f) if f.tool in _SCA_TOOLS else ""
        if pkg:
            out.append(dataclasses.replace(f, reachable=module_of(pkg) in imported))
        else:
            out.append(f)
    return out
