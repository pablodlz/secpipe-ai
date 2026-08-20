"""`secpipe config-validate` — pega MISCONFIG SILENCIOSA: hoje `Config.from_dict` cai em default sem avisar
(um typo em 'scanners' vira o default; block_severity inválido vira CRITICAL via Severity.parse). Config que
enfraquece o gate por engano é risco de segurança — aqui listamos os erros de forma explícita (exit != 0)."""
from __future__ import annotations

import os

from secpipe.domain import Severity

# Chaves reconhecidas no .secpipe.yml (expandir conforme novas features adicionam config).
_KNOWN_KEYS = frozenset({
    "scanners", "block_severity", "languages", "test_command",
    "dast", "dast_target", "min_scanners", "require",
    "image_target", "licenses",
})


def validate_config(path: str, known_scanners: frozenset[str]) -> list[str]:
    """Valida o arquivo de config. Devolve a lista de problemas (vazia = OK). Não lança."""
    if not os.path.isfile(path):
        return [f"arquivo nao encontrado: {path}"]
    try:
        import yaml
    except ImportError:  # pragma: no cover - ambiente
        return ["PyYAML nao instalado — nao da para validar (instale 'pyyaml')"]
    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        return [f"YAML invalido: {str(exc)[:200]}"]
    if data is None:
        return []  # arquivo vazio = zero-config válido
    if not isinstance(data, dict):
        return ["raiz do .secpipe.yml deve ser um mapeamento (chave: valor)"]

    errors: list[str] = []
    for key in data:
        if key not in _KNOWN_KEYS:
            errors.append(f"chave desconhecida: '{key}' (typo? chaves validas: {', '.join(sorted(_KNOWN_KEYS))})")

    sev = data.get("block_severity")
    if sev is not None and (not isinstance(sev, str) or sev.strip().upper() not in Severity.__members__):
        errors.append(f"block_severity invalido: {sev!r} (use um de {', '.join(Severity.__members__)})")

    scanners = data.get("scanners")
    if scanners is not None and not isinstance(scanners, list):
        errors.append("scanners deve ser uma lista")
    elif isinstance(scanners, list):
        for s in scanners:
            if s not in known_scanners:
                errors.append(f"scanner desconhecido: '{s}' (conhecidos: {', '.join(sorted(known_scanners))})")

    require = data.get("require")
    if require is not None and not isinstance(require, list):
        errors.append("require deve ser uma lista")
    elif isinstance(require, list) and isinstance(scanners, list):
        for r in require:
            if r not in scanners:
                errors.append(f"require '{r}' nao esta na lista 'scanners' — nunca rodaria")

    mins = data.get("min_scanners")
    if mins is not None and (not isinstance(mins, int) or isinstance(mins, bool) or mins < 0):
        errors.append(f"min_scanners invalido: {mins!r} (inteiro >= 0)")

    return errors
