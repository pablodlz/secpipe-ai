"""Carrega .secpipe/waivers.yml -> list[Waiver]. Fail-closed: entrada malformada (sem fingerprint) é
IGNORADA (não isenta nada). Criar waiver é via PR reviewado (CODEOWNERS), nunca pelo agente."""
from __future__ import annotations

import os

from secpipe.domain.waivers import Waiver

WAIVERS_FILE = os.path.join(".secpipe", "waivers.yml")


def load_waivers(path: str) -> list[Waiver]:
    if not os.path.isfile(path):
        return []
    try:
        import yaml
    except ImportError:  # pragma: no cover - ambiente
        return []
    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except (OSError, yaml.YAMLError):
        return []
    entries = data.get("waivers") if isinstance(data, dict) else data
    if not isinstance(entries, list):
        return []
    out: list[Waiver] = []
    for item in entries:
        if not isinstance(item, dict) or not item.get("fingerprint") or not item.get("expires"):
            continue   # fail-closed: sem fingerprint/expiração -> ignora
        out.append(Waiver(
            fingerprint=str(item["fingerprint"]), reason=str(item.get("reason", "")),
            owner=str(item.get("owner", "")), ticket=str(item.get("ticket", "")),
            expires=str(item["expires"]),
        ))
    return out
