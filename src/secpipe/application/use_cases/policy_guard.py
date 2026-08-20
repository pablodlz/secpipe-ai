"""`secpipe policy-lock` / `policy-check` — grava e valida o `.secpipe.lock`. Imposição TÉCNICA da
integridade da política (combina com CODEOWNERS: mudar a régua exige review do dono de segurança).

Camada application: só I/O + orquestração; a lógica de comparação mora no domínio (policy_lock)."""
from __future__ import annotations

import json
import os

from secpipe.domain.policy_lock import Snapshot, policy_hash, weaknesses

LOCK_FILE = ".secpipe.lock"


def write_lock(path: str, snapshot: Snapshot) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"policy": snapshot, "hash": policy_hash(snapshot)}, fh, sort_keys=True, indent=2)
        fh.write("\n")


def check_lock(path: str, current: Snapshot) -> tuple[bool, list[str]]:
    """Compara a política atual com o lock. (ok, problemas). ok=False se enfraqueceu (ou lock ausente/corrompido)."""
    if not os.path.isfile(path):
        return (False, [f"{path} ausente — rode `secpipe policy-lock` e faca commit (protegido por CODEOWNERS)"])
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        return (False, [f"lock ilegivel: {exc}"])
    locked = data.get("policy") if isinstance(data, dict) else None
    if not isinstance(locked, dict):
        return (False, ["lock invalido (sem 'policy')"])
    problems = weaknesses(locked, current)
    return (not problems, problems)
