"""Gate-integrity (ADR-0008, questão EM ABERTO do threat model): impedir que a IA do projeto ENFRAQUEÇA a
régua (.secpipe.yml) para o gate passar. Grava um snapshot canônico da política em `.secpipe.lock`; um check
de CI reprova diffs que a tornem MAIS FRACA vs. o lock. Domínio PURO (hashlib/stdlib)."""
from __future__ import annotations

import hashlib
import json

from secpipe.domain.models import Severity

Snapshot = dict[str, object]


def make_snapshot(block_severity: str, scanners: tuple[str, ...], require: tuple[str, ...],
                  min_scanners: int, kev_blocks: bool) -> Snapshot:
    """Representação canônica (ordenada) da política relevante ao gate."""
    return {
        "block_severity": Severity.parse(block_severity).name,
        "scanners": sorted(set(scanners)),
        "require": sorted(set(require)),
        "min_scanners": int(min_scanners),
        "kev_blocks": bool(kev_blocks),
    }


def canonical_json(snap: Snapshot) -> str:
    return json.dumps(snap, sort_keys=True, ensure_ascii=False)


def policy_hash(snap: Snapshot) -> str:
    return hashlib.sha256(canonical_json(snap).encode("utf-8")).hexdigest()


def weaknesses(locked: Snapshot, current: Snapshot) -> list[str]:
    """Lista as formas em que `current` é MAIS FRACA que `locked` (vazio = igual ou mais forte = OK)."""
    out: list[str] = []
    # block_severity MAIOR = mais permissivo (deixa passar mais) = mais fraco.
    lb = Severity.parse(str(locked.get("block_severity", "HIGH")))
    cb = Severity.parse(str(current.get("block_severity", "HIGH")))
    if cb > lb:
        out.append(f"block_severity afrouxou: {lb.name} -> {cb.name}")
    # scanners/require REMOVIDOS = menos cobertura = mais fraco.
    removed_scanners = set(_slist(locked, "scanners")) - set(_slist(current, "scanners"))
    if removed_scanners:
        out.append(f"scanners removidos: {', '.join(sorted(removed_scanners))}")
    removed_require = set(_slist(locked, "require")) - set(_slist(current, "require"))
    if removed_require:
        out.append(f"require removido: {', '.join(sorted(removed_require))}")
    if _int(current, "min_scanners") < _int(locked, "min_scanners"):
        out.append("min_scanners diminuiu")
    if locked.get("kev_blocks") and not current.get("kev_blocks"):
        out.append("kev_blocks foi desligado")
    return out


def _slist(snap: Snapshot, key: str) -> list[str]:
    val = snap.get(key)
    return [str(x) for x in val] if isinstance(val, list) else []


def _int(snap: Snapshot, key: str, default: int = 1) -> int:
    val = snap.get(key, default)
    return val if isinstance(val, int) and not isinstance(val, bool) else default
