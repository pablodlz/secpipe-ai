"""Store local da memória de fixes (JSON em .secpipe/fix_memory.json).

Guarda o PADRÃO generalizado (nunca código/segredo do projeto). A composição entre projetos/tenants é
da camada compartilhada/SaaS (futuro) — aqui é o substrato local que o agente usa."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from secpipe.domain.fix_memory import VerifiedFix

DEFAULT_PATH = ".secpipe/fix_memory.json"


class FixMemory:
    def __init__(self, path: str = DEFAULT_PATH) -> None:
        self._path = Path(path)

    def _load(self) -> list[dict[str, str]]:
        if not self._path.is_file():
            return []
        try:
            raw: Any = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        if not isinstance(raw, list):
            return []
        return [{str(k): str(v) for k, v in item.items()} for item in raw if isinstance(item, dict)]

    def _to_fix(self, item: dict[str, str]) -> VerifiedFix:
        return VerifiedFix(
            cwe=item.get("cwe", ""), tool=item.get("tool", ""),
            rule_id=item.get("rule_id", ""), note=item.get("note", ""),
        )

    def record(self, fix: VerifiedFix) -> bool:
        """Registra um fix verificado. Retorna False se já existia (dedup por padrão)."""
        items = self._load()
        if any(self._to_fix(i).key() == fix.key() for i in items):
            return False
        items.append({"cwe": fix.cwe, "tool": fix.tool, "rule_id": fix.rule_id, "note": fix.note})
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding="utf-8")
        return True

    def recall(self, cwe: str) -> list[VerifiedFix]:
        """Padrões de fix verificados para um CWE (candidatos — ainda passam pela verificação)."""
        return [self._to_fix(i) for i in self._load() if i.get("cwe", "").upper() == cwe.strip().upper()]
