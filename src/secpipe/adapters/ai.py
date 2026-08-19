"""Adapters de IA (FEAT-006). MultiProvider faz fallback; NullProvider é o default seguro (sem IA).

Lição do Omni (multi_provider): cair para o primeiro que RESPONDE (não o primeiro que tem chave); se
TODOS falharem, levantar ALTO (com as causas) — nunca um PASS silencioso. Real SDK adapters entram
depois (precisam de chave via env); a arquitetura é provider-agnostic (ADR-0007)."""
from __future__ import annotations

import logging
from collections.abc import Sequence

from secpipe.application.ports import AIProviderPort

_log = logging.getLogger("secpipe.ai")


class NoProviderAvailable(RuntimeError):
    """Nenhum provedor de IA respondeu. No auto-fix, isto vira fail-closed (não aceita fix às cegas)."""


class NullProvider:
    """Provedor default: sem IA configurada. `available()` False -> o fix por IA é pulado (Fase 3 sem chave)."""
    name = "null"

    def available(self) -> bool:
        return False

    def complete(self, prompt: str) -> str:
        raise NoProviderAvailable("nenhum provedor de IA configurado")


class MultiProvider:
    """Tenta os provedores em ordem e retorna o do PRIMEIRO que RESPONDE. Todos falharem -> levanta."""

    name = "multi"

    def __init__(self, providers: Sequence[AIProviderPort]) -> None:
        self._providers = list(providers)

    def available(self) -> bool:
        return any(p.available() for p in self._providers)

    def complete(self, prompt: str) -> str:
        failures: list[str] = []
        for provider in self._providers:
            if not provider.available():
                continue
            try:
                return provider.complete(prompt)
            except Exception as exc:  # tentar o proximo provedor e o ponto do fallback
                _log.warning("provedor de IA %s falhou, tentando o proximo: %s", provider.name, exc)
                failures.append(f"{provider.name}: {exc}")
        if failures:
            raise NoProviderAvailable(
                f"todos os provedores disponiveis falharam ({len(failures)}) — {'; '.join(failures)}"
            )
        raise NoProviderAvailable("nenhum provedor de IA disponivel/configurado")
