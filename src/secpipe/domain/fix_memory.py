"""Memória de fixes verificados (FEAT-009) — modelo puro. SÓ entra fix que PASSOU na verificação.

No modelo keyless (operador = IA), a composição ENTRE projetos é da camada compartilhada/SaaS (futuro);
localmente é o substrato que o agente usa: registra o padrão de um fix verificado e recupera por CWE."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class VerifiedFix:
    cwe: str
    tool: str
    rule_id: str
    note: str = ""   # o PADRÃO generalizado do fix (ex.: "usar query parametrizada"), nunca código literal

    def key(self) -> str:
        """Chave de deduplicação (não guarda código do projeto — só o padrão)."""
        return f"{self.cwe}|{self.rule_id}|{self.note}".strip().lower()
