# FEAT-007 — Grounding de conhecimento + RAG corretivo

> **Fase 3** · Base: `KnowledgeGate` + `CorrectiveRAG` do Omni (§7). Faz a IA corrigir **fundamentada**,
> não por chute, e ficar mais esperta a cada falha.

## Objetivo
Antes de propor um fix, a IA **consulta** conhecimento relevante (padrões seguros do CWE, fixes
verificados anteriores, regras do `AGENTS.md`); e quando um fix **falha na verificação**, a query é
**reformulada a partir da falha** — não retenta cega.

## Problema
LLM corrige por padrão-plausível, às vezes inseguro/errado. Sem grounding, erra mais; sem corretivo,
repete o mesmo erro. O Omni: *"a falha é a melhor query"*.

## Requisitos
- **RF-01**: **gate cabeado** — bloquear propor fix sem consulta de conhecimento, disparado por sinal
  **OBJETIVO** (o `cwe`/`rule_id` do finding), nunca pelo "isso é difícil?" subjetivo da IA.
- **RF-02**: dedup de consultas por **fingerprint** (não re-consultar o mesmo CWE à toa).
- **RF-03**: **query corretiva** determinística a partir da falha ("como corrigir CWE-89 em <stack> quando <falhou X>").
- **RF-04**: fontes: base de padrões seguros por CWE + memória de fixes verificados (FEAT-009) + `AGENTS.md`.
- **RS-01**: domínio puro na derivação de sinais (zero I/O); o adapter faz a busca.

## Design
```python
def knowledge_signals(finding: Finding, consulted: set[str]) -> list[KnowledgeSignal]: ...
def corrective_query(cwe: str, stack: str, failure: str) -> str: ...  # determinístico, estável
class KnowledgePort(Protocol):
    def lookup(self, query: str) -> list[KnowledgeItem]: ...   # padrões, fixes anteriores
```
- `KnowledgeSignal.fingerprint` = `kb:{cwe}:{stack}` → dedup contra `consulted`.
- Fontes locais primeiro (padrões embutidos + memória FEAT-009); busca externa é **opcional** e sem dado do projeto.

## Segurança / guardrails
- Gatilho **objetivo** (CWE), não subjetivo — evita o "fuzzy trigger" que o Omni identificou como falha.
- Conhecimento **PROPÕE**; o firewall (FEAT-002) e o verificador (FEAT-005) **decidem**. RAG nunca autoriza.
- Nenhum dado sensível do projeto vai para busca externa.

## Critérios de aceite
- Fix proposto sem consulta ao CWE ⇒ bloqueado pelo gate.
- Falha de verificação ⇒ próxima tentativa usa a query corretiva (não idêntica à anterior).
- Consulta duplicada do mesmo CWE é deduplicada.

## Estratégia de testes
- `corrective_query` determinística (mesma entrada → mesma query).
- Dedup por fingerprint; gate bloqueia sem consulta.

## Pontos em aberto
- Base de padrões seguros por CWE: curada, ou derivada de OWASP/Semgrep rules? *[EM ABERTO]*
- Busca externa habilitada por padrão? *[HIPÓTESE: não — local-first, externa opt-in]*
