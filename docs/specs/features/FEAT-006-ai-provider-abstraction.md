# FEAT-006 — Abstração de IA + fallback multi-provedor

> **Fase 3** · Base: `MultiProvider` do Omni (§6). Reusável quase literal. Provider-agnostic (ADR-0007).

## Objetivo
Uma porta única de IA com **fallback** entre provedores, seleção por custo/tarefa/disponibilidade, e
governança de custo — para o auto-fix (FEAT-008) e o verificador (FEAT-005) não dependerem de um modelo.

## Problema
Depender de um provedor é frágil (quota, indisponibilidade) e caro. E um fallback ingênuo cai só para o
provedor **desconfigurado**, não para o que **respondeu** — inútil em produção (lição do Omni).

## Requisitos
- **RF-01**: `AIProviderPort` única; adapters Claude/OpenAI/Gemini/local.
- **RF-02**: fallback para o **primeiro que RESPONDE** (não o primeiro com chave); todos falharem ⇒ erro **alto** (com causas).
- **RF-03**: seleção por config/tarefa/custo; **tier-routing** (modelo forte só onde caro errar).
- **RF-04**: **orçamento por execução** (corta ao estourar); timeouts; retries idempotentes.
- **RS-01**: **redaction** de segredo/PII no prompt; **minimização** de dados enviados ao provedor.
- **RS-02**: observabilidade por chamada (tokens, custo, latência, provedor) — telemetria.

## Design
```python
class AIProviderPort(Protocol):
    def available(self) -> bool: ...
    def complete(self, prompt: str) -> str: ...
class MultiProvider:  # tenta em ordem; retorna o 1º que RESPONDE; todos falham ⇒ raise loud
    def complete(self, prompt: str) -> str: ...
```
Reusa o padrão do Omni: iterar, `if not available(): continue`, `try/except → fallthrough`, acumular
falhas, `raise` com todas as causas se ninguém respondeu. Adiciona: orçamento e telemetria por chamada.

## Segurança / guardrails
- **Nunca** mandar segredo/credencial/PII do projeto ao provedor (redaction obrigatória).
- Falha de todos os provedores é **loud** — no auto-fix, isso vira fail-closed (não aceita fix às cegas).

## Critérios de aceite
- 1º provider erra (429) ⇒ 2º é tentado; todos erram ⇒ raise com causas.
- Prompt com segredo é redigido antes de enviar.
- Orçamento estourado corta a chamada.

## Estratégia de testes
- Mocks: disponível-mas-erra, indisponível, responde → ordem de fallback correta.
- Teste de redaction; teste de corte por orçamento.

## Pontos em aberto
- Formato de config de seleção (por tarefa/custo)? *[EM ABERTO]*
- Suporte a modelo local (Ollama/llama.cpp) desde já? *[HIPÓTESE: adapter opcional]*
