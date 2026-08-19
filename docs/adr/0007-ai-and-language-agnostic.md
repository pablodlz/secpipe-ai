# ADR-0007 — Agnóstico de IA e de linguagem

**Status:** Aceito (Fase 0).

## Contexto
Requisito: compatível com QUALQUER projeto (linguagem) e QUALQUER IA (agente e provedor), não só Python/Claude.

## Decisão
- **Linguagem:** motor em container (consumidor não precisa de Python); scanners multi-linguagem; adapters específicos (Bandit/pip-audit) são um entre muitos.
- **IA (orientação):** contexto de segurança em **`AGENTS.md` canônico** (padrão neutro) + shims opcionais (`CLAUDE.md`, `.cursor/rules`, `.github/copilot-instructions.md`, `CONVENTIONS.md`).
- **IA (imposição):** **agent-independent** — git pre-commit hooks + CI aplicam o gate mesmo que o agente ignore o `AGENTS.md`.
- **Provedor de IA (fase 3):** `AIProviderPort` (Claude/OpenAI/Gemini/local).

## Consequências
- (+) Serve todos os projetos e todas as IAs; guardrail não depende de cooperação do agente.
- (−) Precisa manter shims/adapters. Aceito.
