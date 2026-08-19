# FEAT-010 — Adoção (`secpipe init`) + contexto de agente

> **Fase 2** · O que faz o secpipe ser **plug-and-play** (ADR-0009) e **operado por qualquer IA** (ADR-0007).
> Instala num projeto o contexto + a imposição para a IA dele desenvolver seguro. GitHub é o padrão.

## Objetivo
Um comando (`secpipe init`) que "aplica" o secpipe num projeto: config, hooks de imposição
**agent-independent**, contexto de segurança para a IA (`AGENTS.md` + shims), e o workflow (GitHub por padrão).

## Problema
Se adotar dá trabalho, ninguém adota. E se a imposição depende de o agente cooperar, não vale nada. Tem
que ser um comando, com defaults fortes, e a trava tem que ser estrutural.

## Requisitos
- **RF-01 (plug-and-play):** `secpipe init` funciona com **zero pergunta** (defaults fortes); `.secpipe.yml` é opcional.
- **RF-02 (imposição agent-independent):** instala **git hooks**:
  - `pre-commit`: bloqueia **segredo** (gitleaks) e **supressão** (`# nosec`/`# noqa`/baseline).
  - `pre-push`/`stop`: roda `secpipe scan` + gate.
- **RF-03 (contexto de agente, qualquer IA):** grava **`AGENTS.md` canônico** (regras: não silenciar, não
  editar política, corrigir+verificar, escalar categorias sensíveis) + **shims opcionais** (`CLAUDE.md`,
  `.cursor/rules`, `.github/copilot-instructions.md`, `CONVENTIONS.md`) apontando para ele.
- **RF-04 (GitHub padrão):** adiciona o workflow referenciado (`secpipe.reusable.yml@vX`); **sem GitHub** ⇒ instrução local/container.
- **RF-05 (idempotente):** rodar de novo não duplica; atualiza in-place.

## Design
```text
secpipe init [--mode referenced|template] [--no-shims]
 → .secpipe.yml (se ausente; defaults fortes)
 → .githooks/ (pre-commit, pre-push) + ativa (core.hooksPath)
 → AGENTS.md (canônico) [+ shims]
 → .github/workflows/security.yml (referenced@vX)  |  fallback: instrução docker/CLI
```
Template do `AGENTS.md` já existe em `templates/AGENTS.security.md`.

## Segurança / guardrails
- A **imposição real** são os hooks + CI (estrutural), **não** o `AGENTS.md` (orientação). Um agente que
  ignore o `AGENTS.md` ainda bate no hook e no CI (agent-independent). É o antídoto ao "enforcement theater".
- O hook anti-supressão é o guardrail do ADR-0008 no ponto de commit.

## Critérios de aceite
- `secpipe init` num repo vazio deixa scan+gate+contexto funcionando sem config manual.
- Tentar commitar `# nosec` novo é bloqueado pelo hook.
- Rodar `init` duas vezes é idempotente.

## Estratégia de testes
- Init em fixture → arquivos esperados presentes; hook bloqueia supressão/segredo; idempotência.

## Pontos em aberto
- Ativar hooks via `core.hooksPath` vs. `pre-commit` framework? *[HIPÓTESE: `pre-commit` framework, já usado]*
- Quais shims gerar por default? *[HIPÓTESE: AGENTS.md sempre; shims sob flag]*
