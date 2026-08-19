# 00 — Overview

> **O operador desta esteira é a IA**, não um humano. O objetivo é que **todo projeto desenvolvido por
> IA nasça e permaneça seguro**, com a própria IA achando e corrigindo suas vulnerabilidades — nada
> pendente de uma pessoa. Fonte de verdade do projeto; o que não sabemos vira *ponto em aberto*.

## Objetivo

Fornecer um **motor de segurança adotável** (`secpipe`) que qualquer projeto aplica **antes** de começar
a desenvolver, de modo que a **IA desenvolvedora** desse projeto:
1. desenvolva seguindo padrões seguros (secure-by-default, contexto de segurança carregado);
2. **escaneie** o próprio código (SAST/SCA/secret/IaC) de forma contínua e automática;
3. **corrija** os achados sozinha (loop Detect→Repair→Verify);
4. seja **impedida por guardrails** de burlar/silenciar o próprio gate.

Tudo gratuito, self-hosted, **agnóstico de linguagem** (qualquer projeto/stack) e **agnóstico de IA**
(qualquer agente — Claude, Cursor, Copilot, Aider… — e qualquer provedor — Claude/OpenAI/Gemini/local).

## Compatibilidade (requisito de primeira classe)

- **Qualquer linguagem/projeto:** o motor roda como **container** (o consumidor não precisa ter Python); os scanners são multi-linguagem (Semgrep, Trivy, gitleaks, Checkov, ASH…). Adapters específicos (Bandit/pip-audit p/ Python) são só um entre muitos.
- **Qualquer IA:** o contexto de segurança é emitido em **`AGENTS.md` (padrão neutro)**, com *shims* opcionais por ferramenta (`CLAUDE.md`, `.cursor/rules`, `.github/copilot-instructions.md`) apontando para ele. E — crucial — a **imposição não depende do agente**: git hooks + CI aplicam o gate mesmo que o agente ignore o `AGENTS.md`.

## Problema

IA acelera o desenvolvimento, mas também **introduz vulnerabilidades em escala** (código inseguro,
segredo vazado, dependência vulnerável). Revisar isso manualmente não escala e reintroduz a pessoa no
loop. Ferramentas de mercado ou (a) exigem operador humano/painel, (b) são pagas/hospedadas, ou (c)
corrigem só um scanner (ex.: Copilot Autofix só CodeQL). Falta uma camada **grátis, operada pela IA,
que torne "desenvolver com IA" = "desenvolver com segurança por padrão"**.

## Quem opera (mudança de eixo)

| Ator | Papel | Confiança |
| --- | --- | --- |
| **IA desenvolvedora** (do projeto consumidor) | escreve, escaneia, corrige, verifica | **operador — mas NÃO confiável para se auto-julgar** |
| `secpipe` (motor referenciado/versionado) | acha, normaliza, aplica gate, guarda os guardrails | fonte da régua (a IA não a edita) |
| Verificador independente (2º contexto/IA) | valida o fix; decide *abstention* | árbitro (separado de quem desenvolve) |
| Humano (você) | define política uma vez; recebe só o que for escalado | fora do loop no caso comum |

> Ponto central: a IA é o operador, **e** é justamente por isso que o sistema precisa de guardrails que
> ela não controla (ver `03-security.md`, "quem guarda o guarda").

## Escopo — Fase 0 (esta execução)

Fundação + **esqueleto rodável e testado**: estrutura, Specs, ADRs, contrato de achados normalizado,
política de gate, CLI (`doctor`/`scan` esqueleto), os **dois modos de adoção**, e a arquitetura de
composição (ver `02`). Prior-art e literatura levantados em `06`.

## Fora de escopo — Fase 0

- Execução/parsing real dos scanners (integração com ASH/Semgrep/Trivy/etc.).
- O loop de auto-fix por IA e o verificador independente (só arquitetados).
- DAST, IaC scanning, publicação da imagem, integração DefectDojo.
- Onboarding real (`secpipe init` que instala hooks + instruções de agente).

## Como um projeto "aplica" o secpipe (visão)

```text
Novo projeto  ──▶  secpipe init  ──▶  instala: .secpipe.yml + hooks + AGENTS.md de segurança
                                             │
                        A IA do projeto desenvolve JÁ dentro desses guardrails:
      escreve ──▶ secpipe scan (JSON/SARIF) ──▶ corrige (DRV) ──▶ verificador independente ──▶ gate
                                             │
                        Só o que a IA não deve decidir sozinha é escalado a você.
```

## Fases (macro)

```text
Fase 0  Foundation (aqui)      → estrutura, contrato, política, CLI esqueleto, composição
Fase 1  Motor de scan          → compor tools free (ASH/Semgrep/Trivy/gitleaks) + normalizar p/ SARIF
Fase 2  Gate + adoção          → política fail-closed + `secpipe init` (hooks + AGENTS.md) + supply-chain
Fase 3  Auto-fix (DRV)         → loop achar→corrigir→VERIFICAR + verificador independente + abstention
Fase 4  Integrar nos projetos  → aplicar aos bots/Clavis/(opcional Omni)
```

## Critérios de sucesso da Fase 0

- Fica claro que o **operador é a IA** e onde estão os guardrails que ela **não** controla.
- A arquitetura **compõe** ferramentas free (não reinventa) e define o contrato para a IA.
- Os dois modos de adoção estão especificados.
- Pontos indefinidos listados como perguntas, não suposições.
