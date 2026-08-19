# 01 — Requirements

> Requisitos com o operador = **IA**. Meta declarada: ser **a melhor opção de segurança de custo zero
> do mercado**, compondo o melhor do que já existe (free) + uma camada de sofisticação própria.

## Requisitos Funcionais

| ID | Requisito | Fase |
| --- | --- | --- |
| RF-01 | **Descobrir** vulnerabilidades: SAST, SCA, secret, IaC, (depois) DAST | 1 |
| RF-02 | **Normalizar** todo achado num contrato único (SARIF + CWE) | 1 |
| RF-03 | **Deduplicar** achados entre tools (evitar ruído p/ a IA) | 1 |
| RF-04 | Expor os achados em **JSON machine-first** para a IA consumir | 1 |
| RF-05 | Aplicar **gate de política** (severidade que bloqueia), fail-closed | 2 |
| RF-06 | `secpipe init`: **adotar** o motor num projeto (config + hooks + AGENTS.md de segurança) | 2 |
| RF-07 | Hooks de desenvolvimento (bloquear commit de segredo, scan ao finalizar) | 2 |
| RF-08 | **Auto-fix determinístico** (codemods) para o que for seguro corrigir | 3 |
| RF-09 | **Auto-fix por IA** (DRV) para o resto, provider-agnostic | 3 |
| RF-10 | **Verificação independente** do fix (rerodar checks + testes) antes de aceitar | 3 |
| RF-11 | **Abstention**: reconhecer o que NÃO deve corrigir sozinha e escalar | 3 |
| RF-12 | Supply-chain do próprio pipeline (Scorecard, harden-runner, pin por SHA) | 2 |
| RF-13 | Exportar para gestão externa (DefectDojo) — opcional | 4 |

## Requisitos Não-Funcionais

| ID | Requisito |
| --- | --- |
| RNF-01 | **Custo zero**: só tools free/CE; self-hosted; funciona em repo **privado** (sem depender de CodeQL/GHAS pago) |
| RNF-02 | **Machine-first**: saída determinística e estável para a IA (contrato versionado) |
| RNF-03 | **Provider-agnostic** de IA (trocar Claude/OpenAI/Gemini/local sem reescrever) |
| RNF-04 | **Portável**: roda em GitHub Actions, outra CI e local (motor em container) |
| RNF-05 | **Reutilizável sem drift**: referenciado por versão; template só veste o wrapper |
| RNF-06 | **Auditável**: todo achado→fix→verificação deixa trilha |
| RNF-07 | **Baixo atrito de adoção**: um comando para aplicar num projeto novo |
| RNF-08 | **Determinismo do gate**: mesma entrada → mesma decisão |
| RNF-09 | **Agnóstico de linguagem**: roda em qualquer stack (container; consumidor não precisa de Python); scanners multi-linguagem |
| RNF-10 | **Agnóstico de IA/agente**: contexto em `AGENTS.md` neutro + shims por ferramenta; **imposição agent-independent** (git hooks + CI), não depende de nenhum agente cooperar |
| RNF-11 | **Plug-and-play**: funciona com **zero config** (defaults seguros e fortes; detecção de linguagem automática). O `.secpipe.yml` é opcional (tunar), nunca pré-requisito. **Facilidade NÃO reduz poder** — o default é o modo completo, não uma versão capada (ADR-0009) |
| RNF-12 | **Dogfooding**: o próprio repo do `secpipe` é seu 1º consumidor (roda a esteira em si mesmo) |

## Requisitos de Segurança (do próprio motor — é um produto de segurança)

| ID | Requisito |
| --- | --- |
| RS-01 | **A IA operadora NÃO pode silenciar o próprio achado**: proibir supressão (`# nosec`/`# noqa`/baseline/severidade) no diff sem aprovação | 
| RS-02 | **Política/gate mora no motor referenciado**, fora do alcance de edição da IA do projeto |
| RS-03 | **Verificação independente** (2º contexto) valida o fix — quem corrige não é quem aprova |
| RS-04 | Fix por IA só é aceito com **teste que reproduz a vuln** passando (não silêncio do scanner) |
| RS-05 | Supply-chain: actions pinadas por SHA, releases assinadas, egress monitorado (harden-runner) |
| RS-06 | Zero segredo exposto a workflow de PR de fork (repo público) |
| RS-07 | Consumidor **pina a versão** do motor; bump é mudança revisável (a IA não bumpa sozinha) |
| RS-08 | O motor não executa código não-confiável de alvo com privilégio (isola tools) |

## Regras (invariantes)

- **RN-01**: nenhuma correção por IA é aceita sem verificação independente + teste.
- **RN-02**: a IA do projeto não altera a política que a julga (fonte no motor referenciado).
- **RN-03**: severidade/gate são derivados de evidência, não declarados pela IA (espelha o Omni).
- **RN-04**: preferir **fix determinístico** (codemod) a fix por IA quando existir — mais seguro/barato.

## Critérios de aceite — Fase 0

- Contrato de achados (`Finding`/`Report`) definido e testado.
- Política de gate pura e testada (fail-closed, default-deny).
- CLI `doctor` real; `scan` esqueleto rodável.
- Modos de adoção especificados; matriz "melhor de cada projeto" documentada (`02`).
- Guardrail central ("quem guarda o guarda") descrito em `03`.
