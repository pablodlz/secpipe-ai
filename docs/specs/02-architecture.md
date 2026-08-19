# 02 — Architecture

> Filosofia: **compor o melhor free best-of-breed + uma camada de sofisticação própria** = ser a melhor
> opção de custo zero. Operador = IA. Hexagonal: núcleo puro; scanners/fixers/IA são adapters.

## Estratégia: "melhor de cada projeto" → nosso superset

| Pegamos de… | O quê | Como entra no `secpipe` |
| --- | --- | --- |
| **ASH** (AWS) | orquestração security-first + isolamento de tools | base do orquestrador de scanners |
| **MegaLinter** | breadth, config-driven, reporters, CI-native | modelo de config (`.secpipe.yml`) e reporters |
| **DefectDojo** | normalização/dedup de 500+ tools, ASPM | modelo de normalização/dedup + alvo de exportação |
| **Pixee/Codemodder** | remediação determinística via SARIF (codemods OSS) | camada de **fix determinístico** (antes da IA) |
| **OpenSSF Scorecard** | 18+ checks de postura do repo | módulo de postura + auto-avaliação |
| **Harden-Runner / Secure-Repo** | egress-monitoring do runner + pin por SHA | supply-chain do próprio pipeline |
| **Copilot Autofix / Semgrep Assistant** (conceito) | sugestão de fix por IA | reimplementado **provider-agnostic, self-hosted, multi-scanner, com DRV** |
| **Literatura DRV / abstention** | validar patch, abster-se, feedback | desenho do loop de auto-fix e seus guardrails |

## O que nos torna "muito melhor" (diferenciais grátis)

1. **Operado pela IA, autônomo de verdade** (não só "sugestão"): loop Detect→Repair→**Verify** self-hosted.
2. **Fix determinístico primeiro, IA depois**: codemods (Pixee) resolvem o seguro; a IA só pega o resto — mais seguro, barato e confiável que "LLM em tudo".
3. **Guardrails anti-self-gaming** (quem guarda o guarda): lacuna real nas tools atuais.
4. **Agnóstico de linguagem e de IA + funciona em repo privado sem paywall**: container (qualquer stack, sem exigir Python no consumidor), scanners multi-linguagem, qualquer agente/provedor. Sem CodeQL/GHAS (usa Semgrep CE + Bandit + ASH).
5. **Adoção que instala o contexto de segurança do agente** (hooks + `AGENTS.md` neutro), não só scanners — **e a imposição é agent-independent** (ver abaixo).
6. **Contrato SARIF+CWE auditável** como interface única da IA.

## Integração com agentes (agnóstica) + imposição agent-independent

Não podemos assumir que um agente específico coopere. Por isso separamos **orientação** de **imposição**:

- **Orientação (por agente):** `secpipe init` emite um **`AGENTS.md` canônico** (padrão neutro adotado por vários agentes) com os padrões seguros e as regras ("não edite a política", "não silencie achado"). *Shims* opcionais por ferramenta — `CLAUDE.md`, `.cursor/rules`, `.github/copilot-instructions.md` — apenas apontam para o `AGENTS.md`. Qualquer IA lê a mesma fonte.
- **Imposição (agent-independent):** o gate real vive em camadas que **nenhum agente controla** — **git pre-commit hooks** (bloqueiam segredo e supressão) e **CI** (roda `secpipe` e falha o build). Mesmo um agente que ignore o `AGENTS.md` bate no hook e no CI. Isto é o que resolve "quem guarda o guarda" para **qualquer** IA (ver `03-security.md`).

## Camadas

```text
      entrypoints: CLI (secpipe)  ·  reusable workflow  ·  hooks de agente
                         │
                         ▼
      application: orchestrator · gate(policy) · (fase 3) fix-loop DRV · verifier
                    │            ▲
                    ▼            │ (adapters implementam ports)
      domain (puro)          adapters
      Finding/Report/Severity/Policy   Scanners(Semgrep/Bandit/Trivy/gitleaks/ASH)
                                       Fixers(Codemodder/IA)  ·  Reporters(SARIF/JSON/DefectDojo)
                         ▲
      foundation: config(.secpipe.yml) · logging · composition root
```

- **domain/** — `Finding`, `Severity`, `ScanResult`, `Report`, `Policy` (puro, sem I/O). É o **contrato** e a **régua**.
- **application/** — `Orchestrator` (roda scanners, agrega, dedup), `PolicyGate` (decide bloquear), e (fase 3) `FixLoop` (DRV) + `Verifier`. Ports aqui.
- **adapters/** — `ScannerPort` (Semgrep, Bandit, Trivy, gitleaks, ASH…), `FixerPort` (Codemodder, IA), `ReporterPort` (SARIF, JSON, DefectDojo).
- **foundation/** — config, logging, composition root.

## Ports (abstrações substituíveis)

| Port | Responsabilidade | Adapters |
| --- | --- | --- |
| `ScannerPort` | rodar um scanner e devolver `Finding[]` normalizados | Semgrep, Bandit, pip-audit, Trivy, gitleaks, ASH, ZAP(fut.) |
| `ReporterPort` | serializar `Report` | SARIF, JSON (IA), DefectDojo(fut.) |
| `FixerPort` (fase 3) | propor correção para um `Finding` | Codemodder (determinístico), IA (provider-agnostic) |
| `VerifierPort` (fase 3) | validar independentemente um fix (rerun + testes) | verificador (2º contexto) |
| `AIProviderPort` (fase 3) | IA para o fix (troca de modelo) | Claude/OpenAI/Gemini/local |

## O loop de auto-fix (fase 3 — Detect→Repair→Verify)

```text
scan → Finding(normalizado) → [Fixer determinístico? aplica] senão [Fixer IA propõe]
        → Verifier INDEPENDENTE: rerun scanners + testes + "reproduz a vuln?" 
        → aceita SÓ se verde e sem regressão;  senão → abstention → escala a humano
```
Guardrails (ver `03`): sem supressão no diff; política fora do alcance da IA; verificador ≠ quem corrige.

## Contrato normalizado (a interface da IA)

`Finding` mínimo: `id`, `tool`, `rule_id`, `cwe`, `severity`, `file`, `line`, `message`, `fingerprint`
(para dedup determinística). Serializável em **SARIF** (interop/GitHub) e **JSON** (a IA). É o schema
estável de que a IA depende — versionado.

## Empacotamento & distribuição (motor único, dois modos)

- **Container** (imagem com tools + CLI) = motor portável (qualquer CI + local).
- **Reusable workflow** (`workflow_call`) = adoção referenciada no GitHub.
- **use-as-template** = adoção "template" (copia só wrapper + `.secpipe.yml`; puxa a mesma imagem).
Detalhe em `04-consumption-models.md`.

## Pontos de extensão

Novo scanner → adapter de `ScannerPort`. Novo formato → `ReporterPort`. Nova estratégia de fix →
`FixerPort`. Novo provedor de IA → `AIProviderPort`. Nada disso toca o domínio/contrato.

## Trade-offs

- **Compor > reinventar** (ADR-0006): ganho de segurança/manutenção; custo de orquestrar dependências externas (mitigado por isolamento e pin de versão).
- **Container** acopla a Docker mas dá portabilidade real (inclusive fora do GitHub).
- **Fix determinístico antes de IA**: menos "mágica", mais confiança; a IA cobre a cauda.
