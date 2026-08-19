# 05 — Roadmap & Open Questions

> Operador = IA. Meta = melhor opção free do mercado, compondo best-of-breed. Nada aqui é implementado na Fase 0.
>
> **Estado (2026-08-19):** núcleo completo — Fases 0–3 + servidor MCP. `main` **protegida** (`enforce_admins`):
> daqui em diante, mudanças entram por **PR** com checks obrigatórios. Próximo: **Fase 4** (integrar aos projetos).

## Fases

| Fase | Entrega | Portões |
| --- | --- | --- |
| **0 — Foundation** ✅ | estrutura, specs, ADRs, contrato, política, CLI, prior-art | concluída |
| **1 — Motor de scan** ✅ | 5 scanners (gitleaks/Semgrep/Trivy/Bandit/pip-audit) + SARIF + dedup + reporter | concluída (dogfood real, CI verde, imagem pública) |
| **2 — Gate + adoção** ✅ | `secpipe init` (detecção de linguagem → .secpipe.yml + AGENTS.md + hook + workflow) + `secpipe hook` | concluída (imposição agent-independent; supply-chain ativo) |
| **3 — Auto-fix (DRV)** ✅ | **KEYLESS** (operador = IA): `secpipe fix` (Codemodder) → agente corrige → `secpipe verify` (juiz determinístico) + abstention + memória | concluída; ciclo DRV real demonstrado. Auto-fix por IA embutido = modo headless opcional (futuro) |
| **4 — Integração** *(atual)* | aplicar aos projetos (bots/Clavis) e, opcional, Omni; exportar DefectDojo | por-projeto |

## Specs detalhadas das Fases 2-3 (prontas)

As estratégias das próximas fases já estão especificadas em detalhe em
[`features/`](features/) (FEAT-001..010) — contrato, firewall, anti-FP, severidade, verificador,
abstração de IA, grounding, loop de auto-fix, memória de fixes e adoção. Ver também
[`../standards/ENGINEERING-DISCIPLINE.md`](../standards/ENGINEERING-DISCIPLINE.md).

## Próximos passos imediatos (Fase 1)

- [x] Implementar `ScannerPort` reais (gitleaks + Semgrep + Trivy) com parsing p/ o contrato.
- [x] Adicionar **Bandit** (SAST Python) e **pip-audit** (SCA Python) como adapters.
- [x] `ReporterPort` SARIF + JSON, com **dedup por fingerprint**.
- [x] Execução segura e cross-platform (Windows/Linux): subprocess sem shell, path resolvido, UTF-8.
- [x] **Dogfood real:** gitleaks + trivy + bandit executados de verdade sobre `src`; gate PASS.
- [x] Gate de qualidade verde no próprio código (ruff + mypy strict + bandit + 22 testes).
- [x] **Setup reproduzível na raiz**: `install.py` (+ `setup.sh`/`setup.ps1`) cria venv, instala deps e baixa scanners.
- [x] **Publicar imagem**: workflow `publish-image.yml` (dispara em tag `vX.Y.Z`; o CI faz o build, sem Docker local).
- [x] **ASH**: decidido no [ADR-0010](../adr/0010-orchestration-own-not-ash.md) — orquestração própria; ASH como adapter opcional.
- [x] **Imagem pública** em `ghcr.io/pablodlz/secpipe-ai:0.1.0` (+ `:latest`); CI verde.
- [x] **Supply-chain**: actions pinadas por SHA + `scorecard.yml` dedicado + gitleaks/Harden-Runner no CI.
- [x] **Branch protection** ativa em `main` (fluxo por PR: checks obrigatórios, sem force-push/deleção). Loosen via `scripts/setup_github_hardening.sh`/painel.

> **Nota Windows:** `semgrep` não roda nativamente no Windows (limitação do próprio tool) — no Windows
> ele fica `skipped`; roda no **container Linux** e no **CI**. gitleaks/trivy/bandit/pip-audit rodam nos dois.

## Pontos em aberto

### Composição / motor
- **ASH como base** de orquestração (reusar) vs. orquestrar direto os scanners? *[EM ABERTO — provável: ASH como um `ScannerPort` "meta" + scanners diretos onde precisar de controle fino]*
- Usar **Codemodder** como engine de fix determinístico (reusar) vs. próprio? *[HIPÓTESE: reusar Codemodder]*
- Exportar para **DefectDojo** ou manter só o contrato JSON/SARIF? *[HIPÓTESE: contrato primeiro; DefectDojo opcional]*

### Guardrails / auto-fix
- Como ancorar tecnicamente a **política referenciada** para a IA do projeto não editá-la (CODEOWNERS + check de CI que compara com a versão do motor)? *[EM ABERTO — crítico]*
- O **verificador independente** é determinístico, 2º modelo, ou híbrido? *[HIPÓTESE: híbrido]*
- Matriz de **autonomia por categoria** (auto-fix vs. escalar)? *[EM ABERTO — default: escalar auth/cripto/dinheiro/severidade alta]*

### Compatibilidade
- Conjunto mínimo de scanners multi-linguagem para "qualquer projeto" (cobertura vs. custo/tempo)? *[EM ABERTO]*
- Quais shims de agente gerar por padrão (AGENTS.md + quais)? *[HIPÓTESE: AGENTS.md sempre; shims sob flag]*

### Custo / limites
- Como lidar com a limitação do **Semgrep CE** (arquivo único, ~44–48% detecção)? *[HIPÓTESE: combinar com Bandit/ASH; documentar honestamente]*
- Orçamento de IA por execução no auto-fix? *[EM ABERTO]*

## Hipóteses (a validar)

- **H1**: compor ASH + Codemodder + Scorecard/Harden-Runner cobre 80% com custo zero; nosso valor é a cola + o loop DRV + os guardrails.
- **H2**: imposição por git hook + CI é suficiente para ser agent-independent (não precisa de hook específico de agente).
- **H3**: o contrato SARIF+CWE basta como interface única para qualquer IA corrigir.

## Débito consciente

- Nenhum ainda. Solução temporária futura registra aqui: risco, prazo, plano de substituição.
