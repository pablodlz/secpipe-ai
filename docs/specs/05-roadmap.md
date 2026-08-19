# 05 — Roadmap & Open Questions

> Operador = IA. Meta = melhor opção free do mercado, compondo best-of-breed. Nada aqui é implementado na Fase 0.

## Fases

| Fase | Entrega | Portões |
| --- | --- | --- |
| **0 — Foundation** ✅ | estrutura, specs, ADRs, contrato, política, CLI, prior-art | concluída |
| **1 — Motor de scan** *(atual)* | 5 scanners (gitleaks/Semgrep/Trivy/Bandit/pip-audit) + SARIF + dedup + reporter | ✅ execução real (dogfood) + gate verde; falta empacotar a imagem |
| **2 — Gate + adoção** | política fail-closed; `secpipe init` (AGENTS.md + hooks + workflow); supply-chain (Scorecard/Harden-Runner/Secure-Repo) | imposição agent-independent |
| **3 — Auto-fix (DRV)** | fix determinístico (Codemodder) → fix IA (provider-agnostic) → **verificador independente** + abstention | fix só com teste+verificação |
| **4 — Integração** | aplicar aos projetos (bots/Clavis) e, opcional, Omni; exportar DefectDojo | por-projeto |

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
- [~] **Branch protection**: `scripts/setup_github_hardening.sh` pronto (acionar ao migrar p/ PR — não ativado agora p/ não bloquear push direto). Scorecard/Harden-Runner já rodam no CI.

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
