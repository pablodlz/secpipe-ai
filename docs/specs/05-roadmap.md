# 05 — Roadmap & Open Questions

> Operador = IA. Meta = melhor opção free do mercado, compondo best-of-breed. Nada aqui é implementado na Fase 0.

## Fases

| Fase | Entrega | Portões |
| --- | --- | --- |
| **0 — Foundation** *(atual)* | estrutura, specs, ADRs, contrato, política, CLI esqueleto, prior-art | nada escaneia/corrige de verdade |
| **1 — Motor de scan** | compor tools free (ASH/Semgrep CE/Bandit/pip-audit/Trivy/gitleaks) + normalizar p/ SARIF + dedup | multi-linguagem; saída JSON p/ IA |
| **2 — Gate + adoção** | política fail-closed; `secpipe init` (AGENTS.md + hooks + workflow); supply-chain (Scorecard/Harden-Runner/Secure-Repo) | imposição agent-independent |
| **3 — Auto-fix (DRV)** | fix determinístico (Codemodder) → fix IA (provider-agnostic) → **verificador independente** + abstention | fix só com teste+verificação |
| **4 — Integração** | aplicar aos projetos (bots/Clavis) e, opcional, Omni; exportar DefectDojo | por-projeto |

## Próximos passos imediatos (Fase 1)

1. Empacotar o **container** do motor (imagem com CLI + tools free).
2. Implementar 2–3 `ScannerPort` reais (gitleaks + Semgrep CE + Trivy) com parsing p/ o contrato.
3. Avaliar **usar ASH como orquestrador de base** vs. orquestração própria (decisão medida).
4. `ReporterPort` SARIF + JSON, com **dedup por fingerprint**.
5. `git init` + branch protection + Scorecard/Harden-Runner/Secure-Repo no próprio repo (dogfooding).

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
