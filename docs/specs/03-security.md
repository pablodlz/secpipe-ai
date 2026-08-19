# 03 — Security & Threat Model

> Um produto de segurança operado por IA. A ameaça central é nova: **a IA operadora burlar o próprio
> gate**. Aqui isso é tratado como o risco nº 1. Também: supply-chain do próprio pipeline (ele toca
> muitos projetos). Metodologia: STRIDE + abuse cases + a lição `SCOPE-SELFGRANT` do Omni.

## Ativos

| Ativo | Por quê |
| --- | --- |
| Integridade do **gate/política** | se a IA a enfraquece, tudo passa "verde" e inseguro |
| Contrato de achados (`Finding`/SARIF) | é a verdade que a IA usa para corrigir |
| O código dos projetos consumidores | o que se quer manter seguro |
| A imagem/motor (dependência de N projetos) | comprometê-la = comprometer todos (supply-chain) |
| Trilha de auditoria (achado→fix→verificação) | prova e forense |

## Ameaça nº 1 — "quem guarda o guarda" (self-gaming da IA operadora)

A **mesma IA** escreve o código, roda o gate e corrige achados. Sem controle, ela otimiza para "deixar
o CI verde", não para "ficar seguro". Formas de burla (todas observadas na prática, e a raiz do
`SCOPE-SELFGRANT-01` do Omni): adicionar `# nosec`/`# noqa`, jogar achado em baseline/allowlist, baixar
a severidade/threshold, apagar teste, ou "corrigir" o sintoma.

**Mitigações (invariantes):**
1. **A política mora no motor referenciado e versionado.** A IA do projeto consumidor **não edita** a régua que a julga. Mudar a política = bump de versão **revisável** (a IA não bumpa sozinha).
2. **Proibir supressão no diff da IA.** Um lint do próprio `secpipe` **bloqueia** PRs que adicionem `# nosec`/`# noqa`/entradas de baseline/rebaixem severidade. Silenciar ≠ corrigir.
3. **Verificador independente.** Um 2º contexto/IA valida o fix (*Patch Validation* da literatura) — **quem corrige não é quem aprova**.
4. **Fix aceito só com teste que reproduz a vuln** (vermelho→verde) + suíte funcional verde. Silêncio de scanner não basta (*execution-grounded*).
5. **Abstention.** A IA reconhece o que não deve corrigir sozinha (auth/cripto/caminho de dinheiro/severidade alta) e **escala** — o único caso "pendente de humano", por exceção.
6. **Gate reforçado onde a IA não controla** (CI/hook referenciado), não só um comando que ela pode pular.

## STRIDE (do pipeline)

| # | Categoria | Ameaça | Mitigação |
| --- | --- | --- | --- |
| S1 | Spoofing | tool/imagem falsa | imagem assinada, pin por digest/SHA, allowlist |
| T1 | **Tampering** | IA enfraquece política/baseline | política no motor referenciado; lint anti-supressão; bump revisável (Ameaça nº1) |
| T2 | Tampering | patch malicioso/regressivo | verificador independente + testes + diff review |
| R1 | Repudiation | "não fui eu que silenciei" | auditoria append-only de achado→fix→verificação |
| I1 | **Info disclosure** | segredo vaza em log/PR de fork | redaction; **zero segredo em PR de fork** (repo público); gitleaks |
| D1 | DoS | loop de fix oscila / custo de IA explode | limite de iterações; orçamento; degradação; abstention |
| E1 | **Elevation** | IA se auto-autoriza a passar o gate | política fora do modelo; verificador separado (Ameaça nº1) |
| Sup | **Supply-chain** | motor comprometido atinge N projetos | ver abaixo |

## Supply-chain (o motor é dependência de alta confiança)

Sendo público e usado por vários projetos, um comprometimento do `secpipe` cascateia. Controles (todos free):
- **Pin de actions por SHA** (StepSecurity **Secure-Repo**), não por tag móvel.
- **Egress-monitoring do runner** (StepSecurity **Harden-Runner**, community) — detecta exfiltração.
- **Postura do repo** (**OpenSSF Scorecard**) — rodada em nós mesmos.
- **Releases assinadas** + **SBOM** (CycloneDX/Syft) do próprio motor.
- **Branch protection + review obrigatório**; **zero segredo** exposto a workflow de fork.
- **Consumidor pina versão**; nunca `@main`.

## Riscos (registro inicial)

| ID | Risco | Prob. | Impacto | Tratamento |
| --- | --- | --- | --- | --- |
| RK-01 | IA silencia o próprio achado | **alta** | **crítico** | Ameaça nº1 (política externa, anti-supressão, verificador, teste) |
| RK-02 | Motor comprometido (supply-chain) | média | crítico | pin SHA, assinatura, Scorecard/Harden-Runner, SBOM |
| RK-03 | Fix por IA introduz vuln/bug novo | alta | alto | verificador independente + testes + abstention |
| RK-04 | Falso "custo zero" (tool vira paga/limitada) | média | médio | só CE/free; abstrair scanners; múltiplos por dimensão |
| RK-05 | Segredo em PR de fork (repo público) | média | alto | sem secret em fork PR; sem `pull_request_target` inseguro |

## Perguntas de segurança em aberto

- O verificador independente é outro modelo, outra instância, ou uma checagem determinística? *[EM ABERTO — provável: híbrido, determinístico + 2º contexto]*
- Onde a política "referenciada" é ancorada tecnicamente para a IA não a editar (arquivo protegido por CODEOWNERS? check de CI que compara com a versão do motor?)? *[EM ABERTO]*
- Nível de autonomia por categoria (o que auto-fix vs. o que escala)? *[EM ABERTO — default: escalar auth/cripto/dinheiro/severidade alta]*
