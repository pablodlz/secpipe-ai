# FEAT-008 — Loop de auto-fix DRV (escada limitada + abstention)

> **Fase 3** · Base: `RehypothesisEngine` do Omni (§8) **com as inversões de defesa**. É a **orquestração**
> que amarra FEAT-002/005/006/007: achar → corrigir → **verificar**, com escalonamento honesto.

## Objetivo
Para cada achado bloqueante, tentar corrigir subindo uma **escada** de estratégias (barato→caro), cada
tentativa **verificada**, com **limite** de custo/iterações e **abstention** (escalar ao humano) — nada
pendente da pessoa **exceto** o que a política manda escalar.

## Problema
Um "LLM corrige tudo" ingênuo: (a) não converge (retenta cego), (b) aceita fix inseguro (sem verificação),
(c) nunca para (custo) **ou** desiste cedo demais. A escada + verificação + terminação resolvem os quatro.

## Requisitos (Detect → Repair → Verify)
- **RF-01 (escada, barato→caro):** para cada finding:
  1. **fix determinístico** (codemod, ex.: Codemodder) se `remediation.autofixable`;
  2. **fix por template** (padrão conhecido do CWE, FEAT-007);
  3. **fix por IA** (FEAT-006), fundamentado (FEAT-007).
- **RF-02 (verificar cada tentativa):** roda o firewall de aceitação (FEAT-002) — scanner-limpo + teste de
  regressão + suíte verde + verificador (FEAT-005). Só `ACCEPT` fecha o finding.
- **RF-03 (corretivo):** tentativa que falha ⇒ **query corretiva** (FEAT-007), não retenta idêntico;
  dedup de tentativas por **fingerprint**.
- **RS-01 (INVERSÃO — limite):** **orçamento + máx. de iterações** por finding; ao esgotar a escada sem
  ACCEPT ⇒ **ESCALATE** (não retenta infinito). "Esgotado" é propriedade da **estratégia**, não desistência precoce.
- **RS-02 (INVERSÃO — terminação/abstention):** categorias **sempre escaladas** (auth/authz, cripto,
  caminho de dinheiro, severidade **crítica**, e qualquer mudança de política). Este é o único "pendente de humano".
- **RS-03 (fail-closed):** se a verificação não pode rodar (scanner/verificador indisponível) ⇒ não aceita ⇒ ESCALATE.

## Design
```python
class FixLoop:
    def resolve(self, finding: Finding, budget: Budget) -> FixOutcome: ...
# FixOutcome ∈ {FIXED(patch), ESCALATED(reason), EXHAUSTED(reason)}
```
Escada como no Omni (spiral que não repete), mas **com degrau terminal**: `deterministic → template →
ai(+corretivo até k) → widen(buscar padrão novo, FEAT-007) → ESCALATE`. Dedup de tentativas por
fingerprint. Todo passo é auditado (achado→tentativa→veredito).

## Segurança / guardrails (as inversões do §0 do doc 07)
- **Degrade FECHADO** (RS-03) — herança invertida do LlmJudge.
- **Termina** (RS-01/02) — herança invertida do Modo Profundo (que nunca termina).
- Nenhum fix aceito sem verificação independente + teste (não silêncio do scanner).

## Critérios de aceite
- Fix determinístico disponível é tentado **antes** do de IA.
- Achado de categoria sensível ⇒ ESCALATE sem tentar auto-fix arriscado.
- Orçamento esgotado ⇒ ESCALATE (nunca loop infinito).
- Tentativa falha ⇒ próxima é diferente (corretivo + dedup).

## Estratégia de testes
- Simular: codemod resolve (FIXED na etapa 1); IA resolve após corretivo; categoria sensível (ESCALATE); orçamento estoura (ESCALATE); verificador indisponível (ESCALATE/fail-closed).

## Pontos em aberto
- Valores default de orçamento/iterações (plug-and-play forte, ADR-0009). *[EM ABERTO]*
- Aplicar fix em branch/PR sempre (auto-PR) e auto-merge só de baixo risco? *[HIPÓTESE: sim — auto-PR sempre; merge tiered]*
