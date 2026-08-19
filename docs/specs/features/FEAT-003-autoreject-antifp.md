# FEAT-003 — AutoReject anti-falso-positivo (regras no motor)

> **Fase 2** · Base: `AutoReject` do Omni (§3). Resolve o **maior problema prático** do secpipe:
> ruído de falso-positivo (Semgrep CE sozinho gera muito). Corta o FP **antes** de a IA gastar fix.

## Objetivo
Um motor de regras determinístico que marca achados **conhecidamente benignos** como `filtered` **antes**
do firewall (FEAT-002), encodando conhecimento anti-FP — mas de forma que a IA do projeto **não possa**
usá-lo para silenciar bugs reais.

## Problema
Scanners geram FP (código de teste, exemplo/mock, dependência vendorizada, padrão client-side por design).
Sem pré-filtro, a IA "corrige" não-bug (desperdício) ou fica ruidosa. Mas uma allowlist de FP é
**exatamente a superfície de gaming** — se a IA edita, ela silencia o que quiser.

## Requisitos
- **RF-01**: regras com predicados (por `rule_id`, `cwe`, path glob, `finding_type`, metadata).
- **RF-02**: match → `filtered` com o **id da regra** (auditável).
- **RS-01**: **as regras moram no motor referenciado/versionado (dono humano)** — a IA do projeto **não** as edita (a régua não é escrita por quem ela gateia). Consumidor pode *propor* via PR revisado, nunca alterar localmente sem bump.
- **RS-02**: default embutido (sem dependência de arquivo); toda regra é auditada em review.

## Design
```python
@dataclass(frozen=True)
class FPRule: id: str; predicate: Mapping[str, Any]; rationale: str
class AutoRejectPolicy:
    def check(self, finding: Finding) -> str | None: ...  # id da 1ª regra que casa, ou None
```
**Predicados** (AND): `cwe`, `rule_id`, `path_glob` (ex.: `**/test/**`, `**/vendor/**`, `**/examples/**`),
`in_generated_file`, `metadata_missing`.

**Regras-semente candidatas (código):**
- FP em **arquivo de teste/fixture** (path glob) — a menos que o próprio teste seja o alvo.
- **Dependência vendorizada / gerada** (não é código do projeto).
- **Segredo de exemplo** (`example`, `dummy`, `changeme`, placeholders) — mas gitleaks real fica.
- **Padrão client-side por design** (chaves públicas de RUM/analytics — herda a lista do Omni).
- **Código de exemplo/doc** (path `**/examples/**`, `**/docs/**`).
⚠️ Cada regra precisa de `rationale` e é **calibrada com evidência** (o Omni mede: uma regra que acerta
0/2 é removida). Nada de allowlist por chute.

## Segurança / guardrails
- **A trava central:** allowlist no engine, versionada, revisada. Isso é a **síntese** AutoReject(Omni) +
  anti-self-gaming(nosso) — o pré-filtro que corta ruído **sem** virar botão de silêncio da IA.
- `GateNoSuppression` (FEAT-002) complementa: mesmo que uma regra nova entre, o diff não pode silenciar.

## Critérios de aceite
- FP em `**/test/**` é filtrado; o MESMO padrão em código de produção **não** é.
- Nenhuma regra editável pela IA do projeto derruba um achado real.
- Toda regra tem rationale e (quando aplicável) medição.

## Estratégia de testes
- Corpus rotulado (benigno × real) → precisão/recall da regra (herda a disciplina do Omni).
- Teste de que a config do consumidor **não** consegue desabilitar uma regra localmente.

## Pontos em aberto
- Conjunto inicial de regras e seus path globs por linguagem. *[EM ABERTO — calibrar com corpus]*
- Formato de "propor regra" pelo consumidor (PR ao engine)? *[HIPÓTESE: sim]*
