# FEAT-001 — Contrato de achado normalizado (SARIF + CWE)

> **Fase 1** · Status: especificado (Fase 0). Base: `ConfidenceScorer` do Omni (§2 do doc 07).
> É a **interface única** que a IA consome. Tudo depende dela → é API pública versionada.

## Objetivo
Um schema estável e **machine-first** que normaliza a saída de qualquer scanner num modelo único, com
**evidência estruturada** e **orientação acionável** (como corrigir / como conquistar aceitação), para a
IA raciocinar e corrigir sem ler formato de cada tool.

## Problema
Cada scanner tem formato próprio; a IA não pode depender de N formatos. E um achado "morto" sem dizer *o
que falta* faz a IA patinar (o "silent-death" do Omni). O contrato resolve ambos.

## Requisitos
- **RF-01**: normalizar Semgrep/Bandit/Trivy/gitleaks/… num `Finding` único (já iniciado em `domain/models.py`).
- **RF-02**: cada `Finding` carrega `cwe`, `severity`, localização, `fingerprint` (dedup determinístico).
- **RF-03**: `Finding` carrega **evidência estruturada** (não prosa) e **`remediation`** (como corrigir).
- **RF-04**: serializável em **SARIF** (interop/GitHub code scanning) e **JSON** (a IA).
- **RS-01**: a orientação é *como corrigir de verdade*, **nunca** *como silenciar* (lição SCOPE-SELFGRANT).
- **RS-02**: contrato é **versionado** (`schema_version`); mudança que quebra = major (ver DOC-SYNC).

## Design
Estende o `Finding` atual:
```python
@dataclass(frozen=True, slots=True)
class Evidence:            # estruturada, class-aware (nunca um bit que a própria IA declara)
    kind: str             # "code_span" | "dataflow" | "dependency" | "secret_match" | "test_result"
    data: Mapping[str, str]
@dataclass(frozen=True, slots=True)
class Remediation:
    how: str              # passo concreto p/ corrigir (ex.: "use parametrized query")
    autofixable: bool     # há codemod determinístico? (entra no ladder FEAT-008)
    references: tuple[str, ...] = ()   # OWASP/CWE/pattern
# Finding ganha: evidence: tuple[Evidence,...], remediation: Remediation | None
```
- **Fingerprint** (já existe): sha256 de `rule_id|cwe|file|line` → dedup entre tools (FEAT-002/003 usam).
- **SARIF**: `Finding → result`; `rule_id → rule.id`; `cwe → rule.properties.cwe`; `severity → level`;
  fingerprint → `partialFingerprints`. Ingestão reversa (SARIF→Finding) é como scanners que já emitem SARIF entram.
- **Verdict/aceitação** ficam no `ValidationResult` (FEAT-002), não no `Finding` (separação de responsabilidades).

## Segurança / guardrails
- Evidência é **objeto estruturado**, não um flag que a IA escreve (o Omni descobriu que um `diff_proves_effect`
  auto-declarado fura o gate — o medidor sempre ganha do auto-declarado).
- `remediation.how` descreve correção legítima; qualquer texto que sugira supressão é bug do contrato.

## Critérios de aceite
- Adapters de ≥2 scanners emitem `Finding` idêntico em forma.
- Round-trip `Finding ↔ SARIF` sem perda dos campos-chave.
- Dedup por fingerprint testado (já há teste base).

## Estratégia de testes
- Fixtures reais de cada scanner → parse → asserts de campos.
- Property test: fingerprint estável e colisão só quando esperado.
- SARIF validado contra o schema OASIS.

## Pontos em aberto
- Mapear severidade de cada tool → nossa escala (tabela por tool). *[EM ABERTO]*
- Guardar `dataflow` (source→sink) do Semgrep para dar contexto ao fix? *[HIPÓTESE: sim, ajuda o auto-fix]*
