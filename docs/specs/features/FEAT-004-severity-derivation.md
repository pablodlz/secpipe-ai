# FEAT-004 — Severidade derivada da evidência (⊥ gate)

> **Fase 1-2** · Base: `SeverityDeriver` do Omni (§4, SPEC-066), **enxuto** (sem os 70KB de CVSS/VRT).
> Severidade é **calculada** da evidência, nunca o rótulo que a IA declara.

## Objetivo
Derivar a severidade de um `Finding` de forma determinística a partir de evidência estruturada (CWE +
severidade do scanner + contexto), **ortogonal** à decisão de gate (bloquear ≠ severidade).

## Problema
Se a IA declara a severidade, ela infla/deflaciona conforme conveniência (para passar ou priorizar). O
rótulo tem que vir da evidência.

## Requisitos
- **RS-01**: severidade **derivada**, sobrescreve a declarada.
- **RS-02**: **ortogonal ao veredito** (§12 do Omni): nunca muda ACCEPT/REJECT, só o rótulo.
- **RF-01**: baseline por **CWE** (tabela CWE→severidade), ajustada por sinais estruturados.
- **RF-02**: **âncora do consumidor só rebaixa** (um projeto pode dizer "isto aqui é menos crítico"), nunca eleva — evita subestimar por conveniência.

## Design
```python
@dataclass(frozen=True)
class SeverityResult: severity: Severity; rationale: str
class SeverityDeriver:
    def derive(self, finding: Finding) -> SeverityResult: ...
```
Ordem: `baseline = CWE_TABLE[finding.cwe]` (default MEDIUM se desconhecido) → ajustes por evidência
(ex.: secret **ativo/validado** sobe; secret de exemplo já foi filtrado em FEAT-003) → `min(baseline,
scanner_severity_mapeada)`? Não — **usa o MAIOR** entre baseline-CWE e scanner (não subestimar), depois
âncora do consumidor **só rebaixa**. Determinístico e pequeno (uma tabela + regras claras).

## Segurança / guardrails
- Sem "S:C grátis": qualquer elevação exige sinal estruturado (herda a lição do Omni — a caneta sai da IA).
- A âncora do consumidor é **config no engine-contract**, e **só rebaixa** (não vira brecha de subavaliação).

## Critérios de aceite
- Mesma evidência → mesma severidade.
- Severidade declarada pela IA é ignorada.
- Âncora do consumidor rebaixa, nunca eleva.

## Estratégia de testes
- Tabela CWE coberta; casos de elevação por evidência; âncora que tenta elevar é ignorada.

## Pontos em aberto
- Fonte da tabela CWE→severidade (curada à mão vs. derivada de CVSS base)? *[HIPÓTESE: curada, enxuta]*
- Reusar o mapeamento de severidade dos próprios scanners como piso? *[EM ABERTO]*
