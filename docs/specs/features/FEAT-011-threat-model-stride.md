# FEAT-011 — Threat model STRIDE do app (keyless, determinístico)

> **Fase 4** · Status: implementado. Complementa o threat model do *pipeline* (`docs/specs/03-security.md`):
> aqui o alvo é o **app do consumidor**. Comando `secpipe threat-model` + tool MCP `secpipe_threat_model`.

## Objetivo
Dar a todo adotante um **threat model STRIDE do próprio app** sem chave de IA e sem serviço externo: o motor
faz o trabalho **objetivo e auditável** (mapear achados reais por CWE→STRIDE + descobrir a superfície de
ataque) e entrega um **scaffold** que o agente de IA (o operador) completa.

## Problema
Threat modeling costuma ser (a) manual e caro, ou (b) uma ferramenta paga/externa. Nenhum encaixa no modelo do
secpipe (grátis, keyless, operado pela própria IA). Mas "categorizar risco por STRIDE" e "achar a superfície"
são tarefas **determinísticas** — não precisam de LLM. O que precisa de raciocínio (o *julgamento* por
categoria) é justamente o que o agente já faz bem. Então dividimos o trabalho na fronteira certa.

## Requisitos
- **RF-01**: mapa **auditável CWE→STRIDE** (dado, não mágica) + fallback por palavra-chave quando não há CWE.
- **RF-02**: **descoberta de superfície** por marcadores estáticos: entrypoints (rotas web/CLI/input),
  sinks (subprocess/eval/SQL/deserialize/file/network/template), ativos (segredos/cripto/auth).
- **RF-03**: agrupar **achados reais** (do scan) e a superfície pelas 6 categorias STRIDE.
- **RF-04**: saída em **Markdown** (agente/humano, com checklists por categoria) e **JSON** (máquina).
- **RS-01**: 100% **keyless e determinístico** no motor — nenhuma chamada de IA/serviço.
- **RS-02**: o scaffold **orienta o raciocínio** (checklists), nunca finge ser o threat model final — o agente
  completa (mesma filosofia do AGENTS.md e do "quem opera é a IA").
- **RS-03**: robusto cross-platform (saída utf-8; ignora dirs vendored; cap de arquivos/bytes).

## Design
- `domain/stride.py` — `Stride` (enum S/T/R/I/D/E) + `_CWE_STRIDE` (mapa) + `categorize(cwe, *hints)`.
- `application/use_cases/threat_model.py` — `discover_surface()` (marcadores regex), `build_threat_model()`,
  `render_markdown()` / `render_json()`; agrupamento via `ThreatModel.by_category()`.
- Entrypoints: `secpipe threat-model [target] [--format md|json]` (CLI) e `secpipe_threat_model` (MCP).
- **Não é um gate**: threat model é insumo de raciocínio, não pass/fail. O gate continua sendo o scan.

## Fronteira (o que é do motor vs. do agente)
| Determinístico (motor, keyless) | Raciocínio (agente) |
| --- | --- |
| Mapear cada achado por CWE→STRIDE | Julgar exploitabilidade/priorizar por categoria |
| Descobrir entrypoints/sinks/ativos | Confirmar trust boundaries e fluxos de dados reais |
| Montar o scaffold + checklists | Responder as checklists e propor mitigações |

## Evolução (futuro)
- Enriquecer marcadores por framework (Django/FastAPI/Express/Spring) e por linguagem.
- Ligar a superfície ao dataflow dos scanners (source→sink) para reduzir ruído.
- Exportar para formatos de threat modeling (ex.: OWASP Threat Dragon / pytm) quando fizer sentido.
