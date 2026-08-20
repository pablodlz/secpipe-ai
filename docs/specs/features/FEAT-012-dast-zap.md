# FEAT-012 — DAST (OWASP ZAP baseline)

> **Fase 4** · Status: implementado. Análise **dinâmica**, gratuita e keyless, **opt-in**. Tira o DAST do
> "roadmap/fase futura" (ADR-0003) e o torna real, sem quebrar o plug-and-play estático.

## Objetivo
Cobrir a dimensão que faltava (dinâmica) reusando o **mesmo contrato e o mesmo gate**: rodar o **ZAP baseline**
contra um app no ar, normalizar os alertas em `Finding` (com `cwe`/severidade) e reprovar o build em HIGH+.

## Problema
DAST precisa de um **app rodando** (deploy + spider + ataque leve) — não encaixa no modelo estático/CI-time
por padrão. Se fosse ligado sempre, quebraria o "baixou e funciona". Solução: **opt-in** — só roda com uma
URL alvo definida e um runner ZAP presente; caso contrário, **SKIP** (o estático segue intacto).

## Requisitos
- **RF-01**: adapter `ZapDastScanner` implementa `ScannerPort` (mesmo padrão dos demais).
- **RF-02**: **opt-in** por `dast.target_url` no `.secpipe.yml`; sem URL → SKIPPED. Runner ausente → SKIPPED.
  URL definida mas ZAP falhou → **ERROR** (fail-closed: pediu DAST e não rodou).
- **RF-03**: normaliza o relatório JSON do ZAP em `Finding` (`cweid`→`cwe`, `riskcode`→severidade).
- **RF-04**: dois caminhos: **local/live** (`secpipe scan` com `dast` nos scanners, via docker/zap-baseline.py)
  e **CI** (workflow reusável `secpipe-dast.reusable.yml`: o ZAP roda como container, `secpipe dast-import`
  normaliza + aplica o gate).
- **RS-01**: **grátis e keyless** — ZAP é OSS; nenhuma chave. A imagem do ZAP **não** é embutida na do secpipe
  (é grande): roda-se o container oficial do ZAP.
- **RS-02**: execução segura (via `run_tool`: sem shell, args em lista, timeout).

## Design
- `adapters/dast_zap.py` — `parse_zap_report()` (parser puro, testável), `ZapDastScanner` (opt-in), `_run_zap()`
  (docker preferido; CLI nativo como fallback, com `cwd` no `run_tool`).
- `foundation/config.py` — `dast_target` (aceita `dast: {target_url}` ou `dast_target:`).
- `composition_root` — registra `dast` e injeta a URL da config.
- `cli.py` — `secpipe dast-import <report.json>` (ponte de CI: normaliza + gate).
- `.github/workflows/secpipe-dast.reusable.yml` — job DAST opt-in (ZAP container → `dast-import`).
- `init` — seção `dast` comentada no `.secpipe.yml` + apontamento pro workflow.

## Severidade (ZAP riskcode → secpipe)
| riskcode | ZAP | secpipe |
| --- | --- | --- |
| 3 | High | HIGH |
| 2 | Medium | MEDIUM |
| 1 | Low | LOW |
| 0 | Informational | INFO |

ZAP não tem "critical"; High é o topo. `cweid = -1` (sem CWE) → `cwe` vazio.

## Evolução (futuro)
- ZAP **full scan** (ativo) opt-in além do baseline; autenticação/contexto (login) para áreas logadas.
- SARIF direto do ZAP para o code scanning; correlação DAST↔SAST (mesmo CWE/rota).
- Outros DAST livres (Nuclei) como adapters alternativos por dimensão (evita lock-in — RK-04).
