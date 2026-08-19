# ADR-0009 — Plug-and-play (defaults fortes) + dogfooding

**Status:** Aceito (Fase 0).

## Contexto
Requisitos do dono: (a) praticamente **plug-and-play** — baixar, ajuste mínimo, pronto; fácil para o público — **sem** que a facilidade cape o desempenho/segurança; (b) o motor deve poder **rodar sobre si mesmo**.

## Decisão
- **Convention over configuration:** `secpipe init`/`scan` funciona com **zero config** usando **defaults seguros e fortes** (detecção de linguagem automática, conjunto de scanners recomendado, gate fail-closed). O `.secpipe.yml` é **opcional** — existe só para tunar, nunca é pré-requisito.
- **Facilidade não reduz poder:** os defaults são o modo COMPLETO recomendado, não uma versão "capada". Quem quiser, ajusta (mais scanners, severidade, autonomia) — mas o padrão já entrega segurança forte.
- **Dogfooding (self-hosting):** o próprio repositório do `secpipe` é seu **primeiro consumidor** — roda a própria esteira em si mesmo (scan + gate + supply-chain via Scorecard/Harden-Runner/Secure-Repo). É teste de credibilidade e valida o guardrail "quem guarda o guarda".

## Consequências
- (+) Adoção trivial + segurança forte por padrão; a esteira prova a si mesma.
- (−) Defaults fortes podem gerar ruído inicial em projeto legado — mitigado por `secpipe init` calibrar por linguagem e por *abstention*, nunca por baixar a régua.
