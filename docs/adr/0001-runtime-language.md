# ADR-0001 — Runtime do CLI: Python (alvo agnóstico)

**Status:** Aceito (Fase 0).

## Contexto
O `secpipe` orquestra ferramentas externas (Semgrep, Trivy, gitleaks…) e consome/emite SARIF/JSON. O consumidor pode ser de QUALQUER linguagem.

## Decisão
CLI do motor em **Python 3.11+** (rico em SARIF/JSON, subprocess seguro, ecossistema de segurança). O consumidor **não** precisa de Python: o motor roda como **container** (ADR-0002). Python é detalhe do orquestrador, não requisito do alvo.

## Alternativas
- **Go** (binário único): forte candidato; reavaliável se o container não bastar para distribuição.

## Consequências
- (+) Iteração rápida, integra tools free, consistência com os demais projetos.
- (−) Sem container exigiria Python no host. **Mitigação:** distribuição primária é container.
