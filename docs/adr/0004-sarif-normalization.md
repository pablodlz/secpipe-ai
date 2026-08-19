# ADR-0004 — Contrato normalizado SARIF + CWE

**Status:** Aceito (Fase 0).

## Contexto
A interface do sistema é a IA. Cada tool tem formato próprio; a IA precisa de UM schema estável para raciocinar e corrigir.

## Decisão
Normalizar todo achado num modelo `Finding` (id, tool, rule_id, **CWE**, severidade, file, line, message, **fingerprint** p/ dedup), serializável em **SARIF** (interop/GitHub) e **JSON** (a IA). O contrato é API pública versionada. Validado pela prática do Pixee (SARIF como entrada universal).

## Consequências
- (+) IA consome uma fonte só; interop com GitHub code scanning e DefectDojo.
- (−) Custo de escrever adapters de parsing por tool. Aceito — é o valor central.
