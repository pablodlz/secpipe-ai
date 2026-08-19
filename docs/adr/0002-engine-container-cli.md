# ADR-0002 — Motor = container + CLI; um motor, dois modos

**Status:** Aceito (Fase 0).

## Contexto
Precisa rodar em qualquer CI e local, servir qualquer linguagem, e ser reutilizável SEM drift, atendendo dois públicos (referenciado e template).

## Decisão
A **lógica vive num motor único** = imagem **container** (tools + CLI), versionado. Dois wrappers finos consomem o MESMO motor: **reusable workflow** (referenciado) e **use-as-template** (vendored). O que se adapta é só config + wrapper, nunca a lógica.

## Consequências
- (+) Portabilidade real (qualquer CI/local, qualquer linguagem); sem drift; dois públicos com um motor.
- (−) Manutenção da imagem. Aceito — é o que dá portabilidade e evita fork da lógica.
