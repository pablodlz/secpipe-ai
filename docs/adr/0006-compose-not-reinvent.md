# ADR-0006 — Compor best-of-breed, não reinventar

**Status:** Aceito (Fase 0).

## Contexto
O levantamento (specs/06) mostrou muito free já resolvido: orquestração (ASH/MegaLinter), normalização (DefectDojo), remediação (Pixee/Codemodder), supply-chain (Scorecard/Harden-Runner/Secure-Repo). Reinventar = mais esforço e MENOS segurança.

## Decisão
**Compor** o melhor de cada projeto free e adicionar a nossa camada de valor (contrato p/ IA + loop DRV + guardrails + adoção agent-independent). Construir do zero só o que não existe grátis+integrado+self-hosted.

## Consequências
- (+) Mais segurança, menos manutenção, custo zero; foco no diferencial real.
- (−) Dependência de projetos externos (mitigado por abstração `ScannerPort`/`FixerPort`, isolamento e pin de versão).
