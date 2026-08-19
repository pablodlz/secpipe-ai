# ADR-0010 — Orquestração própria (enxuta), ASH como adapter opcional (não base)

**Status:** Aceito (Fase 1).

## Contexto
O ADR-0006 mandou compor, não reinventar. A dúvida da Fase 1 (roadmap): usar o **ASH** (AWS Automated
Security Helper) como **orquestrador de base** vs. orquestração própria. Já implementamos um orquestrador
próprio enxuto (`Orchestrator` + `ScannerPort`), testado e **cross-platform**, com 5 scanners reais.

## Decisão
Manter a **orquestração própria** como base — ela é pequena, testada, cross-platform (Windows/Linux) e nos
dá controle direto sobre o **contrato normalizado**, o **gate** e a **dedup** (o nosso valor, ADR-0004/0008).
O **ASH** entra, quando fizer sentido, como **um `ScannerPort` "meta" opcional** (envolvendo o ASH como
mais um scanner entre outros), **não** como o núcleo. Isso preserva o ADR-0006 (compor) sem acoplar o
motor a um orquestrador externo mais pesado e Linux-cêntrico (o ASH isola tools via UV).

## Alternativas
- **ASH como base:** menos código de orquestração, mas: mais pesado, foco Linux, e a normalização/gate/
  contrato — o nosso diferencial — ficariam presos ao formato do ASH. Perderíamos o cross-platform e o controle.

## Consequências
- (+) Motor leve, cross-platform, dono do contrato; ASH continua reutilizável como adapter futuro.
- (−) Escrevemos o loop de orquestração (já feito, ~1 arquivo). Aceito — é o núcleo do produto.
