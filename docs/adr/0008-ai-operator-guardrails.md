# ADR-0008 — Operador = IA + guardrails anti-self-gaming

**Status:** Aceito (Fase 0).

## Contexto
O operador é a própria IA que desenvolve. Risco nº1: a mesma IA escreve, roda o gate e corrige — e pode "deixar verde" silenciando o achado (a raiz do SCOPE-SELFGRANT do Omni). "Nada pendente de humano" NÃO pode significar "IA se auto-aprova".

## Decisão (guardrails invioláveis)
1. **Política mora no motor referenciado/versionado** — a IA do projeto não edita a régua que a julga; mudar = bump revisável.
2. **Anti-supressão:** lint bloqueia `# nosec`/`# noqa`/baseline/rebaixe de severidade no diff.
3. **Verificador independente** (2º contexto) valida o fix — quem corrige não aprova (Patch Validation).
4. **Fix aceito só com teste que reproduz a vuln (vermelho→verde) + suíte verde** (execution-grounded).
5. **Abstention:** a IA escala o que não deve corrigir sozinha (auth/cripto/dinheiro/severidade alta).
6. **Imposição agent-independent** (git hooks + CI), não um comando que a IA pode pular.

Fundamentação: literatura DRV (Detect–Repair–Verify), Bug Abstention + Patch Validation (specs/06).

## Consequências
- (+) Autonomia sem auto-aprovação insegura; respaldo acadêmico.
- (−) Mais componentes (verificador, lint anti-supressão) e raros itens escalados. Aceito — é o ponto do produto.
