# Feature Specs — secpipe

> Specs detalhadas (blueprints de implementação) das estratégias do secpipe, muitas destiladas do
> Omni-Pentest com as **inversões de defesa** aplicadas (ver [`../07-strategies-from-omni-pentest.md`](../07-strategies-from-omni-pentest.md)).
> Cada spec é a fonte de verdade da sua feature. **Nada aqui está implementado** — é o plano da Fase 1-4.

| Spec | Feature | Fase | Base (Omni) |
| --- | --- | --- | --- |
| [FEAT-001](FEAT-001-finding-contract.md) | Contrato de achado normalizado (SARIF+CWE, machine-first) | 1 | ConfidenceScorer §2 |
| [FEAT-002](FEAT-002-validation-firewall.md) | Firewall de validação (recompute > declarado, default-deny) | 2 | ValidationService §1 |
| [FEAT-003](FEAT-003-autoreject-antifp.md) | AutoReject anti-falso-positivo (regras no motor) | 2 | AutoReject §3 |
| [FEAT-004](FEAT-004-severity-derivation.md) | Severidade derivada da evidência (⊥ gate) | 1-2 | SeverityDeriver §4 |
| [FEAT-005](FEAT-005-independent-verifier.md) | Verificador independente (fail-CLOSED, maioria-de-N) | 3 | LlmJudge §5 |
| [FEAT-006](FEAT-006-ai-provider-abstraction.md) | Abstração de IA + fallback multi-provedor | 3 | MultiProvider §6 |
| [FEAT-007](FEAT-007-knowledge-grounding.md) | Grounding de conhecimento + RAG corretivo | 3 | KnowledgeGate/CorrectiveRAG §7 |
| [FEAT-008](FEAT-008-autofix-loop-drv.md) | Loop de auto-fix DRV (escada limitada + abstention) | 3 | RehypothesisEngine §8 |
| [FEAT-009](FEAT-009-fix-memory.md) | Memória de fixes verificados (compõe entre projetos) | 3-4 | LESSON_RECALL/MOVE_LIBRARY §9 |
| [FEAT-010](FEAT-010-adoption-and-agent-context.md) | Adoção (`secpipe init`) + contexto de agente | 2 | — |

Disciplina de engenharia transversal: [`../../standards/ENGINEERING-DISCIPLINE.md`](../../standards/ENGINEERING-DISCIPLINE.md).

## Como estas specs se encaixam

```text
FEAT-001 (contrato)  ──alimenta──▶  FEAT-002 (firewall/gate)  ──decide──▶  bloquear/aceitar
     ▲                                     ▲                                      │
FEAT-004 (severidade)              FEAT-003 (anti-FP)                             ▼
                                                                     FEAT-008 (loop de fix DRV)
                                                          ┌───────────────┼───────────────┐
                                                   FEAT-007 (grounding) FEAT-005 (verificador) FEAT-006 (IA)
                                                                          │
                                                                   FEAT-009 (memória)
FEAT-010 (adoção) instala tudo num projeto consumidor, com imposição agent-independent.
```
