# FEAT-002 — Firewall de validação (recompute > declarado, default-deny)

> **Fase 2** · Base: `ValidationService` do Omni (§1). O **coração do guardrail**: decide, de forma
> determinística, se um achado é real e se um fix foi aceito — **nunca** confiando no que a IA declara.

## Objetivo
Um pipeline determinístico com **ordem inviolável** que produz um veredito sobre (a) validade de um
achado e (b) aceitação de um fix, **recomputando** qualquer número/rótulo declarado pela IA e falhando
fechado por padrão.

## Problema
Se a IA declara "corrigido" / "severidade baixa" / "não é bug" e o sistema confia, o operador-IA se
auto-aprova (o furo que o ADR-0008 combate). O firewall tira a caneta da IA.

## Requisitos
- **RS-01**: **Default = REJECT/KILL**; na dúvida, rejeita.
- **RS-02**: ordem inviolável: `prescreener → AutoReject(FEAT-003) → gates → verdict`.
- **RS-03**: todo valor declarado (severidade, "fixed", score) é **recomputado e sobrescrito** da evidência.
- **RS-04**: evidência não-parseável/ausente **zera** o sinal (não beneficia a IA) — anti-evasão.
- **RS-05**: o veredito é **determinístico** (mesma evidência → mesma decisão).

## Design
Dois vereditos, mesmo motor:

### A) Validade do achado (é real?)
Reaproveita FEAT-003 (AutoReject) + gates leves (ex.: `GateEvidencePresent`, `GateNotBenignPattern`).
Serve para **cortar FP** antes de gastar fix.

### B) Aceitação do fix (o loop DRV, FEAT-008)
```python
class FixVerdict(Enum): ACCEPT; REJECT; ESCALATE
# gates de aceitação (todos PASS obrigatório):
#  GateScannerClean       — o scanner NÃO acusa mais o finding (evidência, não palavra da IA)
#  GateRegressionTest     — existe teste que reproduz a vuln (vermelho→verde) e passa
#  GateSuiteGreen         — a suíte funcional continua passando (sem regressão)
#  GateNoSuppression      — o diff não adiciona # nosec/# noqa/baseline/rebaixe de severidade
#  GateNoNewFindings      — o fix não introduziu achado novo (re-scan diferencial)
#  GateVerifier           — verificador independente não vetou (FEAT-005), FAIL-CLOSED se não rodou
```
`verdict = ACCEPT` só com **todos PASS**; qualquer gate crítico falho → `REJECT`; categoria sensível
(auth/cripto/dinheiro/critical) → `ESCALATE` (abstention, FEAT-008).

### Feedback acionável (o "silent-death fix" — §2)
Quando rejeita, o resultado **lista exatamente qual gate falhou e como conquistá-lo** (ex.:
`GateRegressionTest: adicione um teste que reproduz CWE-89 em x.py:42`). É o que faz o loop convergir.
⚠️ O "como" ensina a **corrigir**, jamais a **silenciar**.

## Segurança / guardrails
- `GateNoSuppression` é o guardrail anti-self-gaming em forma de gate (não confia no hook só).
- A **política/limiares moram no motor referenciado** (FEAT-010), fora do alcance de edição da IA do projeto.
- Fail-closed: `GateVerifier` e `GateScannerClean` que **não conseguem rodar** ⇒ REJECT (não ACCEPT).

## Critérios de aceite
- Um fix que só silencia (adiciona `# nosec`) é **sempre** REJECT.
- Um fix sem teste de regressão é REJECT com feedback acionável.
- Veredito idêntico em execuções repetidas (determinismo).

## Estratégia de testes
- Casos: fix real (ACCEPT), fix-supressão (REJECT), fix sem teste (REJECT), scanner indisponível (REJECT/fail-closed), categoria sensível (ESCALATE).

## Pontos em aberto
- Conjunto exato de gates de validade (A) para o MVP. *[EM ABERTO]*
- `GateNoNewFindings` exige re-scan diferencial — custo/tempo aceitável? *[EM ABERTO]*
