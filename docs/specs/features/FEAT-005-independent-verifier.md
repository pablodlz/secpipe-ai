# FEAT-005 — Verificador independente (fail-CLOSED, maioria-de-N)

> **Fase 3** · Base: `LlmJudge` do Omni (§5) **com a inversão de defesa**. É o "quem corrige não aprova":
> um segundo contexto valida o fix antes de aceitar.

## Objetivo
Um verificador **independente** de quem propôs o fix, que **veta** correções ruins (não cria confiança),
com ruído reduzido por votação e **degradando FECHADO** quando não pode rodar.

## Problema (e a inversão)
No Omni o juiz degrada **ABERTO** (provider caiu → não-veto), e o próprio código admite que uma quota
estourada virou "PASS silencioso do único gate cético". Isso é aceitável na **ofensa** (FP vai p/ humano).
Na **defesa**, aceitar um fix de segurança sem poder verificá-lo é inaceitável → **degrade FECHADO**.

## Requisitos
- **RS-01 (INVERSÃO):** verificador que **não consegue rodar** ⇒ `GateVerifier` FAIL ⇒ fix **não aceito**.
- **RF-01**: **só-veto** — nunca aprova sozinho; a linha real é teste-verde + scanner-limpo (FEAT-002).
- **RF-02**: **maioria de N amostras** (N ímpar, ex.: 3) — reduz ruído do modelo; empate ⇒ veto (fail-closed).
- **RF-03**: **handoff compacto** — resumo estruturado (finding + diff + resultado do teste/scanner), nunca o repo inteiro.
- **RF-04**: **tier-routing** — modelo forte só para severidade alta / mudança sensível (controle de custo).
- **RS-02**: **redaction** — sem segredo/PII no prompt do verificador.

## Design
```python
class VerifierPort(Protocol):
    def verify(self, finding: Finding, patch: str, evidence: VerifyEvidence) -> VerifierVerdict: ...
@dataclass(frozen=True)
class VerifierVerdict: vetoed: bool; reason: str; judged: int; samples: int; degraded: bool
```
- `VerifyEvidence` = {scanner re-scan resultado, teste de regressão resultado, diff resumido}.
- Amostra N vezes; `vetoed` por **maioria estrita**; **empate ⇒ veto** (≠ Omni, que dá não-veto — aqui
  invertido porque falso-negativo em defesa é pior).
- **Ambiguidade genuína** (modelo respondeu, mas incerto) ⇒ deferir ao núcleo determinístico (aceita SÓ se
  teste-verde + scanner-limpo). **Falha de infra** (não respondeu) ⇒ `degraded=True` ⇒ FAIL-CLOSED.
- Ledger append-only de cada veredito (auditoria).

## Segurança / guardrails
- É a materialização do **Patch Validation** da literatura (+15pp) e do "quem corrige não aprova".
- Fail-closed na infra; deferir-ao-determinístico na ambiguidade — dois casos distintos, tratados distinto.

## Critérios de aceite
- Provider indisponível ⇒ fix NÃO aceito (fail-closed).
- Fix que passa teste+scanner mas o verificador identifica como inseguro ⇒ vetado.
- Empate de votos ⇒ veto.

## Estratégia de testes
- Mock provider: sempre-veta / nunca-veta / erro / ambíguo / empate → asserts no verdict.
- Verificar que segredo do diff é redigido antes do prompt.

## Pontos em aberto
- N ideal e critério de tier-routing (severidade? categoria?). *[HIPÓTESE: N=3; forte p/ HIGH+ e categorias sensíveis]*
- O verificador é outro provedor, outra instância do mesmo, ou determinístico+modelo? *[HIPÓTESE: híbrido]*
