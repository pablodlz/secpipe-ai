# FEAT-009 — Memória de fixes verificados (compõe entre projetos)

> **Fase 3-4** · Base: `LESSON_RECALL` + `MOVE_LIBRARY` do Omni (§9, Reflexion).
> **REORIENTADO (keyless):** o **substrato local** (`secpipe remember`/`recall`, store JSON) está
> **implementado** — o agente registra o PADRÃO de um fix verificado e recupera por CWE. A **composição
> ENTRE projetos/tenants** (o diferencial de auto-aprendizado compartilhado) é da **camada SaaS/compartilhada
> (futuro)**, não do CLI local.

## Objetivo
Acumular fixes que **passaram na verificação independente** e recuperá-los como candidatos para achados
similares — de modo que o secpipe fique melhor a cada correção, em todos os projetos que o usam.

## Problema
Sem memória, a IA re-resolve o mesmo CWE do zero toda vez (custo, variância). Com memória mal-curada,
propaga um fix ruim. A trava: só entra o que foi **verificado**.

## Requisitos
- **RF-01**: registrar um fix **apenas** quando `FixVerdict == ACCEPT` (FEAT-002) — teste-verde + verificador OK.
- **RF-02**: chave de recuperação por `(cwe, stack, rule_id)`; recuperar como **candidato** (não aplicar cego).
- **RF-03**: candidato recuperado ainda passa pela escada+verificação (FEAT-008) — memória **propõe**, firewall dispõe.
- **RS-01 (privacidade/tenant):** armazenar **o padrão/transformação generalizada**, **não** o código
  literal do projeto — evita vazar código de um projeto para outro. Segredos/PII nunca entram.
- **RS-02**: uma "lição" pode ser **revogada** se um fix baseado nela depois falhar/regredir (feedback negativo).

## Design
```python
@dataclass(frozen=True)
class VerifiedFix: cwe: str; stack: str; rule_id: str; pattern: str; references: tuple[str,...]
class FixMemoryPort(Protocol):
    def record(self, vf: VerifiedFix) -> None: ...          # só após ACCEPT
    def recall(self, cwe: str, stack: str) -> list[VerifiedFix]: ...
```
- `pattern` = a **transformação** ("substituir concatenação SQL por query parametrizada"), não o diff bruto.
- Escopo de compartilhamento configurável: **por-org** (default seguro) ou público (curado) — decisão de privacidade.

## Segurança / guardrails
- **Só fix verificado entra** — o mesmo rigor da §1; uma lição ruim seria um fix ruim propagado.
- **Generalizar, não copiar** — a memória compartilhada não pode virar canal de vazamento de código entre projetos/tenants.

## Critérios de aceite
- Fix rejeitado **não** entra na memória.
- Recall retorna candidato que ainda é verificado antes de aplicar.
- Nenhum código literal/segredo de projeto atravessa a fronteira de projeto.

## Estratégia de testes
- Record só em ACCEPT; recall por chave; revogação em regressão; ausência de dado sensível no registro.

## Pontos em aberto
- Escopo default de compartilhamento (por-org vs. público-curado)? *[HIPÓTESE: por-org por padrão]*
- Como generalizar o diff em "pattern" sem perder utilidade? *[EM ABERTO — provável: template + AST]*
