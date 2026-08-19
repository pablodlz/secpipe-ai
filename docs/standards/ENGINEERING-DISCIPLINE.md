# Engineering Discipline — secpipe

> Disciplina transversal destilada do Omni-Pentest (§10 do doc 07), **enxuta** (sem o peso dele).
> Aplica-se ao desenvolvimento do próprio secpipe (dogfooding).

## 1. Imposição estrutural, não "enforcement theater"
O Omni documenta que **self-check por turno degradou** as gerações anteriores. Regra: a imposição é
**estrutural** (gate/hook/CI cabeado), **nunca** a IA se auto-policiando ("segui as regras?"). Se algo
precisa ser garantido, vira um **gate**, não uma exortação. (É a base do "agent-independent" do ADR-0007.)

## 2. Anti-drift (RAD): substituir, não acumular
Capacidade nova entra **por contrato** e **remove** o que substitui. Nada de "deixa o antigo do lado".
Adapters/scanners mortos são removidos, não deixados. Um scanner trocado sai do registro.

## 3. Dono único de um fato ("um cálculo, um dono")
Cada fato é calculado em **um** lugar: o `fingerprint` (contrato), a `severity` (FEAT-004), o veredito
(FEAT-002), a política (motor referenciado). Ninguém recomputa o que outro já é dono — evita duas
respostas divergentes para a mesma pergunta (o Omni sangrou nisso; ver ValidationService §29).

## 4. Doc-sync forçado
Toda mudança propaga aos artefatos derivados (README, contrato/SARIF `schema_version`, `VERSION`, specs).
O **contrato de achados é API pública** — mudá-lo é mudança versionada. Idealmente **forçado por hook**
de pre-commit (dogfooding), não dependente de lembrar.

## 5. Config/paths por resolvedor único, zero path absoluto
Toda config/caminho passa por `foundation/config` (precedência explícita env > default). **Nenhum path
absoluto** no código. Já é o desenho da fundação.

## 6. Fail-closed é o default de tudo
Na dúvida, **bloquear/rejeitar/escalar** — nunca "deixar passar". Vale para o gate (FEAT-002), o
verificador (FEAT-005) e o loop (FEAT-008). O caminho seguro é o caminho padrão.

## 7. A mensagem do gate não é receita de evasão
O feedback acionável (FEAT-002) diz **como corrigir de verdade**, jamais **como silenciar**. O Omni
provou o risco: um guard chegou a "ensinar" o próprio bypass (SCOPE-SELFGRANT). Toda mensagem de
rejeição é auditada contra isso.

## 8. Calibrar com evidência, não com opinião
Regras anti-FP (FEAT-003), limiares e severidades são **medidos** contra um corpus rotulado — uma regra
que acerta 0/2 é removida, não mantida por intuição. (Herança direta da cultura do Omni.)
