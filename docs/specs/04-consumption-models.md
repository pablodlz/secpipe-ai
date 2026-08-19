# 04 — Modelos de Adoção (Consumption Models)

> Como um projeto **aplica** o `secpipe` para que a **IA dele** desenvolva com segurança. Um só motor,
> dois modos — a escolha muda só o **wrapper**, nunca a lógica (evita drift). Ver ADR-0002.

## Princípio: referenciar, não copiar a lógica

A lógica vive no **motor versionado** (imagem container + CLI). O projeto consumidor tem apenas:
- `.secpipe.yml` (config: linguagens, paths, severidade que bloqueia, autonomia de fix);
- um **wrapper** (workflow de ~5 linhas ou stub de template);
- o **contexto de agente** instalado: `AGENTS.md` neutro (+ shims opcionais por ferramenta) + hooks.
  A **imposição** (git hooks + CI) é agent-independent — funciona com qualquer IA.

## Modo A — Referenciado (managed) — recebe updates

```yaml
# .github/workflows/security.yml no projeto consumidor
jobs:
  secpipe:
    uses: pablodlz/security-pipeline/.github/workflows/secpipe.reusable.yml@v1  # pinar tag/SHA
    with: { config: .secpipe.yml }
```
- Update do motor = bump da tag (ou seguir a major `@v1`).
- Melhor para a maioria: menos manutenção, correções de segurança propagam.

## Modo B — Template (vendored) — você é dono do bump

- `use-as-template` do GitHub copia **só o wrapper + `.secpipe.yml`** (não a lógica).
- O wrapper continua puxando a **mesma imagem versionada** (`secpipe:vX` por digest).
- Para: air-gapped, fora do GitHub, ou política de não depender de repo externo.
- **Custo:** você é dono do bump → risco de defasagem. Mitigado por `secpipe doctor` (avisa versão atrás/EOL).

## Adoção pela IA — `secpipe init` (o coração desta ideia)

Um projeto novo "aplica o secpipe" com um comando, que instala o **contexto de segurança do agente**:

```text
secpipe init
 ├── grava .secpipe.yml (defaults seguros)
 ├── instala hooks (imposição AGENT-INDEPENDENT):
 │     • pre-commit: bloqueia segredo (gitleaks) e supressão (# nosec/# noqa)
 │     • pre-push / "stop": roda secpipe scan + gate
 ├── grava AGENTS.md canônico (qualquer IA carrega ANTES de codar):
 │     • padrões secure-by-default, o que nunca fazer, como corrigir
 │     • regra: a IA NÃO edita a política nem silencia achado
 ├── (opcional) shims por ferramenta apontando p/ o AGENTS.md:
 │     • CLAUDE.md · .cursor/rules · .github/copilot-instructions.md · CONVENTIONS.md (Aider)
 └── adiciona o workflow (Modo A ou B)
```

Resultado: a IA daquele projeto **já nasce operando dentro dos guardrails** — desenvolve, escaneia,
corrige e verifica, e só escala a você o que a política manda escalar.

## Matriz de suporte por modo

| Recurso | Referenciado | Template |
| --- | --- | --- |
| Updates automáticos do motor | sim (bump de tag) | não (você bumpa) |
| Roda fora do GitHub | via container | via container |
| UI GitHub code scanning (SARIF) | sim | só se estiver no GitHub |
| Contrato JSON p/ a IA | sim | sim |
| Hooks + AGENTS.md de segurança | sim (`init`) | sim (`init`) |
| Auto-fix DRV (fase 3) | sim | sim |

## Versionamento & compatibilidade

- **SemVer**; consumidor pina `@vMAJOR` ou SHA. Mudança que quebra o contrato `.secpipe.yml` = major.
- **Contrato de achados** (`Finding`/SARIF) é parte da API pública — mudança é versionada.
- `secpipe doctor` reporta versão do motor e defasagem.
