# Contexto de Segurança (instalado pelo `secpipe init`)

> Template do `AGENTS.md` de segurança que o `secpipe` instala num projeto consumidor. **Qualquer IA**
> (Claude, Cursor, Copilot, Aider…) deve carregar este contexto **antes** de desenvolver. Shims por
> ferramenta (`CLAUDE.md`, `.cursor/rules`, `.github/copilot-instructions.md`) apenas apontam para cá.

## Você desenvolve sob uma esteira de segurança (secpipe)

Este projeto adotou o `secpipe`. Ao desenvolver, você deve produzir código **seguro por padrão** e
**corrigir** os achados que a esteira apontar — sem deixar nada pendente para um humano, **exceto** o
que as regras mandam escalar.

## Padrões secure-by-default (resumo)

- Nunca escreva **segredos** no código (chaves, tokens, senhas). Use variável de ambiente/secret manager.
- Valide e sanitize **toda entrada externa**. Nada de comando/SQL/caminho construído por concatenação.
- Sem execução de código/comando arbitrário; sem desserialização insegura.
- Least privilege; falha segura (fail-closed).

## Regras invioláveis (guardrails — ADR-0008)

1. **NUNCA silencie um achado.** É proibido adicionar `# nosec`, `# noqa`, `nosemgrep`, entradas de
   baseline/allowlist, ou **baixar a severidade** para o gate passar. Resolva a causa.
2. **NÃO edite a política/gate** — a régua mora no motor `secpipe` referenciado, não neste repo.
3. **Toda correção precisa ser verificada**: um teste que reproduz a vulnerabilidade (vermelho→verde)
   e a suíte funcional passando. Silêncio do scanner não é prova de correção.
4. **Escale (abstention)** — não corrija sozinha e peça revisão humana — quando o achado envolver:
   autenticação/autorização, criptografia, caminho de dinheiro/pagamento, ou severidade **crítica**.

## Loop de trabalho esperado

```text
escrever → `secpipe scan` (lê o JSON de achados) → corrigir (determinístico de preferência) →
verificar (rerun + testes) → repetir até o gate passar → escalar só o que a regra 4 manda.
```

## Como consumir os achados

`secpipe scan` emite JSON no stdout (contrato estável): cada `finding` tem `tool`, `rule_id`, `cwe`,
`severity`, `file`, `line`, `message`, `fingerprint`. Use isso para localizar e corrigir. O gate vai
para o stderr e o **exit code** indica PASS(0)/FAIL(1).
