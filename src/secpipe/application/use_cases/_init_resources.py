"""Templates instalados pelo `secpipe init` (FEAT-010). Placeholders __X__ são substituídos por replace().

Este arquivo cita os tokens de supressão como REGRA (prosa do AGENTS.md) — por isso está na allowlist
do guardrail anti-supressão do próprio repo (scripts/check_no_suppression.py)."""
from __future__ import annotations

# Ref do reusable workflow (Modo A — referenciado). Pinar tag/SHA no consumidor.
REUSABLE_REF = "pablodlz/secpipe-ai/.github/workflows/secpipe.reusable.yml@v1"

SECPIPE_YML = """# .secpipe.yml — gerado por `secpipe init`. OPCIONAL (zero-config também funciona; defaults fortes).
scanners: [__SCANNERS__]
block_severity: HIGH
languages: [__LANGUAGES__]
"""

WORKFLOW_YML = """# Segurança via secpipe (Modo A — referenciado). Recebe updates ao bumpar a tag/SHA.
name: security
on:
  push: { branches: [main] }
  pull_request: { branches: [main] }
permissions:
  contents: read
jobs:
  secpipe:
    uses: __REF__
    with:
      target: "."
      config: ".secpipe.yml"
"""

# Hook POSIX sh (git no Windows roda via sh embutido). Falha-aberto se secpipe não estiver instalado
# (o CI ainda aplica o gate) — o hook local é reforço, não a única linha.
PRECOMMIT_SH = """#!/usr/bin/env sh
# Hook pre-commit instalado pelo `secpipe init` — imposição agent-independent (ADR-0008).
if command -v secpipe >/dev/null 2>&1; then exec secpipe hook; fi
if command -v python >/dev/null 2>&1; then exec python -m secpipe.cli hook; fi
if command -v python3 >/dev/null 2>&1; then exec python3 -m secpipe.cli hook; fi
echo "secpipe: nao encontrado no PATH — hook local pulado (o CI ainda aplica o gate)."
exit 0
"""

# Registro do servidor MCP (Claude Code lê .mcp.json na raiz do projeto). O agente ganha as tools
# secpipe_scan/verify/fix/recall/remember/doctor. Lançado via console script `secpipe mcp`.
MCP_JSON = """{
  "mcpServers": {
    "secpipe": { "command": "secpipe", "args": ["mcp"] }
  }
}
"""

# Shim que aponta o agente para o AGENTS.md (para ferramentas que leem CLAUDE.md, etc.).
SHIM = "Este projeto adotou o secpipe. Carregue **AGENTS.md** antes de desenvolver (contexto de segurança).\n"

AGENTS_MD = """# Contexto de Segurança (instalado pelo `secpipe init`)

> Este projeto adotou o **secpipe**. **Qualquer IA** (Claude, Cursor, Copilot, Aider...) deve carregar
> este contexto **antes** de desenvolver. Shims por ferramenta apontam para cá.

## Você desenvolve sob uma esteira de segurança

Produza código **seguro por padrão** e **corrija** o que a esteira apontar — sem deixar nada pendente
para um humano, **exceto** o que as regras mandam escalar.

## Padrões secure-by-default
- Nunca escreva **segredos** no código (chaves, tokens, senhas). Use variável de ambiente / secret manager.
- Valide e sanitize **toda entrada externa**; nada de comando/SQL/caminho por concatenação.
- Sem execução de código/comando arbitrário; sem desserialização insegura. Least privilege; fail-closed.

## Regras invioláveis (guardrails — ADR-0008)
1. **NUNCA silencie um achado.** Proibido adicionar `# nosec`, `# noqa`, `nosemgrep`, entradas de
   baseline/allowlist, ou baixar a severidade para o gate passar. Resolva a causa. (O hook pre-commit bloqueia isso.)
2. **NÃO edite a política/gate** — a régua mora no motor `secpipe` referenciado, não neste repo.
3. **Toda correção precisa ser verificada**: teste que reproduz a vulnerabilidade (vermelho->verde) + suíte verde.
4. **Escale** (não corrija sozinha, peça revisão humana) quando o achado envolver: autenticação/autorização,
   criptografia, caminho de dinheiro/pagamento, ou severidade **crítica**.

## Loop de trabalho
```text
`secpipe scan` (lê o JSON) -> `secpipe fix` (codemods determinísticos) -> corrigir o resto ->
`secpipe verify` (gate + anti-supressão + testes) -> repetir até ACCEPT
```
- Cada achado traz `escalate: true|false` — se `true` (auth/cripto/segredo/crítico), **escale**, não corrija sozinha.
- Antes de corrigir um CWE, `secpipe recall --cwe CWE-XXX` pode trazer um padrão que já funcionou.
- Depois de um fix ACEITO, `secpipe remember --cwe ... --note "<padrão>"` (o PADRÃO, nunca código/segredo).

`secpipe scan` emite JSON no stdout (tool, rule_id, cwe, severity, file, line, message, fingerprint, escalate);
o gate vai no stderr e o exit code indica PASS(0)/FAIL(1).
"""
