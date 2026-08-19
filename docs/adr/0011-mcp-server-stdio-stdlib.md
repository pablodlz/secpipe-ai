# ADR-0011 — Servidor MCP (JSON-RPC stdio, stdlib) expondo primitivas

**Status:** Aceito.

## Contexto
O operador é um agente de IA (ADR-0007/reframe keyless). MCP é o padrão de como agentes chamam ferramentas.
Expor o secpipe via MCP é a interface NATIVA do modelo agent-driven — melhor que o agente adivinhar rodar a CLI no shell.

## Decisão
- **Transporte:** JSON-RPC 2.0 sobre **stdio, stdlib-only** (sem dependência externa — menor superfície de
  supply-chain, coerente com "domínio stdlib puro"). Padrão inspirado no mcp_server do Omni-Pentest.
- **Launch:** `secpipe mcp` (console script já instalado); o `secpipe init` grava o `.mcp.json`. Mais limpo
  que `python caminho/arquivo.py` (sem bootstrap de sys.path).
- **Expõe PRIMITIVAS** (`scan/verify/fix/recall/remember/doctor`); o AGENTE orquestra o loop DRV. Nada de
  tool monolítico "auto_fix" — fiel ao keyless (o agente é a inteligência; o secpipe é o juiz determinístico).
- **É ergonomia/orientação, NÃO imposição:** o agente pode não chamar as tools; por isso a imposição real
  continua nos **git hooks + CI** (o agente não os controla). MCP fica ao lado do AGENTS.md.
- **Local/stdio apenas.** Um MCP remoto/HTTP é empreendimento nível-SaaS (auth/sandbox) — fora de escopo agora.
- 3º surface, fino sobre o mesmo motor: CLI + container + MCP (o CI/CD não fala MCP).

## Consequências
- (+) Interface de primeira classe para qualquer agente MCP; I/O estruturado; zero dependência nova.
- (−) Precisa implementar o handshake JSON-RPC à mão (initialize/tools/list/tools/call). Aceito — é pequeno e testado.
