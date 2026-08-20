"""Servidor MCP do secpipe — JSON-RPC 2.0 sobre stdio, STDLIB-ONLY (sem dependência externa).

Expõe as PRIMITIVAS (scan/fix/verify/recall/remember/doctor) como tools; o AGENTE orquestra o loop DRV
(keyless). Lançado por `secpipe mcp` (o `secpipe init` registra no `.mcp.json` do projeto).

MCP é a camada de ERGONOMIA/orientação — a IMPOSIÇÃO continua nos git hooks + CI (o agente não os controla).
Padrão inspirado no mcp_server do Omni-Pentest (stdlib JSON-RPC), com launch via console script."""
from __future__ import annotations

import json
import sys
from typing import Any

from secpipe import __version__
from secpipe.adapters.fix_memory import FixMemory
from secpipe.adapters.reporters import JsonReporter
from secpipe.application.use_cases.threat_model import build_threat_model
from secpipe.application.use_cases.threat_model import render_json as tm_render_json
from secpipe.application.use_cases.verify import verify as run_verify
from secpipe.domain.fix_memory import VerifiedFix
from secpipe.foundation.composition_root import _SCANNER_REGISTRY, build, build_fixer
from secpipe.foundation.config import Config

_STR = {"type": "string"}
_PROTOCOL = "2024-11-05"

TOOLS: list[dict[str, Any]] = [
    {"name": "secpipe_scan",
     "description": "DETECT: escaneia o alvo (5 scanners free), normaliza e devolve os achados (JSON, "
                    "cada um com `cwe`, `severity`, `file`, `line`, `fingerprint` e `escalate`) + o "
                    "veredito do gate. Comece o loop por aqui.",
     "inputSchema": {"type": "object",
                     "properties": {"target": _STR, "config": _STR}, "required": []}},
    {"name": "secpipe_verify",
     "description": "VERIFY: juiz DETERMINÍSTICO e keyless do fix — gate (achados resolvidos) + "
                    "ausência de supressão no diff + testes. Devolve {accepted, reasons}. Só ACCEPT fecha.",
     "inputSchema": {"type": "object",
                     "properties": {"target": _STR, "base": _STR}, "required": []}},
    {"name": "secpipe_fix",
     "description": "REPAIR (parcial): aplica fixes DETERMINÍSTICOS (codemods) — o restante é você (o "
                    "agente) que corrige. Devolve o que mudou.",
     "inputSchema": {"type": "object",
                     "properties": {"target": _STR, "dry_run": {"type": "boolean"}}, "required": []}},
    {"name": "secpipe_recall",
     "description": "Padrões de fix VERIFICADOS para um CWE (candidatos — ainda passam pela verificação).",
     "inputSchema": {"type": "object", "properties": {"cwe": _STR}, "required": ["cwe"]}},
    {"name": "secpipe_remember",
     "description": "Registra um fix VERIFICADO (o PADRÃO generalizado, NUNCA código/segredo do projeto).",
     "inputSchema": {"type": "object",
                     "properties": {"cwe": _STR, "tool": _STR, "rule_id": _STR, "note": _STR},
                     "required": ["cwe"]}},
    {"name": "secpipe_doctor",
     "description": "Disponibilidade das ferramentas de scan no ambiente.",
     "inputSchema": {"type": "object", "properties": {}, "required": []}},
    {"name": "secpipe_threat_model",
     "description": "THREAT-MODEL (STRIDE): scaffold DETERMINÍSTICO e keyless do app — mapeia os achados "
                    "reais por CWE->STRIDE e descobre a superfície (entrypoints/sinks/ativos). Devolve as 6 "
                    "categorias com achados, superfície e checklists para VOCÊ (o agente) completar o raciocínio.",
     "inputSchema": {"type": "object",
                     "properties": {"target": _STR, "config": _STR}, "required": []}},
]


def _s(args: dict[str, Any], key: str, default: str = "") -> str:
    value = args.get(key)
    return str(value) if value is not None else default


class SecpipeMcpTools:
    def dispatch(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        handler = {
            "secpipe_scan": self._scan, "secpipe_verify": self._verify, "secpipe_fix": self._fix,
            "secpipe_recall": self._recall, "secpipe_remember": self._remember,
            "secpipe_doctor": self._doctor, "secpipe_threat_model": self._threat_model,
        }.get(name)
        if handler is None:
            return {"error": f"unknown tool: {name}"}
        return handler(args)

    def _scan(self, args: dict[str, Any]) -> dict[str, Any]:
        cfg = Config.load(args.get("config"))
        report, decision = build(cfg).run(_s(args, "target", "."))
        payload: dict[str, Any] = json.loads(JsonReporter().render(report))
        payload["gate"] = {"passed": decision.passed, "reason": decision.reason}
        return payload

    def _verify(self, args: dict[str, Any]) -> dict[str, Any]:
        cfg = Config.load(args.get("config"))
        verdict = run_verify(build(cfg), _s(args, "target", "."),
                             base_ref=_s(args, "base", "HEAD"), test_command=cfg.test_command)
        return {"accepted": verdict.accepted, "reasons": verdict.reasons}

    def _fix(self, args: dict[str, Any]) -> dict[str, Any]:
        outcome = build_fixer().run(_s(args, "target", "."), dry_run=bool(args.get("dry_run", False)))
        return {"ran": outcome.ran, "files_changed": outcome.files_changed,
                "changes": outcome.changes, "codemods": list(outcome.codemods), "detail": outcome.detail}

    def _recall(self, args: dict[str, Any]) -> dict[str, Any]:
        cwe = _s(args, "cwe")
        fixes = FixMemory().recall(cwe)
        return {"cwe": cwe,
                "patterns": [{"tool": f.tool, "rule_id": f.rule_id, "note": f.note} for f in fixes]}

    def _remember(self, args: dict[str, Any]) -> dict[str, Any]:
        added = FixMemory().record(VerifiedFix(
            cwe=_s(args, "cwe"), tool=_s(args, "tool"),
            rule_id=_s(args, "rule_id"), note=_s(args, "note")))
        return {"recorded": added}

    def _doctor(self, args: dict[str, Any]) -> dict[str, Any]:
        return {"tools": {name: factory().is_available() for name, factory in _SCANNER_REGISTRY.items()}}

    def _threat_model(self, args: dict[str, Any]) -> dict[str, Any]:
        cfg = Config.load(args.get("config"))
        target = _s(args, "target", ".")
        report, _ = build(cfg).run(target)
        result: dict[str, Any] = json.loads(tm_render_json(build_threat_model(target, tuple(report.findings))))
        return result


def _response(req_id: Any, result: Any = None, error: str | None = None) -> str:
    resp: dict[str, Any] = {"jsonrpc": "2.0", "id": req_id}
    if error is not None:
        resp["error"] = {"code": -32600, "message": error}
    else:
        resp["result"] = result
    return json.dumps(resp)


def run_server(tools: SecpipeMcpTools, stdin: Any = None, stdout: Any = None) -> None:
    stdin = stdin if stdin is not None else sys.stdin
    stdout = stdout if stdout is not None else sys.stdout

    def emit(text: str) -> None:
        stdout.write(text + "\n")
        stdout.flush()

    for raw in stdin:
        line = raw.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError as exc:
            emit(_response(None, error=f"parse error: {exc}"))
            continue
        req_id = req.get("id")
        method = req.get("method", "")
        if req_id is None and str(method).startswith("notifications/"):
            continue
        if method == "initialize":
            emit(_response(req_id, result={
                "protocolVersion": req.get("params", {}).get("protocolVersion", _PROTOCOL),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "secpipe", "version": __version__}}))
        elif method == "tools/list":
            emit(_response(req_id, result={"tools": TOOLS}))
        elif method == "tools/call":
            params = req.get("params", {})
            try:
                result: dict[str, Any] = tools.dispatch(params.get("name", ""), params.get("arguments") or {})
            except Exception as exc:  # uma falha de tool nunca pode derrubar o servidor
                result = {"error": str(exc)}
            emit(_response(req_id, result={
                "content": [{"type": "text", "text": json.dumps(result, indent=2, default=str)}]}))
        elif req_id is not None:
            emit(_response(req_id, error=f"method not found: {method}"))


def main() -> int:
    run_server(SecpipeMcpTools())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
