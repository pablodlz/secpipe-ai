"""Servidor MCP (JSON-RPC stdio, stdlib): dispatch das tools + roundtrip do protocolo."""
from __future__ import annotations

import io
import json

from secpipe.mcp_server import TOOLS, SecpipeMcpTools, run_server


def test_tools_expose_the_primitives() -> None:
    names = {t["name"] for t in TOOLS}
    assert {"secpipe_scan", "secpipe_verify", "secpipe_fix",
            "secpipe_recall", "secpipe_remember", "secpipe_doctor"} <= names


def test_dispatch_doctor() -> None:
    out = SecpipeMcpTools().dispatch("secpipe_doctor", {})
    assert "tools" in out and "bandit" in out["tools"]


def test_dispatch_unknown_is_error_not_crash() -> None:
    assert "error" in SecpipeMcpTools().dispatch("nope", {})


def test_jsonrpc_roundtrip() -> None:
    reqs = "\n".join([
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                    "params": {"name": "secpipe_doctor", "arguments": {}}}),
        json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),  # sem resposta
    ]) + "\n"
    out = io.StringIO()
    run_server(SecpipeMcpTools(), stdin=io.StringIO(reqs), stdout=out)
    lines = [json.loads(x) for x in out.getvalue().splitlines() if x.strip()]
    assert len(lines) == 3                                   # a notification não gera resposta
    assert lines[0]["result"]["serverInfo"]["name"] == "secpipe"
    assert any(t["name"] == "secpipe_scan" for t in lines[1]["result"]["tools"])
    assert "tools" in json.loads(lines[2]["result"]["content"][0]["text"])
