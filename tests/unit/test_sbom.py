"""SBOM: prefere syft, cai p/ trivy, formatos, fail-closed sem gerador/erro; tool MCP."""
from __future__ import annotations

import secpipe.adapters.sbom as sb
import secpipe.mcp_server as mcp
from secpipe.adapters.base import ToolRun
from secpipe.adapters.sbom import SbomResult, emit_sbom


def _run(stdout: str = "{}", rc: int = 0, timed_out: bool = False) -> ToolRun:
    return ToolRun(missing=False, timed_out=timed_out, returncode=rc, stdout=stdout, stderr="")


def test_prefers_syft(monkeypatch) -> None:
    captured: dict[str, object] = {}
    monkeypatch.setattr(sb, "tool_on_path", lambda b: True)   # syft presente

    def fake(b, a, *, timeout=300, cwd=None):
        captured["args"] = a
        return _run('{"bomFormat":"CycloneDX"}')

    monkeypatch.setattr(sb, "run_tool", fake)
    res = emit_sbom(".", "cyclonedx")
    assert res.ran and res.tool == "syft" and "cyclonedx-json" in captured["args"]


def test_falls_back_to_trivy(monkeypatch) -> None:
    monkeypatch.setattr(sb, "tool_on_path", lambda b: b == "trivy")
    monkeypatch.setattr(sb, "run_tool", lambda b, a, *, timeout=300, cwd=None: _run('{"x":1}'))
    res = emit_sbom(".", "spdx")
    assert res.ran and res.tool == "trivy"


def test_no_generator(monkeypatch) -> None:
    monkeypatch.setattr(sb, "tool_on_path", lambda b: False)
    assert emit_sbom(".").ran is False


def test_invalid_format() -> None:
    assert emit_sbom(".", "bogus").ran is False


def test_tool_failure_is_failclosed(monkeypatch) -> None:
    monkeypatch.setattr(sb, "tool_on_path", lambda b: b == "syft")
    monkeypatch.setattr(sb, "run_tool", lambda b, a, *, timeout=300, cwd=None: _run("", rc=1))
    assert emit_sbom(".").ran is False


def test_mcp_sbom_dispatch(monkeypatch) -> None:
    monkeypatch.setattr(mcp, "emit_sbom", lambda t, f: SbomResult(True, "syft", f, "BIGDOC", ""))
    out = mcp.SecpipeMcpTools().dispatch("secpipe_sbom", {"target": "."})
    assert out["ran"] and out["tool"] == "syft" and out["bytes"] == len("BIGDOC")
