"""Emissão de SBOM (Software Bill of Materials) — CycloneDX (default) ou SPDX — via syft (preferido,
especialista) com fallback para trivy (JÁ embutido na imagem). GRÁTIS, keyless, dependency-light.

Não é scanner (não produz Finding, não passa pelo gate) — é utilitário de supply-chain."""
from __future__ import annotations

from dataclasses import dataclass

from secpipe.adapters.base import run_tool, tool_on_path

_SKIP_DIRS = ".venv,venv,node_modules,tools,dist,build,.tox,vendor"
# formato lógico -> (arg do syft, arg do trivy)
_FORMATS = {"cyclonedx": ("cyclonedx-json", "cyclonedx"), "spdx": ("spdx-json", "spdx-json")}


@dataclass(frozen=True, slots=True)
class SbomResult:
    ran: bool
    tool: str
    fmt: str
    document: str
    detail: str


def emit_sbom(target: str, fmt: str = "cyclonedx", *, timeout: int = 300) -> SbomResult:
    if fmt not in _FORMATS:
        return SbomResult(False, "", fmt, "", f"formato invalido: {fmt} (use cyclonedx|spdx)")
    syft_fmt, trivy_fmt = _FORMATS[fmt]
    if tool_on_path("syft"):
        tool, run = "syft", run_tool("syft", [target, "-o", syft_fmt, "-q"], timeout=timeout)
    elif tool_on_path("trivy"):
        tool = "trivy"
        run = run_tool("trivy", ["fs", "--format", trivy_fmt, "--quiet", "--skip-dirs", _SKIP_DIRS, target],
                       timeout=timeout)
    else:
        return SbomResult(False, "", fmt, "",
                          "sem gerador de SBOM (instale syft/trivy via `python install.py` ou use o container)")
    if run.timed_out:
        return SbomResult(False, tool, fmt, "", "timeout")
    if not run.stdout.strip():
        return SbomResult(False, tool, fmt, "", f"{tool} nao gerou SBOM: {(run.stderr or '').strip()[:200]}")
    return SbomResult(True, tool, fmt, run.stdout, "")
