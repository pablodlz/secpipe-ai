"""Utilidades comuns aos adapters de scanner: descoberta e execução SEGURA de ferramentas.

Segurança (ADR-0008 / é um produto de segurança): binário resolvido por caminho absoluto (shutil.which),
`shell=False`, argumentos sempre em LISTA (nunca string), timeout obrigatório. Sem injeção de comando."""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass


def tool_on_path(binary: str) -> bool:
    """True se o binário existe no PATH. Base do `is_available()` e do `secpipe doctor`."""
    return shutil.which(binary) is not None


@dataclass(frozen=True, slots=True)
class ToolRun:
    missing: bool          # binário não está no PATH
    timed_out: bool
    returncode: int
    stdout: str
    stderr: str

    @property
    def ran(self) -> bool:
        return not self.missing and not self.timed_out


def run_tool(binary: str, args: list[str], *, timeout: int = 300) -> ToolRun:
    """Executa `binary args...` de forma segura e captura a saída.

    NUNCA usa shell; resolve o binário para caminho absoluto; argumentos em lista. Um returncode != 0
    NÃO é necessariamente erro (muitos scanners saem 1 quando ACHAM algo) — quem interpreta é o adapter."""
    resolved = shutil.which(binary)
    if resolved is None:
        return ToolRun(missing=True, timed_out=False, returncode=127, stdout="", stderr="")
    try:
        # Suppressão da regra "subprocess sem shell" é feita no NÍVEL DE PROJETO (pyproject:
        # ruff per-file-ignores S603/S607 + bandit skips), revisável — não inline (ADR-0008).
        proc = subprocess.run(
            [resolved, *args],
            capture_output=True,
            text=True,
            encoding="utf-8",      # cross-platform: evita cp1252/mojibake no Windows
            errors="replace",
            timeout=timeout,
            shell=False,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return ToolRun(missing=False, timed_out=True, returncode=124, stdout="", stderr="timeout")
    return ToolRun(
        missing=False, timed_out=False, returncode=proc.returncode,
        stdout=proc.stdout or "", stderr=proc.stderr or "",
    )
