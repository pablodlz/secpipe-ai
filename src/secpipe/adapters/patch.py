"""Aplica/reverte um unified diff no repo alvo de forma SEGURA e reversível, via `git apply` (shell=False,
argumentos em lista). NÃO faz commit/push/merge — isso é passo separado do workflow (opt-in). Usado pelo
loop headless: aplica o patch da IA, roda o verify determinístico, e REVERTE se não for aceito."""
from __future__ import annotations

import os
import tempfile

from secpipe.adapters.base import run_tool


def _write_patch(diff: str) -> str:
    fd, path = tempfile.mkstemp(prefix="secpipe-patch-", suffix=".diff")
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(diff if diff.endswith("\n") else diff + "\n")
    return path


def apply_patch(target: str, diff: str) -> tuple[bool, str]:
    """`git apply --check` e então `git apply`. Devolve (aplicou, detalhe). Não commita."""
    if not diff.strip():
        return (False, "patch vazio")
    path = _write_patch(diff)
    try:
        check = run_tool("git", ["-C", target, "apply", "--check", path], timeout=60)
        if check.missing:
            return (False, "git ausente no PATH")
        if check.returncode != 0:
            return (False, f"patch nao aplica limpo: {(check.stderr or '').strip()[:200]}")
        applied = run_tool("git", ["-C", target, "apply", path], timeout=60)
        if applied.returncode != 0:
            return (False, f"git apply falhou: {(applied.stderr or '').strip()[:200]}")
        return (True, "aplicado")
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def revert_patch(target: str, diff: str) -> bool:
    """Desfaz um patch aplicado (`git apply -R`). Best-effort."""
    if not diff.strip():
        return False
    path = _write_patch(diff)
    try:
        return run_tool("git", ["-C", target, "apply", "-R", path], timeout=60).returncode == 0
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
