"""Obtém as linhas ADICIONADAS por um diff git (para o diff-scoped gate). I/O na application; o parse é
puro no domínio (diffscope). Segue o padrão de subprocess do verify.py."""
from __future__ import annotations

import subprocess

from secpipe.domain.diffscope import parse_added_lines


def get_added_lines(target: str, base_ref: str) -> dict[str, set[int]] | None:
    """{arquivo: {linhas adicionadas}} de `git -C target diff base_ref -U0`.

    Retorna None se o `git diff` FALHAR (ex.: base_ref não fetchado num shallow clone) — o chamador DEVE
    tratar None como fail-closed (nao estreitar o gate). Prefixo FORÇADO (--src-prefix/--dst-prefix) para o
    parse nao depender de diff.noprefix/mnemonicprefix do repo-alvo."""
    proc = subprocess.run(
        ["git", "-C", target, "diff", base_ref, "--src-prefix=a/", "--dst-prefix=b/", "-U0", "--no-color"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", check=False,
    )
    if proc.returncode != 0:
        return None   # git falhou -> sinaliza (fail-closed no chamador), NAO um diff vazio silencioso
    return parse_added_lines(proc.stdout)
