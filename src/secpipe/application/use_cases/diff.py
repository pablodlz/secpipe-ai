"""Obtém as linhas ADICIONADAS por um diff git (para o diff-scoped gate). I/O na application; o parse é
puro no domínio (diffscope). Segue o padrão de subprocess do verify.py."""
from __future__ import annotations

import subprocess

from secpipe.domain.diffscope import parse_added_lines


def get_added_lines(target: str, base_ref: str) -> dict[str, set[int]]:
    """{arquivo: {linhas adicionadas}} de `git -C target diff base_ref -U0`. Vazio se git falhar."""
    proc = subprocess.run(
        ["git", "-C", target, "diff", base_ref, "-U0", "--no-color"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", check=False,
    )
    return parse_added_lines(proc.stdout)
