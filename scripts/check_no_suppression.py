#!/usr/bin/env python3
"""Guardrail anti-supressão (ADR-0008): bloqueia INTRODUZIR silenciadores de achado no diff staged.

Cross-platform (Windows/Linux) — puro Python, sem bash. Analisa só as linhas ADICIONADAS do diff.
Ignora este próprio script e o config do pre-commit (que naturalmente citam os tokens)."""
from __future__ import annotations

import subprocess

_SUPPRESSORS = ("# nosec", "#nosec", "# noqa", "#noqa", "nosemgrep")
_IGNORE = {
    "scripts/check_no_suppression.py",
    ".pre-commit-config.yaml",
    # citam os tokens como DADO/REGRA (dono do padrão + template do AGENTS.md), não como supressão real:
    "src/secpipe/application/use_cases/precommit.py",
    "src/secpipe/application/use_cases/_init_resources.py",
    "tests/unit/test_precommit.py",   # fixture contém '# nosec' de propósito (testa o detector)
}


def main() -> int:
    diff = subprocess.run(
        ["git", "diff", "--cached", "-U0", "--no-color"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", check=False,
    ).stdout
    current = ""
    offending: list[str] = []
    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            current = line[6:].strip()
            continue
        if line.startswith("+") and not line.startswith("+++") and current not in _IGNORE:
            low = line.lower()
            if any(tok in low for tok in _SUPPRESSORS):
                offending.append(f"{current}: {line[1:].strip()}")
    if offending:
        print("Supressao de achado detectada (ADR-0008) — resolva a causa, nao silencie:")
        for item in offending:
            print("  -", item)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
