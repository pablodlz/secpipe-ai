"""`secpipe hook` — imposição agent-independent no pre-commit (ADR-0008 / FEAT-010).

Bloqueia a INTRODUÇÃO de silenciadores de achado no diff staged e, se `gitleaks` estiver disponível,
barra segredo no staged. Cross-platform (Windows/Linux). É o dono único do padrão de supressão."""
from __future__ import annotations

import shutil
import subprocess

# padrões de supressão barrados (dono único). Não confundir com uso legítimo em config revisada.
SUPPRESSORS: tuple[str, ...] = (
    "# nosec", "#nosec", "# noqa", "#noqa", "nosemgrep",
    "gitleaks:allow", "checkov:skip", "trivy:ignore", "semgrep-ignore",  # supressores inline por tool
)


def _staged_diff() -> str:
    proc = subprocess.run(
        ["git", "diff", "--cached", "-U0", "--no-color"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", check=False,
    )
    return proc.stdout


def find_suppressions(diff: str) -> list[str]:
    """Linhas ADICIONADAS que introduzem um silenciador. Retorna 'arquivo: linha'."""
    current = ""
    out: list[str] = []
    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            current = line[6:].strip()
            continue
        if line.startswith("+") and not line.startswith("+++"):
            low = line.lower()
            if any(tok in low for tok in SUPPRESSORS):
                out.append(f"{current}: {line[1:].strip()}")
    return out


def run() -> int:
    """Executado pelo hook pre-commit. 0 = ok; !=0 bloqueia o commit."""
    offending = find_suppressions(_staged_diff())
    if offending:
        print("secpipe: supressao de achado detectada (ADR-0008) — resolva a causa, nao silencie:")
        for item in offending:
            print("  -", item)
        return 1
    if shutil.which("gitleaks"):
        result = subprocess.run(
            ["gitleaks", "protect", "--staged", "--no-banner"], check=False
        )
        if result.returncode != 0:
            print("secpipe: gitleaks encontrou segredo no conteudo staged.")
            return result.returncode
    return 0
