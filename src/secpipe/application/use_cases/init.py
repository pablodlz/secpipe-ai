"""`secpipe init` — adota o secpipe num projeto (FEAT-010): detecta linguagem e instala config,
contexto de agente (AGENTS.md + shim), hook pre-commit (imposição agent-independent) e o workflow.
Idempotente (pula o que já existe; `force=True` sobrescreve)."""
from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from secpipe.application.use_cases import _init_resources as R
from secpipe.domain.languages import detect_from_paths, scanners_for

_SKIP_DIRS = {".git", ".venv", "venv", "node_modules", ".tox", "dist", "build", "__pycache__", "tools"}


@dataclass(slots=True)
class InitResult:
    actions: list[str] = field(default_factory=list)


def _iter_filenames(root: Path, limit: int = 5000) -> list[str]:
    names: list[str] = []
    for _dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        names.extend(filenames)
        if len(names) >= limit:
            break
    return names


def _write(path: Path, content: str, *, force: bool, label: str, actions: list[str]) -> None:
    if path.exists() and not force:
        actions.append(f"mantido (ja existe): {label}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    actions.append(f"gravado: {label}")


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, text=True, check=False
    )


# Bloco de hook do secpipe para projetos que já usam o pre-commit framework (integração, não clobber).
_PRECOMMIT_HOOK_BLOCK = """  - repo: local
    hooks:
      - id: secpipe
        name: secpipe (anti-supressao + segredo staged)
        entry: secpipe hook
        language: system
        pass_filenames: false
"""


def _integrate_precommit(cfg: Path, actions: list[str]) -> None:
    """Anexa o hook secpipe ao .pre-commit-config.yaml existente (idempotente). NÃO mexe em core.hooksPath."""
    content = cfg.read_text(encoding="utf-8")
    if "id: secpipe" in content or "secpipe hook" in content:
        actions.append("mantido: hook secpipe ja presente no .pre-commit-config.yaml")
        return
    sep = "" if content.endswith("\n") else "\n"
    cfg.write_text(content + sep + _PRECOMMIT_HOOK_BLOCK, encoding="utf-8")
    actions.append("hook secpipe adicionado ao .pre-commit-config.yaml existente (core.hooksPath intocado)")


def _install_hooks(root: Path, *, force: bool, actions: list[str]) -> None:
    # Projeto que JÁ usa o pre-commit framework: integra o hook lá (não sequestra core.hooksPath,
    # o que silenciosamente desativaria os hooks existentes do pre-commit).
    precommit = root / ".pre-commit-config.yaml"
    if precommit.is_file():
        _integrate_precommit(precommit, actions)
        return
    # Caso contrário: hook nativo do git via .githooks + core.hooksPath.
    hook = root / ".githooks" / "pre-commit"
    _write(hook, R.PRECOMMIT_SH, force=force, label=".githooks/pre-commit", actions=actions)
    try:
        os.chmod(hook, 0o700)   # executável só pelo dono (git roda como o usuário) — menos permissivo
    except OSError:
        pass
    if _git(root, "rev-parse", "--git-dir").returncode != 0:
        actions.append("AVISO: nao e um repo git — rode `git init` e `secpipe init` de novo p/ ativar os hooks.")
        return
    current = _git(root, "config", "--get", "core.hooksPath").stdout.strip()
    if current and current != ".githooks" and not force:
        actions.append(f"AVISO: core.hooksPath ja e '{current}' — nao alterado (use --force para trocar).")
        return
    if _git(root, "config", "core.hooksPath", ".githooks").returncode == 0:
        actions.append("git config core.hooksPath = .githooks")


def init(
    target: str = ".", *, force: bool = False, shims: bool = True,
    hooks: bool = True, workflow: bool = True,
) -> InitResult:
    root = Path(target).resolve()
    res = InitResult()
    langs = detect_from_paths(_iter_filenames(root))
    scanners = scanners_for(langs)

    yml = (R.SECPIPE_YML
           .replace("__SCANNERS__", ", ".join(scanners))
           .replace("__LANGUAGES__", ", ".join(sorted(langs))))
    _write(root / ".secpipe.yml", yml, force=force, label=".secpipe.yml", actions=res.actions)

    _write(root / "AGENTS.md", R.AGENTS_MD, force=force, label="AGENTS.md", actions=res.actions)
    _write(root / ".mcp.json", R.MCP_JSON, force=force, label=".mcp.json (servidor MCP)", actions=res.actions)
    if shims:
        _write(root / "CLAUDE.md", R.SHIM, force=force, label="CLAUDE.md (shim)", actions=res.actions)

    if workflow:
        wf = R.WORKFLOW_YML.replace("__REF__", R.REUSABLE_REF)
        _write(root / ".github" / "workflows" / "security.yml", wf, force=force,
               label=".github/workflows/security.yml", actions=res.actions)

    if hooks:
        _install_hooks(root, force=force, actions=res.actions)

    return res
