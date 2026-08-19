"""`secpipe init` num repo git temporário: instala config/AGENTS/hook/workflow; idempotente."""
from __future__ import annotations

import subprocess
from pathlib import Path

from secpipe.application.use_cases.init import init


def _git(root: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(root), *args],
                          capture_output=True, text=True, check=False).stdout.strip()


def test_init_installs_everything(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "main.py").write_text("print('hi')\n", encoding="utf-8")

    result = init(str(tmp_path))

    assert (tmp_path / ".secpipe.yml").is_file()
    assert (tmp_path / "AGENTS.md").is_file()
    assert (tmp_path / "CLAUDE.md").is_file()
    assert (tmp_path / ".github" / "workflows" / "security.yml").is_file()
    assert (tmp_path / ".githooks" / "pre-commit").is_file()
    # python detectado -> bandit no .secpipe.yml
    assert "bandit" in (tmp_path / ".secpipe.yml").read_text(encoding="utf-8")
    # hooks ativados
    assert _git(tmp_path, "config", "--get", "core.hooksPath") == ".githooks"
    assert any("gravado" in a for a in result.actions)


def test_init_is_idempotent(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    init(str(tmp_path))
    again = init(str(tmp_path))
    assert any("mantido" in a for a in again.actions)  # não sobrescreve sem --force
