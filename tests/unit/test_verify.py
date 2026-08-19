"""`secpipe verify` — juiz determinístico: aceita só com gate ok, sem supressão e testes verdes."""
from __future__ import annotations

import subprocess
from pathlib import Path

from secpipe.application.use_cases.verify import verify
from secpipe.domain import GateDecision, Report


class _FakeOrch:
    def __init__(self, passed: bool) -> None:
        self._passed = passed

    def run(self, target: str) -> tuple[Report, GateDecision]:
        return Report(()), GateDecision(self._passed, "fake gate")


def _repo(tmp: Path) -> None:
    subprocess.run(["git", "init", "-q", str(tmp)], check=True)
    subprocess.run(["git", "-C", str(tmp), "config", "user.email", "t@t"], check=True)
    subprocess.run(["git", "-C", str(tmp), "config", "user.name", "t"], check=True)
    (tmp / "app.py").write_text("x = 1\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(tmp), "commit", "-qm", "init"], check=True)


def test_accepts_clean(tmp_path: Path) -> None:
    _repo(tmp_path)
    v = verify(_FakeOrch(True), str(tmp_path))  # type: ignore[arg-type]
    assert v.accepted is True


def test_rejects_on_gate_fail(tmp_path: Path) -> None:
    _repo(tmp_path)
    v = verify(_FakeOrch(False), str(tmp_path))  # type: ignore[arg-type]
    assert v.accepted is False
    assert any("gate" in r for r in v.reasons)


def test_rejects_on_added_suppression(tmp_path: Path) -> None:
    _repo(tmp_path)
    (tmp_path / "app.py").write_text("x = 1  # nosec B101\n", encoding="utf-8")  # fix que SILENCIA
    v = verify(_FakeOrch(True), str(tmp_path))  # type: ignore[arg-type]
    assert v.accepted is False
    assert any("supressao" in r for r in v.reasons)
