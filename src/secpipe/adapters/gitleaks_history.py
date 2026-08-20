"""Adapter gitleaks-history (segredos no HISTÓRICO git). O GitleaksScanner roda com --no-git (só o
filesystem atual), então segredos COMMITADOS e depois removidos passam batido. Este varre o histórico
inteiro (sem --no-git). Segredo no histórico = comprometido (público forever) => ROTACIONAR, não só remover.

Opt-in: pode ser lento em repos grandes; SKIPPED fora de repo git."""
from __future__ import annotations

import dataclasses
import os
import tempfile

from secpipe.adapters.base import run_tool, tool_on_path
from secpipe.adapters.gitleaks import parse_gitleaks
from secpipe.domain import ScanResult, ScanStatus

NAME = "gitleaks-history"
BINARY = "gitleaks"


def _is_git_repo(target: str) -> bool:
    return os.path.isdir(os.path.join(target, ".git")) or run_tool(
        "git", ["-C", target, "rev-parse", "--git-dir"], timeout=15
    ).returncode == 0


class GitleaksHistoryScanner:
    name = NAME

    def is_available(self) -> bool:
        return tool_on_path(BINARY)

    def scan(self, target: str) -> ScanResult:
        if not tool_on_path(BINARY):
            return ScanResult(self.name, ScanStatus.SKIPPED, (), "ferramenta ausente no PATH")
        if not _is_git_repo(target):
            return ScanResult(self.name, ScanStatus.SKIPPED, (), "nao e um repo git (nada de historico p/ varrer)")
        fd, report = tempfile.mkstemp(prefix="secpipe-gitleaks-hist-", suffix=".json")
        os.close(fd)
        try:
            # SEM --no-git: varre TODO o histórico de commits.
            run = run_tool(BINARY, ["detect", "--source", target, "--report-format", "json",
                                    "--report-path", report, "--exit-code", "0"], timeout=1200)
            if run.timed_out:
                return ScanResult(self.name, ScanStatus.ERROR, (), "timeout no scan de historico")
            try:
                with open(report, encoding="utf-8") as fh:
                    base = parse_gitleaks(fh.read())
            except (OSError, ValueError) as exc:
                return ScanResult(self.name, ScanStatus.ERROR, (), f"report ilegivel: {exc}")
            # re-tag: deixa claro que é do histórico e orienta ROTAÇÃO (não só remoção).
            findings = tuple(
                dataclasses.replace(f, tool=self.name, message=f"[git history] {f.message} — ROTACIONE o segredo")
                for f in base
            )
            return ScanResult(self.name, ScanStatus.OK, findings, "")
        finally:
            try:
                os.unlink(report)
            except OSError:
                pass
