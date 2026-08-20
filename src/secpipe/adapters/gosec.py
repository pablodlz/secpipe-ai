"""Adapter gosec (SAST de Go). GRÁTIS (Apache-2.0), KEYLESS. Emite SARIF (gravado em arquivo via -out).

Guard: só 'disponível' se gosec E o toolchain `go` estiverem no PATH — sem `go`, gosec ERRA ao carregar
pacotes e o gate fail-closed bloquearia falsamente; o AND vira um SKIPPED honesto."""
from __future__ import annotations

import os
import shutil
import tempfile

from secpipe.adapters.base import run_tool, tool_on_path
from secpipe.adapters.sarif import parse_sarif
from secpipe.domain import ScanResult, ScanStatus

BINARY = "gosec"


class GosecScanner:
    name = BINARY

    def is_available(self) -> bool:
        return tool_on_path(BINARY) and tool_on_path("go")

    def scan(self, target: str) -> ScanResult:
        if not self.is_available():
            return ScanResult(self.name, ScanStatus.SKIPPED, (), "gosec ou toolchain 'go' ausente no PATH")
        workdir = tempfile.mkdtemp(prefix="secpipe-gosec-")
        report = os.path.join(workdir, "gosec.sarif")
        try:
            run = run_tool(BINARY, ["-quiet", "-fmt", "sarif", "-out", report, "-no-fail", "./..."],
                           timeout=900, cwd=target)
            if run.timed_out:
                return ScanResult(self.name, ScanStatus.ERROR, (), "timeout")
            try:
                with open(report, encoding="utf-8", errors="replace") as fh:
                    findings = parse_sarif(fh.read(), self.name)
            except OSError:
                detail = (run.stderr or run.stdout or "sem relatorio").strip()[:200]
                return ScanResult(self.name, ScanStatus.ERROR, (), f"gosec nao gerou SARIF: {detail}")
            except (ValueError, TypeError) as exc:
                return ScanResult(self.name, ScanStatus.ERROR, (), f"SARIF invalido: {str(exc)[:200]}")
            return ScanResult(self.name, ScanStatus.OK, tuple(findings), "")
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
