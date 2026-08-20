"""Adapter Checkov (IaC SAST: Terraform, CloudFormation, Kubernetes, Dockerfile, Helm, ARM). GRÁTIS
(Apache-2.0), KEYLESS. Emite SARIF -> reusa parse_sarif. Auto-habilitado quando `init` detecta IaC.

Checkov grava o SARIF num arquivo (não stdout limpo): usamos --output-file-path num tmpdir e lemos."""
from __future__ import annotations

import os
import shutil
import tempfile

from secpipe.adapters.base import run_tool, tool_on_path
from secpipe.adapters.sarif import parse_sarif
from secpipe.domain import ScanResult, ScanStatus

BINARY = "checkov"


class CheckovScanner:
    name = BINARY

    def is_available(self) -> bool:
        return tool_on_path(BINARY)

    def scan(self, target: str) -> ScanResult:
        if not tool_on_path(BINARY):
            return ScanResult(self.name, ScanStatus.SKIPPED, (), "ferramenta ausente no PATH")
        workdir = tempfile.mkdtemp(prefix="secpipe-checkov-")
        try:
            # NUNCA passa --bc-api-key/--prisma-api-url: mantém keyless. --compact enxuga a saída.
            run = run_tool(
                BINARY,
                ["-d", target, "--quiet", "--compact", "-o", "sarif", "--output-file-path", workdir],
                timeout=900,
            )
            if run.timed_out:
                return ScanResult(self.name, ScanStatus.ERROR, (), "timeout")
            report = os.path.join(workdir, "results_sarif.sarif")
            try:
                with open(report, encoding="utf-8", errors="replace") as fh:
                    findings = parse_sarif(fh.read(), self.name)
            except OSError:
                detail = (run.stderr or run.stdout or "sem relatorio").strip()[:200]
                return ScanResult(self.name, ScanStatus.ERROR, (), f"checkov nao gerou SARIF: {detail}")
            except (ValueError, TypeError) as exc:
                return ScanResult(self.name, ScanStatus.ERROR, (), f"SARIF invalido: {str(exc)[:200]}")
            return ScanResult(self.name, ScanStatus.OK, tuple(findings), "")
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
