"""Adapter DAST — OWASP ZAP **baseline** (FEAT-012): análise dinâmica, gratuita e keyless.

Opt-in por design: só roda se houver `dast.target_url` na config E um runner ZAP (docker OU zap-baseline.py).
Sem URL -> SKIPPED (preserva o estático plug-and-play). Normaliza os alertas do ZAP no MESMO contrato
(Finding com cwe/severidade) e alimenta o MESMO gate. O ZAP não é embutido na imagem (é grande): rodamos
o container oficial do ZAP, ou o CLI nativo se presente."""
from __future__ import annotations

import json
import os
import tempfile

from secpipe.adapters.base import run_tool, tool_on_path
from secpipe.domain import Finding, ScanResult, ScanStatus, Severity

NAME = "dast"
_ZAP_CLI = "zap-baseline.py"
_DOCKER = "docker"
_ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"

# ZAP riskcode -> severidade. ZAP não tem "critical"; High é o topo da escala dele.
_RISK: dict[str, Severity] = {"3": Severity.HIGH, "2": Severity.MEDIUM, "1": Severity.LOW, "0": Severity.INFO}


def _sev(riskcode: object) -> Severity:
    return _RISK.get(str(riskcode).strip(), Severity.MEDIUM)  # desconhecido -> MEDIUM (não subestimar)


def parse_zap_report(raw: str) -> list[Finding]:
    """Relatório JSON do ZAP (-J) -> Finding[]. Cada alerta vira um achado (cweid -> cwe, riskcode -> sev)."""
    if not raw.strip():
        return []
    doc = json.loads(raw)
    findings: list[Finding] = []
    for site in doc.get("site") or []:
        if not isinstance(site, dict):
            continue
        site_name = str(site.get("@name") or "")
        for alert in site.get("alerts") or []:
            if not isinstance(alert, dict):
                continue
            cweid = str(alert.get("cweid") or "").strip()
            cwe = f"CWE-{cweid}" if cweid.isdigit() and cweid != "-1" else ""
            instances = alert.get("instances") or []
            uri = str(instances[0].get("uri") or "") if instances and isinstance(instances[0], dict) else ""
            findings.append(Finding(
                tool=NAME,
                rule_id=str(alert.get("alertRef") or alert.get("pluginid") or "zap"),
                severity=_sev(alert.get("riskcode", "")),
                message=str(alert.get("alert") or alert.get("name") or ""),
                file=uri or site_name,
                line=0,
                cwe=cwe,
            ))
    return findings


def runner_available() -> bool:
    """True se dá para rodar o ZAP baseline: container docker (preferido) ou o CLI nativo."""
    return tool_on_path(_DOCKER) or tool_on_path(_ZAP_CLI)


def _run_zap(url: str) -> tuple[bool, str, str]:
    """Roda o ZAP baseline contra `url`. Devolve (rodou, json_do_relatorio, detalhe_do_erro)."""
    workdir = tempfile.mkdtemp(prefix="secpipe-zap-")
    report = "report.json"
    if tool_on_path(_DOCKER):
        # docker monta o workdir em /zap/wrk; o `-J` grava lá -> lemos no host. Caminho confiável.
        run = run_tool(_DOCKER, [
            "run", "--rm", "-v", f"{workdir}:/zap/wrk:rw", _ZAP_IMAGE,
            "zap-baseline.py", "-t", url, "-J", report, "-I",
        ], timeout=1200)
    else:  # CLI nativo: grava o relatório no cwd (workdir)
        run = run_tool(_ZAP_CLI, ["-t", url, "-J", report, "-I"], timeout=1200, cwd=workdir)
    if run.timed_out:
        return (False, "", "timeout no ZAP baseline")
    try:
        with open(os.path.join(workdir, report), encoding="utf-8", errors="replace") as fh:
            return (True, fh.read(), "")
    except OSError:
        detail = (run.stderr or run.stdout or "sem relatorio").strip()[:300]
        return (False, "", f"ZAP nao gerou relatorio: {detail}")


class ZapDastScanner:
    """DAST via ZAP baseline. Só roda com `dast_target` definido (senão SKIP); runner ausente -> SKIP
    (o orquestrador nem chama o scan). ZAP falhou com URL definida -> ERROR (fail-closed)."""
    name = NAME

    def __init__(self, target_url: str = "") -> None:
        self.target_url = target_url

    def is_available(self) -> bool:
        return runner_available()

    def scan(self, target: str) -> ScanResult:  # `target` (dir) é ignorado: DAST atua na URL configurada
        if not self.target_url:
            return ScanResult(self.name, ScanStatus.SKIPPED, (),
                              "DAST desligado: defina dast.target_url no .secpipe.yml para ativar")
        ran, raw, detail = _run_zap(self.target_url)
        if not ran:
            return ScanResult(self.name, ScanStatus.ERROR, (), detail)  # pediu DAST e não rodou -> fail-closed
        try:
            findings = parse_zap_report(raw)
        except (json.JSONDecodeError, ValueError, TypeError) as exc:
            return ScanResult(self.name, ScanStatus.ERROR, (), f"relatorio ZAP invalido: {str(exc)[:200]}")
        return ScanResult(self.name, ScanStatus.OK, tuple(findings), "")
