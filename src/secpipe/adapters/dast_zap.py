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
_ZAP_BASELINE = "zap-baseline.py"   # passivo (rápido, seguro)
_ZAP_FULL = "zap-full-scan.py"      # ATIVO (envia payloads reais — só contra alvos próprios!)
_DOCKER = "docker"
_ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"
_TIMEOUT = {"baseline": 1200, "full": 3600}


def _zap_script(mode: str) -> str:
    return _ZAP_FULL if mode == "full" else _ZAP_BASELINE

# ZAP riskcode -> severidade. ZAP não tem "critical"; High é o topo da escala dele.
_RISK: dict[str, Severity] = {"3": Severity.HIGH, "2": Severity.MEDIUM, "1": Severity.LOW, "0": Severity.INFO}


def _sev(riskcode: object) -> Severity:
    return _RISK.get(str(riskcode).strip(), Severity.MEDIUM)  # desconhecido -> MEDIUM (não subestimar)


def parse_zap_report(raw: str) -> list[Finding]:
    """Relatório JSON do ZAP (-J) -> Finding[]. Cada alerta vira um achado (cweid -> cwe, riskcode -> sev)."""
    if not raw.strip():
        return []
    doc = json.loads(raw)
    if not isinstance(doc, dict):   # JSON válido não-objeto -> ERROR fail-closed (achado #11)
        raise ValueError("ZAP: o topo do relatorio nao e um objeto")
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


def runner_available(mode: str = "baseline") -> bool:
    """True se dá para rodar o ZAP: container docker (cobre ambos os modos) ou o CLI nativo do modo."""
    return tool_on_path(_DOCKER) or tool_on_path(_zap_script(mode))


def _run_zap(url: str, *, mode: str = "baseline", timeout: int = 0) -> tuple[bool, str, str]:
    """Roda o ZAP (baseline|full) contra `url`. Devolve (rodou, json_do_relatorio, detalhe_do_erro)."""
    workdir = tempfile.mkdtemp(prefix="secpipe-zap-")
    report = "report.json"
    script = _zap_script(mode)
    secs = timeout if timeout > 0 else _TIMEOUT.get(mode, 1200)
    if tool_on_path(_DOCKER):
        # docker monta o workdir em /zap/wrk; o `-J` grava lá -> lemos no host. Caminho confiável.
        run = run_tool(_DOCKER, [
            "run", "--rm", "-v", f"{workdir}:/zap/wrk:rw", _ZAP_IMAGE,
            script, "-t", url, "-J", report, "-I",
        ], timeout=secs)
    else:  # CLI nativo: grava o relatório no cwd (workdir)
        run = run_tool(script, ["-t", url, "-J", report, "-I"], timeout=secs, cwd=workdir)
    if run.timed_out:
        return (False, "", f"timeout no ZAP {mode}")
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

    def __init__(self, target_url: str = "", *, mode: str = "baseline", timeout: int = 0) -> None:
        self.target_url = target_url
        self.mode = mode if mode in ("baseline", "full") else "baseline"
        self.timeout = timeout

    def is_available(self) -> bool:
        return runner_available(self.mode)

    def scan(self, target: str) -> ScanResult:  # `target` (dir) é ignorado: DAST atua na URL configurada
        if not self.target_url:
            return ScanResult(self.name, ScanStatus.SKIPPED, (),
                              "DAST desligado: defina dast.target_url no .secpipe.yml para ativar")
        ran, raw, detail = _run_zap(self.target_url, mode=self.mode, timeout=self.timeout)
        if not ran:
            return ScanResult(self.name, ScanStatus.ERROR, (), detail)  # pediu DAST e não rodou -> fail-closed
        try:
            findings = parse_zap_report(raw)
        except (json.JSONDecodeError, ValueError, TypeError) as exc:
            return ScanResult(self.name, ScanStatus.ERROR, (), f"relatorio ZAP invalido: {str(exc)[:200]}")
        return ScanResult(self.name, ScanStatus.OK, tuple(findings), "")
