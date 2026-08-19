"""Parser SARIF 2.1.0 -> Finding[] (contrato FEAT-001). Reusado por qualquer scanner que emita SARIF
(Semgrep, Trivy, CodeQL...). É a razão de o SARIF ser o formato de interop (ADR-0004)."""
from __future__ import annotations

import json
import re
from typing import Any

from secpipe.adapters.base import run_tool
from secpipe.domain import Finding, ScanResult, ScanStatus, Severity

_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)
# SARIF level -> nossa severidade (fallback quando não há security-severity numérica).
_LEVEL = {"error": Severity.HIGH, "warning": Severity.MEDIUM, "note": Severity.LOW, "none": Severity.INFO}


def _sev_from_score(raw: str) -> Severity | None:
    """Convenção GitHub `security-severity` (0-10) -> banda. None se não numérica."""
    try:
        score = float(raw)
    except (TypeError, ValueError):
        return None
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFO


def _first_cwe(*sources: Any) -> str:
    """Extrai o primeiro CWE-nnn encontrado em qualquer das fontes (str, lista ou dict)."""
    for src in sources:
        for text in _flatten_strings(src):
            match = _CWE_RE.search(text)
            if match:
                return match.group(0).upper()
    return ""


def _flatten_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        out: list[str] = []
        for v in value.values():
            out.extend(_flatten_strings(v))
        return out
    if isinstance(value, (list, tuple)):
        out2: list[str] = []
        for v in value:
            out2.extend(_flatten_strings(v))
        return out2
    return []


def _props(obj: Any) -> dict[str, Any]:
    props = obj.get("properties") if isinstance(obj, dict) else None
    return props if isinstance(props, dict) else {}


def _rule_index(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    driver = (run.get("tool") or {}).get("driver") or {}
    rules = driver.get("rules") or []
    index: dict[str, dict[str, Any]] = {}
    for rule in rules:
        if isinstance(rule, dict) and isinstance(rule.get("id"), str):
            index[rule["id"]] = rule
    return index


def _location(result: dict[str, Any]) -> tuple[str, int]:
    locations = result.get("locations") or []
    if not locations or not isinstance(locations[0], dict):
        return "", 0
    phys = locations[0].get("physicalLocation") or {}
    uri = ((phys.get("artifactLocation") or {}).get("uri")) or ""
    start = (phys.get("region") or {}).get("startLine") or 0
    try:
        line = int(start)
    except (TypeError, ValueError):
        line = 0
    return str(uri), line


def parse_sarif(raw: str, default_tool: str) -> list[Finding]:
    """Converte um documento SARIF em Findings normalizados. Lança json.JSONDecodeError se inválido
    (o adapter trata como ScanStatus.ERROR -> gate fail-closed)."""
    if not raw.strip():
        return []
    doc = json.loads(raw)
    findings: list[Finding] = []
    for run in doc.get("runs") or []:
        if not isinstance(run, dict):
            continue
        tool_name = (((run.get("tool") or {}).get("driver") or {}).get("name")) or default_tool
        rules = _rule_index(run)
        for result in run.get("results") or []:
            if not isinstance(result, dict):
                continue
            rule_id = str(result.get("ruleId") or result.get("rule", {}).get("id") or "unknown")
            rule = rules.get(rule_id, {})
            message = str((result.get("message") or {}).get("text") or "")
            file, line = _location(result)
            cwe = _first_cwe(
                _props(result).get("cwe"), _props(rule).get("cwe"),
                _props(rule).get("tags"), rule.get("name"), message,
            )
            # severidade: security-severity numérica (result > rule) > level SARIF
            severity = (
                _sev_from_score(str(_props(result).get("security-severity", "")))
                or _sev_from_score(str(_props(rule).get("security-severity", "")))
                or _LEVEL.get(str(result.get("level") or "").lower(), Severity.MEDIUM)
            )
            findings.append(
                Finding(
                    tool=str(tool_name), rule_id=rule_id, severity=severity,
                    message=message, file=file, line=line, cwe=cwe,
                )
            )
    return findings


def run_sarif_scanner(
    name: str, binary: str, args: list[str], *, timeout: int = 300
) -> ScanResult:
    """Roda um scanner que emite SARIF no stdout e normaliza. Ausente -> SKIPPED; falha/saída
    inválida -> ERROR (gate fail-closed). Usado por Semgrep, Trivy e qualquer outro que fale SARIF."""
    run = run_tool(binary, args, timeout=timeout)
    if run.missing:
        return ScanResult(name, ScanStatus.SKIPPED, (), "ferramenta ausente no PATH")
    if run.timed_out:
        return ScanResult(name, ScanStatus.ERROR, (), "timeout")
    try:
        findings = parse_sarif(run.stdout, name)
    except (json.JSONDecodeError, ValueError, TypeError) as exc:
        detail = (run.stderr or str(exc)).strip()[:300]
        return ScanResult(name, ScanStatus.ERROR, (), f"saída SARIF inválida: {detail}")
    return ScanResult(name, ScanStatus.OK, tuple(findings), "")
