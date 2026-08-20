"""Fetch de EPSS (api.first.org) e CISA KEV (cisa.gov) via urllib (stdlib, sem dep nova). GRÁTIS, KEYLESS.

FAIL-OPEN: erro de rede/offline => sem enrichment (nunca derruba o scan). Cache em disco com TTL para o
modo offline/determinístico. Consulta SÓ por CVE público — nenhum dado do repo sai para as APIs."""
from __future__ import annotations

import dataclasses
import json
import os
import ssl
import time
import urllib.error
import urllib.request
from collections.abc import Iterable

from secpipe.domain import Report
from secpipe.domain.enrichment import apply_enrichment, extract_cves

_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_EPSS_URL = "https://api.first.org/data/v1/epss"
_TTL_SECONDS = 86400          # 24h
_MAX_BYTES = 30_000_000       # cap defensivo (KEV ~ alguns MB)
_BATCH = 50


def _get(url: str, timeout: int) -> bytes:
    """GET https simples. Valida esquema https (anti-SSRF/anti file://). urlopen: S310/B310 ignorados a
    nível de PROJETO (pyproject) — URL fixa/validada, sem interpolação de dado do repo."""
    if not url.startswith("https://"):
        raise ValueError("apenas https")
    req = urllib.request.Request(url, headers={"User-Agent": "secpipe-enrich"})
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:  # urlopen ok: pyproject S310/B310
        return bytes(resp.read(_MAX_BYTES))


def _read_cache(path: str) -> str | None:
    try:
        if time.time() - os.path.getmtime(path) < _TTL_SECONDS:
            with open(path, encoding="utf-8") as fh:
                return fh.read()
    except OSError:
        return None
    return None


def _write_cache(path: str, text: str) -> None:
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
    except OSError:
        pass


def fetch_kev(cache_dir: str, *, timeout: int = 20) -> set[str]:
    """Conjunto de CVEs no CISA KEV (com cache). Fail-open: erro => conjunto vazio."""
    cache = os.path.join(cache_dir, "kev.json")
    raw = _read_cache(cache)
    if raw is None:
        try:
            raw = _get(_KEV_URL, timeout).decode("utf-8", "replace")
            _write_cache(cache, raw)
        except (urllib.error.URLError, OSError, ValueError, TimeoutError):
            return set()
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return set()
    vulns = data.get("vulnerabilities", []) if isinstance(data, dict) else []
    return {str(v.get("cveID", "")).upper() for v in vulns if isinstance(v, dict) and v.get("cveID")}


def fetch_epss(cves: Iterable[str], *, timeout: int = 20) -> dict[str, float]:
    """Mapa CVE -> score EPSS (0..1). Fail-open por lote. Consulta api.first.org só pelos CVEs dados."""
    unique = sorted({c.upper() for c in cves})
    out: dict[str, float] = {}
    for i in range(0, len(unique), _BATCH):
        url = f"{_EPSS_URL}?cve={','.join(unique[i:i + _BATCH])}"
        try:
            data = json.loads(_get(url, timeout).decode("utf-8", "replace"))
        except (urllib.error.URLError, OSError, ValueError, TimeoutError, json.JSONDecodeError):
            continue
        for row in data.get("data", []) if isinstance(data, dict) else []:
            if not isinstance(row, dict):
                continue
            try:
                out[str(row.get("cve", "")).upper()] = float(row.get("epss", 0))
            except (TypeError, ValueError):
                continue
    return out


def enrich_report(report: Report, cache_dir: str, *, epss: bool = True, kev: bool = True,
                  timeout: int = 20) -> Report:
    """Anota o Report com EPSS/KEV. Sem CVEs ou sem dados => retorna o Report inalterado (fail-open)."""
    cves = {c for r in report.results for f in r.findings for c in extract_cves(f)}
    if not cves:
        return report
    kev_set = fetch_kev(cache_dir, timeout=timeout) if kev else set()
    epss_map = fetch_epss(cves, timeout=timeout) if epss else {}
    if not kev_set and not epss_map:
        return report
    results = tuple(
        dataclasses.replace(r, findings=tuple(apply_enrichment(r.findings, epss_map, kev_set)))
        for r in report.results
    )
    return Report(results)
