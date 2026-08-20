"""Export do threat model para OWASP Threat Dragon (JSON). Determinístico (IDs derivados de sha256 -> saída
reproduzível). Todo texto dinâmico é escapado por json.dumps (nada é executado)."""
from __future__ import annotations

import hashlib
import json

from secpipe.application.use_cases.threat_model import ThreatModel
from secpipe.domain.stride import Stride, categorize

_SHAPE = {"entrypoint": "tm.Actor", "sink": "tm.Process", "asset": "tm.Store"}
_STRIDE_TYPE = {
    Stride.SPOOFING: "Spoofing", Stride.TAMPERING: "Tampering", Stride.REPUDIATION: "Repudiation",
    Stride.INFO_DISCLOSURE: "Information disclosure", Stride.DENIAL_OF_SERVICE: "Denial of service",
    Stride.ELEVATION: "Elevation of privilege",
}


def _stable_id(*parts: str) -> str:
    h = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def _sanitize(text: str) -> str:
    return "".join(c for c in text if c >= " ").replace("\t", " ")[:200]


def _threat_type(cwe: str, rule_id: str, message: str) -> str:
    cats = categorize(cwe, rule_id, message)
    for s in Stride:               # ordem canônica
        if s in cats:
            return _STRIDE_TYPE[s]
    return "Tampering"


def render_threat_dragon(tm: ThreatModel) -> str:
    cells = [
        {
            "id": _stable_id(e.kind, e.file, str(e.line), e.label),
            "shape": _SHAPE.get(e.kind, "tm.Process"),
            "data": {"name": _sanitize(f"{e.label} @ {e.file}:{e.line}"), "type": _SHAPE.get(e.kind, "tm.Process")},
        }
        for e in tm.surface[:300]
    ]
    threats = [
        {
            "id": _stable_id(f.fingerprint),
            "title": _sanitize(f.rule_id),
            "status": "Open",
            "severity": f.severity.name.capitalize(),
            "type": _threat_type(f.cwe, f.rule_id, f.message),
            "description": _sanitize(f.message),
        }
        for f in tm.findings
    ]
    doc = {
        "version": "2.0",
        "summary": {"title": f"secpipe STRIDE — {_sanitize(tm.target)}", "owner": "secpipe", "threats": threats},
        "detail": {"contributors": [], "diagrams": [
            {"title": "STRIDE", "diagramType": "STRIDE", "id": 0, "cells": cells},
        ]},
    }
    return json.dumps(doc, ensure_ascii=False, indent=2)
