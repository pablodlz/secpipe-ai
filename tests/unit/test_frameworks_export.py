"""Detecção de framework, marcadores específicos e export OWASP Threat Dragon (determinístico)."""
from __future__ import annotations

import json
from pathlib import Path

from secpipe.application.use_cases.threat_export import render_threat_dragon
from secpipe.application.use_cases.threat_model import (
    SurfaceElement,
    ThreatModel,
    detect_frameworks,
)
from secpipe.domain import Finding, Severity
from secpipe.domain.frameworks import Framework, detect, markers_for
from secpipe.domain.stride import Stride


def test_detect_by_manifest() -> None:
    assert Framework.DJANGO in detect({"requirements.txt": "django==4.0\nrequests"})
    assert Framework.EXPRESS in detect({"package.json": '{"dependencies":{"express":"^4"}}'})
    assert detect({"requirements.txt": "requests\nnumpy"}) == frozenset()


def test_markers_for_django() -> None:
    labels = {m[1] for m in markers_for(frozenset({Framework.DJANGO}))}
    assert "django-route" in labels and "django-raw-sql" in labels
    assert markers_for(frozenset()) == ()


def test_detect_frameworks_reads_root(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("fastapi==0.110\nuvicorn\n", encoding="utf-8")
    assert "fastapi" in detect_frameworks(str(tmp_path))


def _tm() -> ThreatModel:
    el = SurfaceElement("entrypoint", "django-route", "urls.py", 3, "path('x')",
                        frozenset({Stride.TAMPERING}), "django")
    findings = (Finding("bandit", "B608", Severity.HIGH, '"; import os #evil', "views.py", 9, cwe="CWE-89"),)
    return ThreatModel(target="app", surface=(el,), findings=findings)


def test_threat_dragon_valid_and_deterministic() -> None:
    a = render_threat_dragon(_tm())
    b = render_threat_dragon(_tm())
    assert a == b   # IDs determinísticos
    doc = json.loads(a)
    assert doc["summary"]["threats"][0]["type"] == "Tampering"   # CWE-89 -> Tampering
    assert doc["detail"]["diagrams"][0]["cells"][0]["shape"] == "tm.Actor"
    # payload malicioso fica só como string escapada (JSON válido, nada executado)
    assert "import os" in doc["summary"]["threats"][0]["description"]
