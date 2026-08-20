"""threat-model: descoberta de superfície (determinística) + montagem/render do scaffold STRIDE."""
from __future__ import annotations

from pathlib import Path

from secpipe.application.use_cases.threat_model import (
    build_threat_model,
    discover_surface,
    render_json,
    render_markdown,
)
from secpipe.domain import Finding, Severity
from secpipe.domain.stride import Stride

_APP = '''\
import os
import subprocess

@app.route("/pay")
def pay():
    user = request.args.get("id")
    subprocess.run("echo " + user, shell=True)
    key = os.getenv("API_KEY")
    return key
'''


def _write_app(tmp_path: Path) -> str:
    (tmp_path / "app.py").write_text(_APP, encoding="utf-8")
    return str(tmp_path)


def test_discover_surface_finds_entrypoint_sink_and_asset(tmp_path: Path) -> None:
    surface = discover_surface(_write_app(tmp_path))
    labels = {e.label for e in surface}
    assert "web-route" in labels          # entrypoint
    assert "command-exec" in labels       # sink
    assert "secret" in labels             # asset
    kinds = {e.kind for e in surface}
    assert {"entrypoint", "sink", "asset"} <= kinds


def test_surface_skips_vendored_dirs(tmp_path: Path) -> None:
    vendored = tmp_path / ".venv" / "lib"
    vendored.mkdir(parents=True)
    (vendored / "evil.py").write_text("os.system('rm -rf /')\n", encoding="utf-8")
    (tmp_path / "main.py").write_text("print('ok')\n", encoding="utf-8")
    surface = discover_surface(str(tmp_path))
    assert all(".venv" not in e.file for e in surface)


def test_build_and_group_maps_findings_by_stride(tmp_path: Path) -> None:
    findings = (
        Finding(tool="bandit", rule_id="B602", severity=Severity.HIGH,
                message="subprocess shell=True", file="app.py", line=7, cwe="CWE-78"),
        Finding(tool="gitleaks", rule_id="generic-api-key", severity=Severity.HIGH,
                message="api key", file="app.py", line=8, cwe="CWE-798"),
    )
    tm = build_threat_model(_write_app(tmp_path), findings)
    grouped = tm.by_category()
    # CWE-78 -> Tampering + Elevation ; CWE-798 -> InfoDisclosure + Spoofing
    assert any(f.cwe == "CWE-78" for f in grouped[Stride.TAMPERING].findings)
    assert any(f.cwe == "CWE-78" for f in grouped[Stride.ELEVATION].findings)
    assert any(f.cwe == "CWE-798" for f in grouped[Stride.INFO_DISCLOSURE].findings)


def test_render_markdown_has_all_six_categories(tmp_path: Path) -> None:
    tm = build_threat_model(_write_app(tmp_path), ())
    md = render_markdown(tm)
    for s in Stride:
        assert s.label in md
    assert "STRIDE threat model" in md


def test_render_json_is_valid_and_structured(tmp_path: Path) -> None:
    import json
    tm = build_threat_model(_write_app(tmp_path), ())
    doc = json.loads(render_json(tm))
    assert doc["kind"] == "stride-threat-model"
    assert set(doc["categories"].keys()) == {s.value for s in Stride}
    assert all("checklist" in c for c in doc["categories"].values())
