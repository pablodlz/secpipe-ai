"""Export DefectDojo: multipart com SARIF + auth (token só env), is_available, erro redige token, config."""
from __future__ import annotations

import urllib.error
from pathlib import Path

import pytest

import secpipe.adapters.defectdojo as dd
from secpipe.adapters.defectdojo import DefectDojoExporter
from secpipe.cli import main
from secpipe.domain import Finding, Report, ScanResult, ScanStatus, Severity
from secpipe.foundation.config import Config, DefectDojoConfig


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for k in ("DEFECTDOJO_URL", "DEFECTDOJO_TOKEN", "SECPIPE_DEFECTDOJO_TOKEN"):
        monkeypatch.delenv(k, raising=False)


def _report() -> Report:
    f = Finding("bandit", "B608", Severity.HIGH, "sqli", "a.py", 1, cwe="CWE-89")
    return Report((ScanResult("bandit", ScanStatus.OK, (f,)),))


class _Resp:
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def getcode(self) -> int: return 201


def test_not_available_without_token(monkeypatch) -> None:
    assert DefectDojoExporter(DefectDojoConfig(url="https://dd")).is_available() is False  # url mas sem token


def test_export_posts_sarif_with_auth(monkeypatch) -> None:
    monkeypatch.setenv("DEFECTDOJO_URL", "https://dd")
    monkeypatch.setenv("DEFECTDOJO_TOKEN", "tok123")
    captured: dict[str, object] = {}

    def fake_urlopen(req, timeout=0, context=None):
        captured["url"] = req.full_url
        captured["headers"] = dict(req.headers)
        captured["body"] = req.data
        return _Resp()

    monkeypatch.setattr(dd.urllib.request, "urlopen", fake_urlopen)
    res = DefectDojoExporter(DefectDojoConfig()).export(_report())
    assert res.ok and "import-scan" in str(captured["url"])
    assert any("Token tok123" in str(v) for v in captured["headers"].values())  # auth do env
    body = captured["body"].decode("utf-8")  # type: ignore[union-attr]
    assert "B608" in body and "SARIF" in body   # SARIF embutido + scan_type


def test_http_error_redacts_token(monkeypatch) -> None:
    monkeypatch.setenv("DEFECTDOJO_URL", "https://dd")
    monkeypatch.setenv("DEFECTDOJO_TOKEN", "supersecret")

    def boom(req, timeout=0, context=None):
        raise urllib.error.HTTPError("u", 403, "forbidden", {}, None)  # type: ignore[arg-type]

    monkeypatch.setattr(dd.urllib.request, "urlopen", boom)
    res = DefectDojoExporter(DefectDojoConfig()).export(_report())
    assert not res.ok and "supersecret" not in res.detail and "403" in res.detail


def test_reimport_uses_reimport_endpoint(monkeypatch) -> None:
    monkeypatch.setenv("DEFECTDOJO_URL", "https://dd")
    monkeypatch.setenv("DEFECTDOJO_TOKEN", "t")
    captured: dict[str, object] = {}
    monkeypatch.setattr(dd.urllib.request, "urlopen",
                        lambda req, timeout=0, context=None: captured.setdefault("u", req.full_url) and _Resp())
    # setdefault devolve o valor -> precisamos retornar _Resp de qualquer jeito
    monkeypatch.setattr(dd.urllib.request, "urlopen",
                        lambda req, timeout=0, context=None: (captured.__setitem__("u", req.full_url), _Resp())[1])
    DefectDojoExporter(DefectDojoConfig(reimport=True)).export(_report())
    assert "reimport-scan" in str(captured["u"])


def test_config_parses_defectdojo() -> None:
    cfg = Config.from_dict({"defectdojo": {"url": "https://dd", "product_name": "app", "reimport": True}})
    assert cfg.defectdojo is not None
    assert cfg.defectdojo.url == "https://dd" and cfg.defectdojo.reimport is True
    assert Config.default().defectdojo is None


def test_cli_report_defectdojo_requires_config(tmp_path: Path, capsys) -> None:
    assert main(["report", str(tmp_path), "--defectdojo"]) == 2   # sem env -> nao configurado, fail-closed
    assert "defectdojo" in capsys.readouterr().err.lower()
