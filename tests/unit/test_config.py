"""Plug-and-play: zero-config retorna defaults fortes; from_dict permite tunar."""
from __future__ import annotations

from secpipe.foundation.config import Config


def test_zero_config_returns_strong_defaults() -> None:
    cfg = Config.load("does-not-exist.yml")
    assert "gitleaks" in cfg.scanners
    assert cfg.block_severity == "HIGH"


def test_from_dict_overrides() -> None:
    cfg = Config.from_dict({"scanners": ["gitleaks"], "block_severity": "MEDIUM"})
    assert cfg.scanners == ("gitleaks",)
    assert cfg.block_severity == "MEDIUM"
