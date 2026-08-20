"""Helper HTTP seguro: scheme_ok valida por HOSTNAME (não prefixo) — fecha o bypass #6 da revisão."""
from __future__ import annotations

from secpipe.adapters._http import scheme_ok


def test_https_always_ok() -> None:
    assert scheme_ok("https://api.anthropic.com/v1/messages") is True


def test_http_localhost_ok() -> None:
    assert scheme_ok("http://localhost:11434/v1") is True
    assert scheme_ok("http://127.0.0.1:8080/x") is True


def test_http_prefix_bypass_rejected() -> None:
    # o bug antigo (startswith 'http://localhost') liberava estes; agora hostname exato rejeita
    assert scheme_ok("http://localhostx.com/v1") is False
    assert scheme_ok("http://localhost.evil.com/v1") is False
    assert scheme_ok("http://127.0.0.1.evil.com/x") is False


def test_http_remote_and_other_schemes_rejected() -> None:
    assert scheme_ok("http://dojo.remote.example/api") is False
    assert scheme_ok("file:///etc/passwd") is False
    assert scheme_ok("ftp://x/y") is False
