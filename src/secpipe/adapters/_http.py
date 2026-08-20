"""HTTP helper para os adapters de rede: valida o esquema por HOSTNAME (https; http só p/ localhost exato,
via urlsplit — não por prefixo de string) e NÃO segue redirect (um downgrade/redirect cross-host jamais
reenvia a credencial). Centraliza a política keyless de rede. urlopen: S310/B310 ignorados a nível de
projeto (esquema validado aqui). Achados #5/#6/#7 da revisão."""
from __future__ import annotations

import ssl
import urllib.request
from typing import Any
from urllib.parse import urlsplit

_LOCAL = frozenset({"localhost", "127.0.0.1", "::1"})


def scheme_ok(url: str) -> bool:
    """https sempre; http SÓ para hostname localhost/127.0.0.1/::1 (comparação exata do hostname)."""
    parts = urlsplit(url)
    if parts.scheme == "https":
        return True
    return parts.scheme == "http" and (parts.hostname or "").lower() in _LOCAL


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        return None   # não segue redirect -> credencial (Authorization/x-api-key) nunca vaza num downgrade


def open_no_redirect(req: urllib.request.Request, *, timeout: int, context: ssl.SSLContext) -> Any:
    """urlopen que valida o esquema e NÃO segue redirect. Usa o `context` do chamador p/ TLS."""
    if not scheme_ok(req.full_url):
        raise ValueError("apenas https (http so localhost)")
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), _NoRedirect)
    return opener.open(req, timeout=timeout)   # S310/B310: esquema validado, sem redirect
