"""Exportador DefectDojo (OSS grátis, self-hosted) — opt-in, default-off. Envia o SARIF do secpipe para a
API /api/v2/import-scan/ do PRÓPRIO usuário via urllib (stdlib, sem dep). O DefectDojo tem parser nativo
'SARIF', então reusamos o SarifReporter — zero re-serialização.

EXCEÇÃO KEYED sancionada (como o PR-bot): token SÓ via env (DEFECTDOJO_TOKEN), nunca no yml/URL/log; TLS
verificado; valida esquema http/https. urlopen: S310/B310 ignorados a nível de projeto (URL validada)."""
from __future__ import annotations

import os
import ssl
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass

from secpipe.adapters.reporters import SarifReporter
from secpipe.domain import Report
from secpipe.foundation.config import DefectDojoConfig

_TOKEN_ENVS = ("DEFECTDOJO_TOKEN", "SECPIPE_DEFECTDOJO_TOKEN")


@dataclass(frozen=True, slots=True)
class ExportResult:
    ok: bool
    detail: str
    test_id: int | None = None


def _token() -> str:
    for env in _TOKEN_ENVS:
        if os.environ.get(env):
            return os.environ[env]
    return ""


def _encode_multipart(fields: dict[str, str], sarif: str) -> tuple[bytes, str]:
    """Monta multipart/form-data: campos de texto + o SARIF no campo `file`. Boundary aleatório (uuid)."""
    boundary = f"----secpipe{uuid.uuid4().hex}"
    parts: list[bytes] = []
    for key, value in fields.items():
        parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{key}\"\r\n\r\n{value}\r\n".encode())
    parts.append(
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"secpipe.sarif\"\r\n"
        "Content-Type: application/json\r\n\r\n".encode() + sarif.encode("utf-8") + b"\r\n"
    )
    parts.append(f"--{boundary}--\r\n".encode())
    return b"".join(parts), boundary


class DefectDojoExporter:
    name = "defectdojo"

    def __init__(self, config: DefectDojoConfig) -> None:
        self.config = config

    def _url(self) -> str:
        base = (os.environ.get("DEFECTDOJO_URL") or self.config.url).rstrip("/")
        endpoint = "reimport-scan" if self.config.reimport else "import-scan"
        return f"{base}/api/v2/{endpoint}/"

    def is_available(self) -> bool:
        base = os.environ.get("DEFECTDOJO_URL") or self.config.url
        return bool(base) and bool(_token())

    def export(self, report: Report) -> ExportResult:
        if not self.is_available():
            return ExportResult(False, "DefectDojo nao configurado (URL + DEFECTDOJO_TOKEN)")
        url = self._url()
        if not url.startswith(("https://", "http://")):
            return ExportResult(False, "URL do DefectDojo invalida (use http/https)")
        fields = {
            "scan_type": self.config.scan_type, "product_name": self.config.product_name,
            "engagement_name": self.config.engagement_name, "active": str(self.config.active).lower(),
            "verified": str(self.config.verified).lower(), "minimum_severity": self.config.minimum_severity,
            "auto_create_context": str(self.config.auto_create_context).lower(),
        }
        body, boundary = _encode_multipart({k: v for k, v in fields.items() if v}, SarifReporter().render(report))
        req = urllib.request.Request(url, data=body, headers={
            "Authorization": f"Token {_token()}",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        })
        ctx = ssl.create_default_context()
        if self.config.ca_bundle:
            ctx.load_verify_locations(self.config.ca_bundle)
        try:
            with urllib.request.urlopen(req, timeout=self.config.timeout, context=ctx) as resp:  # S310/B310: pyproject
                code = resp.getcode()
        except urllib.error.HTTPError as exc:
            return ExportResult(False, f"HTTP {exc.code} do DefectDojo")   # sem corpo (evita vazar token)
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            return ExportResult(False, f"falha ao enviar: {type(exc).__name__}")
        return ExportResult(True, f"enviado (HTTP {code})")
