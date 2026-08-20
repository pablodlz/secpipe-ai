"""Adapter TrivyImage — escaneia a IMAGEM de container final (SO + libs em camadas + misconfig + segredos
embutidos), não só o filesystem do repo. Trivy já está embutido; falta o modo. GRÁTIS, KEYLESS.

Opt-in: precisa de `image_target` (ref da imagem/tarball). Sem ref -> SKIPPED (preserva o estático)."""
from __future__ import annotations

from secpipe.adapters.base import tool_on_path
from secpipe.adapters.sarif import run_sarif_scanner
from secpipe.domain import ScanResult, ScanStatus

NAME = "image"
BINARY = "trivy"


class TrivyImageScanner:
    name = NAME

    def __init__(self, image_ref: str = "") -> None:
        self.image_ref = image_ref

    def is_available(self) -> bool:
        return tool_on_path(BINARY)

    def scan(self, target: str) -> ScanResult:  # `target` (dir) é ignorado: escaneia a imagem configurada
        if not self.image_ref:
            return ScanResult(self.name, ScanStatus.SKIPPED, (), "sem image_target no .secpipe.yml")
        return run_sarif_scanner(
            self.name, BINARY, ["image", "--format", "sarif", "--quiet", self.image_ref], timeout=900,
        )
