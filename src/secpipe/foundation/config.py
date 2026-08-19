"""Config plug-and-play (ADR-0009): ZERO config funciona, com defaults seguros e FORTES.

`.secpipe.yml` é opcional — existe só para tunar, nunca é pré-requisito. Precedência: arquivo > default."""
from __future__ import annotations

import os
from dataclasses import dataclass, field

# Default FORTE (não é versão capada): conjunto recomendado de scanners e gate em HIGH.
_DEFAULT_SCANNERS: tuple[str, ...] = ("gitleaks", "semgrep", "trivy")
_DEFAULT_BLOCK_SEVERITY = "HIGH"


@dataclass(frozen=True, slots=True)
class Config:
    scanners: tuple[str, ...] = _DEFAULT_SCANNERS
    block_severity: str = _DEFAULT_BLOCK_SEVERITY
    languages: tuple[str, ...] = field(default_factory=tuple)  # vazio = auto-detect (Fase 1)
    test_command: tuple[str, ...] = field(default_factory=tuple)  # ex.: ["pytest","-q"] — usado no `verify`

    @staticmethod
    def default() -> Config:
        """Zero-config: o modo plug-and-play. Retorna os defaults fortes."""
        return Config()

    @staticmethod
    def from_dict(data: dict[str, object]) -> Config:
        d = data or {}
        scanners = d.get("scanners")
        languages = d.get("languages")
        block = d.get("block_severity")
        test_cmd = d.get("test_command")
        return Config(
            scanners=tuple(scanners) if isinstance(scanners, list) else _DEFAULT_SCANNERS,
            block_severity=str(block) if isinstance(block, str) else _DEFAULT_BLOCK_SEVERITY,
            languages=tuple(languages) if isinstance(languages, list) else (),
            test_command=tuple(str(x) for x in test_cmd) if isinstance(test_cmd, list) else (),
        )

    @staticmethod
    def load(path: str | None = None) -> Config:
        """Carrega `.secpipe.yml` se existir; senão, default (plug-and-play)."""
        candidate = path or ".secpipe.yml"
        if not os.path.isfile(candidate):
            return Config.default()
        try:
            import yaml  # dependência opcional; só necessária se há arquivo de config
        except ImportError as exc:  # pragma: no cover - caminho de ambiente
            raise RuntimeError(
                "Config encontrada mas PyYAML não está instalado. Instale 'pyyaml' ou remova o arquivo."
            ) from exc
        with open(candidate, encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        return Config.from_dict(data)
