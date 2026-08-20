"""Config plug-and-play (ADR-0009): ZERO config funciona, com defaults seguros e FORTES.

`.secpipe.yml` é opcional — existe só para tunar, nunca é pré-requisito. Precedência: arquivo > default."""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from secpipe.domain.licenses import LicensePolicy

# Default FORTE (não é versão capada): conjunto recomendado de scanners e gate em HIGH.
_DEFAULT_SCANNERS: tuple[str, ...] = ("gitleaks", "semgrep", "trivy")
_DEFAULT_BLOCK_SEVERITY = "HIGH"


def _read_dast_target(d: dict[str, object]) -> str:
    """Aceita `dast: {target_url: ...}` (preferido) ou `dast_target: ...` (atalho). Vazio = DAST off."""
    dast = d.get("dast")
    if isinstance(dast, dict):
        return str(dast.get("target_url") or "")
    flat = d.get("dast_target")
    return flat if isinstance(flat, str) else ""


def _read_enrich(d: dict[str, object], key: str) -> bool:
    """Lê `enrich: {epss: bool, kev: bool}`. Default False (evita rede no zero-config offline)."""
    enrich = d.get("enrich")
    if isinstance(enrich, dict):
        return bool(enrich.get(key, False))
    return False


def _read_license_policy(d: dict[str, object]) -> LicensePolicy | None:
    """Lê `licenses: {deny, allow, unknown_is}`. None se ausente (scanner 'license' desligado)."""
    lic = d.get("licenses")
    if not isinstance(lic, dict):
        return None
    deny = lic.get("deny")
    allow = lic.get("allow")
    unknown = lic.get("unknown_is")
    return LicensePolicy(
        deny=tuple(str(x) for x in deny) if isinstance(deny, list) else (),
        allow=tuple(str(x) for x in allow) if isinstance(allow, list) else (),
        unknown_is=str(unknown).upper() if isinstance(unknown, str) else "MEDIUM",
    )


@dataclass(frozen=True, slots=True)
class Config:
    scanners: tuple[str, ...] = _DEFAULT_SCANNERS
    block_severity: str = _DEFAULT_BLOCK_SEVERITY
    languages: tuple[str, ...] = field(default_factory=tuple)  # vazio = auto-detect (Fase 1)
    test_command: tuple[str, ...] = field(default_factory=tuple)  # ex.: ["pytest","-q"] — usado no `verify`
    dast_target: str = ""  # URL alvo do DAST (ZAP baseline). Vazio = DAST desligado (estático plug-and-play).
    min_scanners: int = 1  # cobertura mínima: <1 => gate fail-closed (evita falso-verde de 0 scanners)
    require_scanners: tuple[str, ...] = field(default_factory=tuple)  # scanners que DEVEM ter rodado (opt-in)
    image_target: str = ""  # ref de imagem p/ o scanner 'image' (trivy image). Vazio = desligado.
    license_policy: LicensePolicy | None = None  # política de licenças p/ o scanner 'license'. None = desligado.
    enrich_epss: bool = False  # anexar EPSS aos achados com CVE (opt-in: usa rede)
    enrich_kev: bool = False   # anexar flag CISA KEV aos achados com CVE (opt-in: usa rede)
    kev_blocks: bool = True    # achado no KEV bloqueia o gate (só morde quando enrich_kev está ligado)
    cache_dir: str = ".secpipe/cache"  # cache de EPSS/KEV (TTL) p/ modo offline
    internal_prefixes: tuple[str, ...] = field(default_factory=tuple)  # p/ malicious-deps (dependency-confusion)

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
        require = d.get("require")
        mins = d.get("min_scanners")
        kev_blocks = d.get("kev_blocks")
        prefixes = d.get("internal_prefixes")
        return Config(
            scanners=tuple(scanners) if isinstance(scanners, list) else _DEFAULT_SCANNERS,
            block_severity=str(block) if isinstance(block, str) else _DEFAULT_BLOCK_SEVERITY,
            languages=tuple(languages) if isinstance(languages, list) else (),
            test_command=tuple(str(x) for x in test_cmd) if isinstance(test_cmd, list) else (),
            dast_target=_read_dast_target(d),
            min_scanners=mins if isinstance(mins, int) and not isinstance(mins, bool) and mins >= 0 else 1,
            require_scanners=tuple(str(x) for x in require) if isinstance(require, list) else (),
            image_target=str(d.get("image_target") or "") if isinstance(d.get("image_target"), str) else "",
            license_policy=_read_license_policy(d),
            enrich_epss=_read_enrich(d, "epss"),
            enrich_kev=_read_enrich(d, "kev"),
            kev_blocks=kev_blocks if isinstance(kev_blocks, bool) else True,
            cache_dir=str(d.get("cache_dir")) if isinstance(d.get("cache_dir"), str) else ".secpipe/cache",
            internal_prefixes=tuple(str(x) for x in prefixes) if isinstance(prefixes, list) else (),
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
