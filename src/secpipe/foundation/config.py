"""Config plug-and-play (ADR-0009): ZERO config funciona, com defaults seguros e FORTES.

`.secpipe.yml` é opcional — existe só para tunar, nunca é pré-requisito. Precedência: arquivo > default."""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from secpipe.domain.licenses import LicensePolicy
from secpipe.domain.rules import PolicyRule

# Default FORTE (não é versão capada): conjunto recomendado de scanners e gate em HIGH.
_DEFAULT_SCANNERS: tuple[str, ...] = ("gitleaks", "semgrep", "trivy")
_DEFAULT_BLOCK_SEVERITY = "HIGH"


@dataclass(frozen=True, slots=True)
class DefectDojoConfig:
    """Config do export DefectDojo. TOKEN nunca aqui — só via env DEFECTDOJO_TOKEN (anti-segredo-em-config)."""
    url: str = ""
    product_name: str = "secpipe"
    engagement_name: str = "ci"
    scan_type: str = "SARIF"
    minimum_severity: str = "Info"
    active: bool = True
    verified: bool = False
    reimport: bool = False
    auto_create_context: bool = True
    ca_bundle: str = ""
    timeout: int = 60


def _read_policy_rules(d: dict[str, object]) -> tuple[PolicyRule, ...]:
    policy = d.get("policy")
    rules = policy.get("rules") if isinstance(policy, dict) else None
    if not isinstance(rules, list):
        return ()
    out: list[PolicyRule] = []
    for item in rules:
        if isinstance(item, dict):
            out.append(PolicyRule(
                cwe=str(item.get("cwe", "")), tool=str(item.get("tool", "")),
                path_glob=str(item.get("path", "") or item.get("path_glob", "")),
                min_severity=str(item.get("min_severity", "")),
            ))
    return tuple(out)


def _read_defectdojo(d: dict[str, object]) -> DefectDojoConfig | None:
    dd = d.get("defectdojo")
    if not isinstance(dd, dict):
        return None
    def _s(key: str, default: str) -> str:
        val = dd.get(key)
        return str(val) if isinstance(val, str) else default
    def _b(key: str, default: bool) -> bool:
        val = dd.get(key)
        return val if isinstance(val, bool) else default
    return DefectDojoConfig(
        url=_s("url", ""), product_name=_s("product_name", "secpipe"),
        engagement_name=_s("engagement_name", "ci"), scan_type=_s("scan_type", "SARIF"),
        minimum_severity=_s("minimum_severity", "Info"), active=_b("active", True),
        verified=_b("verified", False), reimport=_b("reimport", False),
        auto_create_context=_b("auto_create_context", True), ca_bundle=_s("ca_bundle", ""),
    )


def _read_dast_target(d: dict[str, object]) -> str:
    """Aceita `dast: {target_url: ...}` (preferido) ou `dast_target: ...` (atalho). Vazio = DAST off."""
    dast = d.get("dast")
    if isinstance(dast, dict):
        return str(dast.get("target_url") or "")
    flat = d.get("dast_target")
    return flat if isinstance(flat, str) else ""


def _read_dast_mode(d: dict[str, object]) -> str:
    """`dast: {mode: baseline|full}`. Desconhecido -> baseline (o modo seguro)."""
    dast = d.get("dast")
    mode = dast.get("mode") if isinstance(dast, dict) else None
    return "full" if mode == "full" else "baseline"


def _read_dast_timeout(d: dict[str, object]) -> int:
    dast = d.get("dast")
    t = dast.get("timeout") if isinstance(dast, dict) else None
    return t if isinstance(t, int) and not isinstance(t, bool) and t > 0 else 0


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
    dast_mode: str = "baseline"  # baseline (passivo) | full (active scan — só contra alvos próprios!)
    dast_timeout: int = 0  # timeout do ZAP em segundos; 0 = default por modo
    min_scanners: int = 1  # cobertura mínima: <1 => gate fail-closed (evita falso-verde de 0 scanners)
    require_scanners: tuple[str, ...] = field(default_factory=tuple)  # scanners que DEVEM ter rodado (opt-in)
    image_target: str = ""  # ref de imagem p/ o scanner 'image' (trivy image). Vazio = desligado.
    license_policy: LicensePolicy | None = None  # política de licenças p/ o scanner 'license'. None = desligado.
    enrich_epss: bool = False  # anexar EPSS aos achados com CVE (opt-in: usa rede)
    enrich_kev: bool = False   # anexar flag CISA KEV aos achados com CVE (opt-in: usa rede)
    kev_blocks: bool = True    # achado no KEV bloqueia o gate (só morde quando enrich_kev está ligado)
    cache_dir: str = ".secpipe/cache"  # cache de EPSS/KEV (TTL) p/ modo offline
    reachability: bool = False  # anota se a dep vulnerável (SCA) é importada (só anota; opt-in offline)
    internal_prefixes: tuple[str, ...] = field(default_factory=tuple)  # p/ malicious-deps (dependency-confusion)
    defectdojo: DefectDojoConfig | None = None  # export opt-in p/ DefectDojo (token via env). None = off.
    policy_rules: tuple[PolicyRule, ...] = field(default_factory=tuple)  # policy-as-code (só ELEVA o bloqueio)

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
        reach = d.get("reachability")
        prefixes = d.get("internal_prefixes")
        return Config(
            scanners=tuple(scanners) if isinstance(scanners, list) else _DEFAULT_SCANNERS,
            block_severity=str(block) if isinstance(block, str) else _DEFAULT_BLOCK_SEVERITY,
            languages=tuple(languages) if isinstance(languages, list) else (),
            test_command=tuple(str(x) for x in test_cmd) if isinstance(test_cmd, list) else (),
            dast_target=_read_dast_target(d),
            dast_mode=_read_dast_mode(d),
            dast_timeout=_read_dast_timeout(d),
            min_scanners=mins if isinstance(mins, int) and not isinstance(mins, bool) and mins >= 0 else 1,
            require_scanners=tuple(str(x) for x in require) if isinstance(require, list) else (),
            image_target=str(d.get("image_target") or "") if isinstance(d.get("image_target"), str) else "",
            license_policy=_read_license_policy(d),
            enrich_epss=_read_enrich(d, "epss"),
            enrich_kev=_read_enrich(d, "kev"),
            kev_blocks=kev_blocks if isinstance(kev_blocks, bool) else True,
            cache_dir=str(d.get("cache_dir")) if isinstance(d.get("cache_dir"), str) else ".secpipe/cache",
            reachability=reach if isinstance(reach, bool) else False,
            internal_prefixes=tuple(str(x) for x in prefixes) if isinstance(prefixes, list) else (),
            defectdojo=_read_defectdojo(d),
            policy_rules=_read_policy_rules(d),
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
