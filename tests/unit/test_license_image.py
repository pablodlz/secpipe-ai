"""License compliance (política deny/allow + parser trivy) e TrivyImage (opt-in via image_target)."""
from __future__ import annotations

import json

from secpipe.adapters.license_scan import parse_trivy_licenses
from secpipe.adapters.trivy_image import TrivyImageScanner
from secpipe.domain import ScanStatus, Severity
from secpipe.domain.licenses import LicensePolicy, classify_license
from secpipe.foundation.config import Config


def test_classify_deny_allow_unknown() -> None:
    pol = LicensePolicy(deny=("GPL-3.0",), allow=("MIT", "Apache-2.0"), unknown_is="MEDIUM")
    assert classify_license("GPL-3.0", pol) is Severity.HIGH
    assert classify_license("mit", pol) is None                 # case-insensitive allow
    assert classify_license("", pol) is Severity.MEDIUM         # desconhecida
    assert classify_license("BSD-3-Clause", pol) is Severity.MEDIUM  # allowlist ativo, fora do allow


def test_classify_denylist_only() -> None:
    pol = LicensePolicy(deny=("AGPL-3.0",), unknown_is="LOW")
    assert classify_license("MIT", pol) is None                 # denylist: nao negada -> ok
    assert classify_license("AGPL-3.0", pol) is Severity.HIGH
    assert classify_license("NOASSERTION", pol) is Severity.LOW


def test_parse_trivy_licenses() -> None:
    doc = {"Results": [{"Target": "python", "Licenses": [
        {"Name": "GPL-3.0", "PkgName": "foo", "FilePath": "requirements.txt"},
        {"Name": "MIT", "PkgName": "bar"},
    ]}]}
    pol = LicensePolicy(deny=("GPL-3.0",), allow=("MIT",))
    findings = parse_trivy_licenses(json.dumps(doc), pol)
    assert len(findings) == 1  # só a GPL vira finding
    assert findings[0].rule_id == "license/GPL-3.0" and findings[0].severity is Severity.HIGH


def test_trivy_image_skips_without_target() -> None:
    assert TrivyImageScanner("").scan(".").status is ScanStatus.SKIPPED


def test_config_parses_licenses_and_image() -> None:
    cfg = Config.from_dict({
        "image_target": "ghcr.io/x/y:1",
        "licenses": {"deny": ["GPL-3.0"], "allow": ["MIT"], "unknown_is": "HIGH"},
    })
    assert cfg.image_target == "ghcr.io/x/y:1"
    assert cfg.license_policy is not None
    assert cfg.license_policy.deny == ("GPL-3.0",) and cfg.license_policy.unknown_is == "HIGH"
    assert Config.default().license_policy is None and Config.default().image_target == ""
