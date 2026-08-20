"""Adapter MaliciousDeps — typosquat / install-hook suspeito / dependency-confusion. OFFLINE, GRÁTIS,
KEYLESS, determinístico. Cobre o vetor de supply-chain que scanners de CVE não pegam (pacote malicioso
novo, sem CVE). Análise ESTÁTICA de manifesto — NUNCA instala/executa pacote."""
from __future__ import annotations

import os

from secpipe.domain import Finding, ScanResult, ScanStatus, Severity
from secpipe.domain.typosquat import (
    _NPM_TOP,
    _PYPI_TOP,
    nearest_typosquat,
    parse_package_json,
    parse_requirements,
)

NAME = "malicious-deps"


class MaliciousDepsScanner:
    name = NAME

    def __init__(self, internal_prefixes: tuple[str, ...] = ()) -> None:
        self.internal_prefixes = internal_prefixes

    def is_available(self) -> bool:
        return True  # heurística offline pura — sempre executável

    def _confusion(self, dep: str, manifest: str) -> Finding | None:
        for prefix in self.internal_prefixes:
            if prefix and dep.startswith(prefix):
                return Finding(NAME, "dependency-confusion", Severity.HIGH,
                               f"'{dep}' tem prefixo interno '{prefix}' mas vem do indice publico "
                               "(dependency-confusion?)", manifest, 0, cwe="CWE-1357")
        return None

    def scan(self, target: str) -> ScanResult:
        findings: list[Finding] = []
        scanned_any = False

        req = os.path.join(target, "requirements.txt")
        if os.path.isfile(req):
            scanned_any = True
            with open(req, encoding="utf-8", errors="replace") as fh:
                for dep in parse_requirements(fh.read()):
                    imitated = nearest_typosquat(dep, _PYPI_TOP)
                    if imitated:
                        findings.append(Finding(NAME, "typosquat", Severity.HIGH,
                                                f"'{dep}' imita o pacote popular '{imitated}' (typosquat?)",
                                                "requirements.txt", 0, cwe="CWE-1357"))
                    conf = self._confusion(dep, "requirements.txt")
                    if conf:
                        findings.append(conf)

        pkg = os.path.join(target, "package.json")
        if os.path.isfile(pkg):
            scanned_any = True
            with open(pkg, encoding="utf-8", errors="replace") as fh:
                deps, hooks = parse_package_json(fh.read())
            for dep in deps:
                imitated = nearest_typosquat(dep, _NPM_TOP)
                if imitated:
                    findings.append(Finding(NAME, "typosquat", Severity.HIGH,
                                            f"'{dep}' imita o pacote popular '{imitated}' (typosquat?)",
                                            "package.json", 0, cwe="CWE-1357"))
                conf = self._confusion(dep, "package.json")
                if conf:
                    findings.append(conf)
            for hook in hooks:
                findings.append(Finding(NAME, "install-hook", Severity.MEDIUM,
                                        f"package.json define script '{hook}' (vetor comum de malware — revise)",
                                        "package.json", 0, cwe="CWE-506"))

        if not scanned_any:
            return ScanResult(self.name, ScanStatus.SKIPPED, (), "sem requirements.txt/package.json")
        return ScanResult(self.name, ScanStatus.OK, tuple(findings), "")
