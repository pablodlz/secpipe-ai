"""Detecção de linguagem para escolher scanners no `secpipe init` (FEAT-010). Pura, sem I/O."""
from __future__ import annotations

from collections.abc import Iterable

# extensão -> linguagem
_EXT: dict[str, str] = {
    ".py": "python", ".js": "javascript", ".ts": "javascript", ".jsx": "javascript",
    ".tsx": "javascript", ".go": "go", ".rb": "ruby", ".php": "php", ".java": "java",
    ".rs": "rust", ".cs": "csharp", ".kt": "kotlin",
    ".tf": "terraform", ".tfvars": "terraform",   # IaC (Terraform)
}
# arquivo-marcador -> linguagem
_MARKERS: dict[str, str] = {
    "pyproject.toml": "python", "setup.py": "python", "requirements.txt": "python",
    "package.json": "javascript", "package-lock.json": "javascript", "go.mod": "go", "gemfile": "ruby",
    "composer.json": "php", "pom.xml": "java", "build.gradle": "java", "cargo.toml": "rust",
    "dockerfile": "docker", "docker-compose.yml": "docker", "docker-compose.yaml": "docker",   # IaC (containers)
}


def _basename(path: str) -> str:
    return path.replace("\\", "/").rsplit("/", 1)[-1]


def detect_from_paths(relpaths: Iterable[str]) -> set[str]:
    """Linguagens presentes, a partir de nomes de arquivo (marcadores) e extensões."""
    langs: set[str] = set()
    for path in relpaths:
        name = _basename(path)
        low = name.lower()
        if low in _MARKERS:
            langs.add(_MARKERS[low])
        dot = name.rfind(".")
        if dot >= 0:
            ext = name[dot:].lower()
            if ext in _EXT:
                langs.add(_EXT[ext])
    return langs


def scanners_for(langs: set[str]) -> list[str]:
    """Scanners recomendados. Núcleo multi-linguagem sempre; específicos por linguagem/stack quando houver.
    Add-only: nunca reordena o núcleo (preserva os testes)."""
    scanners = ["gitleaks", "semgrep", "trivy"]   # secret · SAST · SCA/IaC (multi-linguagem)
    if "python" in langs:
        scanners += ["bandit", "pip-audit"]        # SAST/SCA específicos de Python
    if {"terraform", "docker"} & langs:
        scanners.append("checkov")                 # IaC SAST (Terraform/K8s/CFN/Dockerfile)
    if "docker" in langs:
        scanners.append("hadolint")                # lint de Dockerfile
    if "go" in langs:
        scanners.append("gosec")                   # SAST de Go (requer toolchain go)
    if "javascript" in langs:
        scanners.append("npm-audit")               # SCA JS (requer npm + package-lock.json)
    return scanners
