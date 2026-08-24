#!/usr/bin/env python3
"""Setup do secpipe — cross-platform (Windows / Linux / macOS).

Cria um venv (.venv), instala o pacote + ferramentas de dev, e baixa os scanners externos que não
vão no git (gitleaks, trivy) para ./tools. semgrep é instalado via pip em Linux/macOS (não roda nativo
no Windows — use o container). Idempotente: pula o que já existe.

Uso:
    python install.py                # tudo (venv + deps + scanners)
    python install.py --no-venv      # instala no interpretador atual (sem criar .venv)
    python install.py --no-tools     # não baixa gitleaks/trivy
    python install.py --no-semgrep   # não tenta instalar semgrep
"""
from __future__ import annotations

import argparse
import io
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV = ROOT / ".venv"
TOOLS = ROOT / "tools"
UA = {"User-Agent": "secpipe-installer"}


def _run(cmd: list[str]) -> None:
    print("+", " ".join(str(c) for c in cmd))
    subprocess.check_call(cmd)


def _venv_python(venv: Path) -> Path:
    return venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def ensure_python(no_venv: bool) -> Path:
    if no_venv:
        return Path(sys.executable)
    if not VENV.exists():
        print(f"[venv] criando {VENV}")
        _run([sys.executable, "-m", "venv", str(VENV)])
    py = _venv_python(VENV)
    _run([str(py), "-m", "pip", "install", "--quiet", "--upgrade", "pip"])
    return py


def install_python_deps(py: Path, no_semgrep: bool) -> None:
    print("[pip] instalando o pacote + dev tools (ruff/mypy/pytest/bandit/pip-audit)")
    _run([str(py), "-m", "pip", "install", "--quiet", "-e", ".[dev]"])
    if no_semgrep:
        return
    if platform.system() == "Windows":
        print("[!] semgrep/codemodder nao rodam nativo no Windows — pulando (use o container Linux/CI).")
        return
    try:
        print("[pip] instalando semgrep + codemodder")
        _run([str(py), "-m", "pip", "install", "--quiet", "semgrep", "codemodder"])
    except subprocess.CalledProcessError:
        print("[!] falha ao instalar semgrep/codemodder — siga sem eles (opcionais).")


def _needles() -> dict[str, tuple[tuple[str, ...], str]]:
    """Padrões do asset de release por plataforma -> (needles, nome-do-binario)."""
    sysname = platform.system().lower()          # windows / linux / darwin
    arm = platform.machine().lower() in ("arm64", "aarch64")
    win = sysname == "windows"
    ext = ".zip" if win else ".tar.gz"
    gl_os = {"windows": "windows", "linux": "linux", "darwin": "darwin"}[sysname]
    tv_os = {"windows": "windows", "linux": "linux", "darwin": "macos"}[sysname]
    # hadolint distribui BINÁRIO BRUTO (hadolint-Linux-x86_64), não tar/zip — tratado em _extract_binary.
    hd_arch = "arm64" if arm else "x86_64"
    return {
        "gitleaks/gitleaks": (("gitleaks", gl_os, "arm64" if arm else "x64", ext), "gitleaks"),
        "aquasecurity/trivy": (("trivy", tv_os, "arm64" if arm else "64bit", ext), "trivy"),
        "hadolint/hadolint": (("hadolint", sysname, hd_arch), "hadolint"),  # lint de Dockerfile (IaC)
    }


def _latest_asset(repo: str, needles: tuple[str, ...]) -> tuple[str, str] | None:
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    data = json.load(urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=90))
    for asset in data.get("assets", []):
        name = asset["name"].lower()
        if all(n in name for n in needles):
            return asset["browser_download_url"], asset["name"]
    return None


def _extract_binary(blob: bytes, asset_name: str, binary: str) -> None:
    TOOLS.mkdir(exist_ok=True)
    exe = binary + (".exe" if os.name == "nt" else "")
    low = asset_name.lower()
    # binário BRUTO (ex.: hadolint-Linux-x86_64) — sem arquivo container: grava o blob direto.
    if not (low.endswith(".zip") or low.endswith(".tar.gz") or low.endswith(".tgz")):
        (TOOLS / exe).write_bytes(blob)
        if os.name != "nt":
            (TOOLS / exe).chmod(0o755)
        return
    if asset_name.lower().endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            for m in zf.namelist():
                if Path(m).name.lower() == exe:
                    zf.getinfo(m).filename = exe
                    zf.extract(m, TOOLS)
                    break
    else:
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
            for m in tf.getmembers():
                if Path(m.name).name == exe:
                    m.name = exe
                    tf.extract(m, TOOLS)  # membro unico, nome ja reduzido ao basename (seguro)
                    break
    target = TOOLS / exe
    if target.exists() and os.name != "nt":
        target.chmod(0o755)


def download_scanners() -> None:
    for repo, (needles, binary) in _needles().items():
        exe = binary + (".exe" if os.name == "nt" else "")
        if shutil.which(binary) or (TOOLS / exe).exists():
            print(f"[tools] {binary} ja disponivel — pulando")
            continue
        try:
            found = _latest_asset(repo, needles)
            if not found:
                print(f"[!] {repo}: asset para esta plataforma nao encontrado — instale manualmente.")
                continue
            url, name = found
            print(f"[tools] baixando {name}")
            blob = urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=180).read()
            _extract_binary(blob, name, binary)
            print(f"[tools] {binary} -> {TOOLS}")
        except Exception as exc:  # setup best-effort: segue sem o tool se o download falhar
            print(f"[!] falha ao baixar {binary}: {exc}")


def print_next_steps(py: Path, no_tools: bool) -> None:
    win = os.name == "nt"
    act = ".venv\\Scripts\\activate" if win else "source .venv/bin/activate"
    print("\n== pronto ==")
    print(f"1) ative o venv:   {act}")
    if not no_tools:
        addpath = (f'$env:Path = "{TOOLS};$env:Path"' if win else f'export PATH="{TOOLS}:$PATH"')
        print(f"2) tools no PATH:  {addpath}")
    print("3) verifique:      secpipe doctor")
    print("4) rode:           secpipe scan .")


def main() -> int:
    ap = argparse.ArgumentParser(description="Setup do secpipe (cross-platform).")
    ap.add_argument("--no-venv", action="store_true", help="instala no interpretador atual")
    ap.add_argument("--no-tools", action="store_true", help="nao baixa gitleaks/trivy")
    ap.add_argument("--no-semgrep", action="store_true", help="nao instala semgrep")
    args = ap.parse_args()

    py = ensure_python(args.no_venv)
    install_python_deps(py, args.no_semgrep)
    if not args.no_tools:
        download_scanners()
    print_next_steps(py, args.no_tools)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
