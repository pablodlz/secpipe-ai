"""Domínio puro: detecção heurística e OFFLINE de dependência maliciosa/typosquat/dependency-confusion —
o vetor de supply-chain que scanners de CVE NÃO pegam (o pacote malicioso é novo, sem CVE).

Sinais: (a) nome a distância de edição 1 de um pacote popular (typosquat); (b) install-hook suspeito em
package.json (preinstall/postinstall — vetor comum de malware); (c) prefixo interno resolvido do índice
público (dependency-confusion). Top-lists embutidas (dados auditáveis). Sem I/O, sem rede."""
from __future__ import annotations

import json

# Top pacotes (curado; os mais populares/typosquatados). Dados revisáveis — ampliar periodicamente.
_PYPI_TOP: frozenset[str] = frozenset({
    "requests", "urllib3", "setuptools", "certifi", "charset-normalizer", "idna", "numpy", "pandas",
    "python-dateutil", "pyyaml", "six", "boto3", "botocore", "click", "flask", "django", "fastapi",
    "sqlalchemy", "pydantic", "jinja2", "cryptography", "pytest", "wheel", "pip", "scipy", "matplotlib",
    "torch", "tensorflow", "scikit-learn", "beautifulsoup4", "lxml", "aiohttp", "httpx", "starlette",
    "uvicorn", "gunicorn", "celery", "redis", "psycopg2", "pillow", "openpyxl", "colorama", "tqdm",
    "rich", "typer", "pytz", "packaging", "attrs", "markupsafe", "werkzeug", "google-api-python-client",
})
_NPM_TOP: frozenset[str] = frozenset({
    "lodash", "react", "react-dom", "express", "chalk", "commander", "axios", "webpack", "typescript",
    "vue", "angular", "next", "eslint", "prettier", "jest", "mocha", "babel", "moment", "dayjs", "uuid",
    "dotenv", "cors", "body-parser", "mongoose", "sequelize", "jsonwebtoken", "bcrypt", "socket.io",
    "rxjs", "redux", "tslib", "yargs", "glob", "minimatch", "semver", "debug", "async", "request",
    "node-fetch", "cross-env", "rimraf", "nodemon", "ts-node", "esbuild", "vite", "zod", "ws", "ejs",
})
_HOOK_KEYS = ("preinstall", "postinstall", "install")


def osa_distance(a: str, b: str, cap: int = 2) -> int:
    """Distância de edição (Optimal String Alignment: inclui transposição de adjacentes). Curto-circuita em `cap`."""
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    la, lb = len(a), len(b)
    prev2: list[int] = []
    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        cur = [i] + [0] * lb
        best = cur[0]
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
            best = min(best, cur[j])
        if best > cap:
            return cap + 1
        prev2, prev = prev, cur
    return prev[lb]


def _norm(name: str) -> str:
    return name.strip().lower().replace("_", "-")


def nearest_typosquat(name: str, top: frozenset[str]) -> str | None:
    """Se `name` está a distância 1 de um nome popular (mas != ele e não é popular), devolve o alvo imitado."""
    n = _norm(name)
    if not n or n in top:
        return None
    for legit in top:
        if abs(len(legit) - len(n)) <= 1 and osa_distance(n, legit, cap=1) == 1:
            return legit
    return None


def parse_requirements(text: str) -> list[str]:
    """Nomes de pacote de um requirements.txt (ignora versões/markers/comentários/opções)."""
    names: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "-", "git+", "http")):
            continue
        name = line.split(";")[0].split("[")[0]
        for sep in ("==", ">=", "<=", "~=", "!=", ">", "<", "="):
            name = name.split(sep)[0]
        name = name.strip()
        if name:
            names.append(name)
    return names


def parse_package_json(text: str) -> tuple[list[str], list[str]]:
    """(dependências, install-hooks presentes) de um package.json. Tolerante a JSON inválido."""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return [], []
    if not isinstance(data, dict):
        return [], []
    deps: list[str] = []
    for key in ("dependencies", "devDependencies", "optionalDependencies"):
        section = data.get(key)
        if isinstance(section, dict):
            deps.extend(str(k) for k in section)
    scripts = data.get("scripts")
    hooks = [h for h in _HOOK_KEYS if isinstance(scripts, dict) and h in scripts] if scripts else []
    return deps, hooks
