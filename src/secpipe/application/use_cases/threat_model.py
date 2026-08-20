"""`secpipe threat-model` — threat model STRIDE do APP do consumidor (FEAT-011), keyless e determinístico.

O motor NÃO "adivinha" ameaças com IA. Ele faz o trabalho objetivo e auditável:
  (a) mapeia os achados REAIS dos scanners por CWE -> STRIDE (domain/stride.py);
  (b) descobre a SUPERFÍCIE de ataque do código (entrypoints, sinks perigosos, ativos sensíveis) por
      marcadores estáticos;
  (c) emite um scaffold STRIDE (JSON + Markdown) com prompts por categoria.
O agente de IA (o operador) completa o raciocínio — como o AGENTS.md guia o resto. Sem chave, sem serviço."""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field

from secpipe.domain import Finding
from secpipe.domain.stride import Stride, categorize

_SKIP_DIRS = {
    ".git", ".venv", "venv", "node_modules", ".tox", "dist", "build", "__pycache__",
    "tools", ".mypy_cache", ".ruff_cache", ".pytest_cache", "vendor", "site-packages",
}
_SCAN_EXT = {".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rb", ".java", ".php", ".cs", ".rs"}
_MAX_FILES = 4000
_MAX_BYTES = 1_500_000  # arquivo maior que isso é provavelmente gerado/minificado -> pula


@dataclass(frozen=True, slots=True)
class SurfaceElement:
    kind: str                 # "entrypoint" | "sink" | "asset"
    label: str                # ex.: "web-route", "subprocess", "secret"
    file: str
    line: int
    evidence: str
    stride: frozenset[Stride]


# Marcadores de superfície: (kind, label, regex, categorias STRIDE implicadas). Determinístico e auditável.
# Cobertura pragmática, multi-linguagem (Python-leaning + web JS). É um ponto de partida, não um oráculo.
_MARKERS: tuple[tuple[str, str, re.Pattern[str], tuple[Stride, ...]], ...] = tuple(
    (kind, label, re.compile(pat), cats)
    for kind, label, pat, cats in (
        # ── entrypoints: fronteiras de entrada não confiável ──
        ("entrypoint", "web-route",
         r"@(?:app|router|blueprint|bp)\.(?:route|get|post|put|patch|delete)\b|"
         r"\b(?:app|router)\.(?:get|post|put|patch|delete)\s*\(|urlpatterns\s*=|@(?:Get|Post|Put|Delete)Mapping",
         (Stride.SPOOFING, Stride.TAMPERING, Stride.DENIAL_OF_SERVICE)),
        ("entrypoint", "request-input",
         r"request\.(?:args|form|json|data|values|files|cookies|headers)|req\.(?:body|query|params)|"
         r"flask\.request|getReceivedInput",
         (Stride.TAMPERING,)),
        ("entrypoint", "cli-arg",
         r"argparse\.ArgumentParser|add_argument\(|click\.(?:command|option|argument)|sys\.argv",
         (Stride.TAMPERING,)),
        # ── sinks: operações perigosas ──
        ("sink", "command-exec",
         r"subprocess\.(?:run|call|Popen|check_output)|os\.system|os\.popen|\beval\s*\(|\bexec\s*\(|"
         r"child_process|shell\s*=\s*True|Runtime\.getRuntime\(\)\.exec",
         (Stride.TAMPERING, Stride.ELEVATION)),
        ("sink", "sql",
         r"\.execute\s*\(|\.executemany\s*\(|cursor\.|sqlalchemy|\.raw\s*\(|SELECT\s.+FROM\s|text\s*\(",
         (Stride.TAMPERING,)),
        ("sink", "deserialize",
         r"pickle\.loads?|yaml\.load\s*\(|marshal\.loads?|jsonpickle|cPickle|ObjectInputStream",
         (Stride.TAMPERING, Stride.ELEVATION)),
        ("sink", "file-io",
         r"\bopen\s*\(|Path\([^)]*\)\.(?:write|read)|os\.remove|shutil\.(?:rmtree|move|copy)|fs\.(?:readFile|writeFile)",
         (Stride.TAMPERING, Stride.INFO_DISCLOSURE)),
        ("sink", "network",
         r"requests\.(?:get|post|put|delete|request)|urllib\.request|httpx\.|aiohttp\.|socket\.socket|fetch\s*\(",
         (Stride.TAMPERING, Stride.INFO_DISCLOSURE)),
        ("sink", "template",
         r"render_template_string|Template\s*\(|jinja2|innerHTML\s*=|dangerouslySetInnerHTML",
         (Stride.TAMPERING,)),
        # ── ativos: material sensível ──
        ("asset", "secret",
         r"os\.environ|os\.getenv|process\.env|dotenv|(?:api[_-]?key|secret|password|passwd|token)\s*[:=]",
         (Stride.INFO_DISCLOSURE,)),
        ("asset", "crypto",
         r"hashlib\.|from cryptography|import ssl\b|ssl\.|jwt\.(?:encode|decode)|bcrypt|hmac\.|Cipher\b",
         (Stride.INFO_DISCLOSURE,)),
        ("asset", "auth",
         r"login_required|authenticate\(|@requires_auth|check_password|verify_token|permission_required|is_admin",
         (Stride.SPOOFING, Stride.ELEVATION)),
    )
)

# Checklists por categoria — prompts que o AGENTE completa (o motor entrega o scaffold, a IA raciocina).
_PROMPTS: dict[Stride, tuple[str, ...]] = {
    Stride.SPOOFING: (
        "Todo entrypoint exige autenticação forte antes de agir?",
        "Sessões/tokens são verificados e não spoofáveis (assinatura, expiração)?",
    ),
    Stride.TAMPERING: (
        "Toda entrada não confiável é validada e as queries/comandos são parametrizados (sem concatenação)?",
        "Integridade de dados em trânsito/repouso é garantida onde importa?",
    ),
    Stride.REPUDIATION: (
        "Ações sensíveis geram log de auditoria à prova de adulteração (quem, o quê, quando)?",
        "Logs não são falsificáveis por injeção de entrada?",
    ),
    Stride.INFO_DISCLOSURE: (
        "Segredos ficam fora do código e de logs; erros não vazam stack/detalhes internos?",
        "Dados sensíveis são cifrados em trânsito (TLS) e em repouso quando aplicável?",
    ),
    Stride.DENIAL_OF_SERVICE: (
        "Há limites (rate-limit, tamanho de payload, timeouts, paginação) nos entrypoints?",
        "Nenhum caminho permite consumo ilimitado de CPU/memória (ReDoS, loops, alocação)?",
    ),
    Stride.ELEVATION: (
        "Autorização é checada por recurso/ação (não só autenticação)?",
        "Processos rodam com o mínimo privilégio; nenhum sink executa entrada não confiável?",
    ),
}


@dataclass(slots=True)
class CategoryGroup:
    surface: list[SurfaceElement] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class ThreatModel:
    target: str
    surface: tuple[SurfaceElement, ...]
    findings: tuple[Finding, ...]

    def _finding_stride(self, f: Finding) -> frozenset[Stride]:
        return categorize(f.cwe, f.rule_id, f.message)

    def by_category(self) -> dict[Stride, CategoryGroup]:
        """Agrupa superfície e achados por categoria STRIDE (ordem canônica)."""
        out: dict[Stride, CategoryGroup] = {s: CategoryGroup() for s in Stride}
        for el in self.surface:
            for s in el.stride:
                out[s].surface.append(el)
        for f in self.findings:
            for s in self._finding_stride(f):
                out[s].findings.append(f)
        return out


def _iter_source_files(root: str) -> list[str]:
    files: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for name in filenames:
            if os.path.splitext(name)[1].lower() in _SCAN_EXT:
                files.append(os.path.join(dirpath, name))
                if len(files) >= _MAX_FILES:
                    return files
    return files


def discover_surface(root: str) -> tuple[SurfaceElement, ...]:
    """Varre o código-fonte e localiza entrypoints, sinks e ativos por marcadores estáticos. Determinístico."""
    elements: list[SurfaceElement] = []
    for path in _iter_source_files(root):
        try:
            if os.path.getsize(path) > _MAX_BYTES:
                continue
            with open(path, encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except OSError:
            continue
        rel = os.path.relpath(path, root).replace("\\", "/")
        for lineno, text in enumerate(lines, start=1):
            for kind, label, pattern, cats in _MARKERS:
                if pattern.search(text):
                    elements.append(SurfaceElement(
                        kind=kind, label=label, file=rel, line=lineno,
                        evidence=text.strip()[:160], stride=frozenset(cats),
                    ))
    return tuple(elements)


def build_threat_model(target: str, findings: tuple[Finding, ...]) -> ThreatModel:
    """Monta o threat model: superfície descoberta + achados reais (já coletados por um scan)."""
    return ThreatModel(target=target, surface=discover_surface(target), findings=tuple(findings))


def render_json(tm: ThreatModel) -> str:
    grouped = tm.by_category()
    payload = {
        "schema_version": "0",
        "kind": "stride-threat-model",
        "target": tm.target,
        "note": "Scaffold DETERMINÍSTICO (keyless). Complete o raciocínio com seu agente de IA.",
        "surface_count": len(tm.surface),
        "categories": {
            s.value: {
                "name": s.label,
                "surface": [
                    {"kind": e.kind, "label": e.label, "file": e.file, "line": e.line, "evidence": e.evidence}
                    for e in g.surface
                ],
                "findings": [
                    {"tool": f.tool, "rule_id": f.rule_id, "severity": f.severity.name,
                     "cwe": f.cwe, "file": f.file, "line": f.line}
                    for f in g.findings
                ],
                "checklist": list(_PROMPTS[s]),
            }
            for s, g in grouped.items()
        },
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def render_markdown(tm: ThreatModel) -> str:
    grouped = tm.by_category()
    out: list[str] = []
    out.append(f"# STRIDE threat model — `{tm.target}`\n")
    out.append("> Scaffold **determinístico e keyless** gerado pelo secpipe: superfície de ataque descoberta "
               "no código + achados reais mapeados por CWE->STRIDE. **Complete o raciocínio com seu agente** "
               "(as checklists abaixo são o ponto de partida).\n")
    total_find = len(tm.findings)
    out.append(f"**Superfície:** {len(tm.surface)} elemento(s) · **Achados:** {total_find}\n")
    for s in Stride:
        g = grouped[s]
        surf, finds = g.surface, g.findings
        out.append(f"\n## {s.value} — {s.label}")
        out.append(f"*Superfície: {len(surf)} · Achados: {len(finds)}*\n")
        if finds:
            out.append("**Achados reais nesta categoria:**\n")
            out.append("| Severidade | CWE | Regra | Local |")
            out.append("| --- | --- | --- | --- |")
            for f in sorted(finds, key=lambda x: x.severity, reverse=True)[:15]:
                loc = f"{f.file}:{f.line}" if f.file else "-"
                out.append(f"| {f.severity.name} | {f.cwe or '-'} | `{f.rule_id}` | {loc} |")
            out.append("")
        if surf:
            out.append("**Superfície de ataque (amostra):**\n")
            for e in surf[:12]:
                out.append(f"- `{e.file}:{e.line}` — **{e.label}** ({e.kind}): `{e.evidence}`")
            if len(surf) > 12:
                out.append(f"- … +{len(surf) - 12} outro(s)")
            out.append("")
        out.append("**Verifique (o agente completa):**")
        for prompt in _PROMPTS[s]:
            out.append(f"- [ ] {prompt}")
    out.append("")
    return "\n".join(out)
