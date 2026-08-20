"""Reporters para HUMANOS/PR: HTML self-contained, resumo Markdown e badge SVG. O produto é machine-first,
mas o review humano importa. Tudo stdlib, keyless, SEM rede (sem CDN/shields.io).

SEGURANÇA: message/file dos achados vêm de código/tools de TERCEIROS — ESCAPAR tudo (html.escape / neutralizar
pipes e control chars) para não virar XSS no HTML nem quebra/injeção no Markdown."""
from __future__ import annotations

import html

from secpipe.domain import Report, Severity

_SEV_ORDER = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)
_SEV_COLOR = {
    Severity.CRITICAL: "#7c1d1d", Severity.HIGH: "#b91c1c", Severity.MEDIUM: "#b45309",
    Severity.LOW: "#2563eb", Severity.INFO: "#4b5563",
}


def _counts(report: Report) -> dict[Severity, int]:
    counts = dict.fromkeys(_SEV_ORDER, 0)
    for f in report.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def _blocking(report: Report, block: Severity = Severity.HIGH) -> int:
    return sum(1 for f in report.findings if f.severity >= block or f.kev)


def _md_cell(text: str) -> str:
    """Neutraliza pipe/quebra de linha/backtick (injeção/quebra de tabela Markdown)."""
    return text.replace("|", "\\|").replace("`", "'").replace("\n", " ").replace("\r", " ").strip()[:200]


def _wc_data(text: str) -> str:
    """Escape do CORPO de um GitHub workflow command (após `::`)."""
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _wc_prop(text: str) -> str:
    """Escape de VALOR de propriedade (`file=`, `title=`): também vírgula e dois-pontos (separadores)."""
    return _wc_data(text).replace(":", "%3A").replace(",", "%2C")


class MarkdownReporter:
    """Resumo compacto para comentar no PR."""
    name = "md"

    def render(self, report: Report) -> str:
        counts = _counts(report)
        blocked = _blocking(report)
        status = "❌ FAIL" if blocked else "✅ PASS"
        out = [f"### secpipe — {status}", ""]
        out.append("| Sev | # |")
        out.append("| --- | --- |")
        for sev in _SEV_ORDER:
            if counts[sev]:
                out.append(f"| {sev.name} | {counts[sev]} |")
        out.append("")
        top = sorted(report.findings, key=lambda f: (f.kev, f.severity), reverse=True)[:15]
        if top:
            out.append("| Sev | CWE | Regra | Local | KEV |")
            out.append("| --- | --- | --- | --- | --- |")
            for f in top:
                loc = _md_cell(f"{f.file}:{f.line}" if f.file else "-")
                out.append(f"| {f.severity.name} | {_md_cell(f.cwe or '-')} | `{_md_cell(f.rule_id)}` "
                           f"| {loc} | {'⚠️' if f.kev else ''} |")
        out.append("")
        return "\n".join(out)


class GithubAnnotationsReporter:
    """Emite workflow commands `::error/::warning file=..,line=..` — anotações inline no PR, KEYLESS
    (só o runner do Actions lê), fallback p/ repos sem GHAS/code-scanning."""
    name = "github"

    def render(self, report: Report) -> str:
        lines: list[str] = []
        for f in report.findings[:50]:  # Actions limita anotações; capamos
            level = "error" if (f.severity >= Severity.HIGH or f.kev) else "warning"
            # ESCAPAR TODO texto de terceiro (message/rule_id/file) — rule_id e file eram inseridos crus,
            # permitindo injeção de workflow-command via \n em nome de arquivo/regra (achado #8).
            msg = _wc_data(f.message)[:400]
            title = _wc_prop(f.rule_id)[:200]
            loc = f"file={_wc_prop(f.file)},line={max(1, f.line)}" if f.file else ""
            lines.append(f"::{level} {loc},title=secpipe {title}::{msg}")
        return "\n".join(lines)


class HtmlReporter:
    """Relatório HTML self-contained (CSS inline, sem rede). Escaping rigoroso (anti-XSS)."""
    name = "html"

    def render(self, report: Report) -> str:
        counts = _counts(report)
        blocked = _blocking(report)
        status = "FAIL" if blocked else "PASS"
        color = "#b91c1c" if blocked else "#15803d"
        rows = []
        for f in sorted(report.findings, key=lambda x: (x.kev, x.severity), reverse=True):
            kev = ' <span style="color:#b91c1c">KEV</span>' if f.kev else ""
            rows.append(
                f"<tr><td style='color:{_SEV_COLOR.get(f.severity, '#000')}'>{html.escape(f.severity.name)}</td>"
                f"<td>{html.escape(f.cwe or '-')}</td><td><code>{html.escape(f.rule_id)}</code>{kev}</td>"
                f"<td>{html.escape(f.file)}:{f.line}</td><td>{html.escape(f.message[:300])}</td></tr>"
            )
        chips = " ".join(
            f"<b style='color:{_SEV_COLOR[s]}'>{s.name}:{counts[s]}</b>" for s in _SEV_ORDER if counts[s]
        )
        return (
            "<div style='font-family:system-ui,sans-serif;max-width:1000px;margin:1rem auto'>"
            f"<h2>secpipe — <span style='color:{color}'>{status}</span></h2>"
            f"<p>{chips or 'nenhum achado'} · scanners: {report.ran}</p>"
            "<table style='border-collapse:collapse;width:100%' border='1' cellpadding='6'>"
            "<tr><th>Sev</th><th>CWE</th><th>Regra</th><th>Local</th><th>Mensagem</th></tr>"
            + "".join(rows) + "</table></div>"
        )


def render_badge(report: Report) -> str:
    """Badge SVG estático (sem shields.io). 'security: PASS' ou 'N high'."""
    blocked = _blocking(report)
    label, value, color = "security", ("PASS" if not blocked else f"{blocked} blocking"), (
        "#15803d" if not blocked else "#b91c1c")
    lw, vw = 62, 8 * len(value) + 20
    total = lw + vw
    return (
        f"<svg xmlns='http://www.w3.org/2000/svg' width='{total}' height='20' role='img'>"
        f"<rect width='{lw}' height='20' fill='#555'/>"
        f"<rect x='{lw}' width='{vw}' height='20' fill='{color}'/>"
        f"<g fill='#fff' font-family='Verdana,sans-serif' font-size='11'>"
        f"<text x='6' y='14'>{html.escape(label)}</text>"
        f"<text x='{lw + 6}' y='14'>{html.escape(value)}</text></g></svg>"
    )
