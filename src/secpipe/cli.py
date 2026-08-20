"""CLI machine-first do secpipe.

Comandos: doctor · scan · fix · verify · threat-model · dast-import · import · config-validate
· init · hook · mcp · remember/recall · version.
Saída pensada para a IA consumir (JSON em `scan`). Exit code de `scan`/`verify` reflete o gate."""
from __future__ import annotations

import argparse
import dataclasses
import sys
from collections.abc import Callable

from secpipe import __version__
from secpipe.adapters.dast_zap import parse_zap_report
from secpipe.adapters.epss_kev import enrich_report
from secpipe.adapters.fix_memory import FixMemory
from secpipe.adapters.reporters import JsonReporter, SarifReporter
from secpipe.adapters.reporters_human import (
    GithubAnnotationsReporter,
    HtmlReporter,
    MarkdownReporter,
    render_badge,
)
from secpipe.adapters.sarif import parse_sarif
from secpipe.application.ports import ReporterPort
from secpipe.application.use_cases.config_validate import validate_config
from secpipe.application.use_cases.init import init as run_init
from secpipe.application.use_cases.precommit import run as run_precommit
from secpipe.application.use_cases.threat_model import build_threat_model
from secpipe.application.use_cases.threat_model import render_json as tm_render_json
from secpipe.application.use_cases.threat_model import render_markdown as tm_render_md
from secpipe.application.use_cases.verify import verify as run_verify
from secpipe.domain import Report, ScanResult, ScanStatus
from secpipe.domain.fix_memory import VerifiedFix
from secpipe.foundation.composition_root import _SCANNER_REGISTRY, build, build_fixer, build_policy
from secpipe.foundation.config import Config
from secpipe.mcp_server import main as mcp_main


def _cmd_doctor() -> int:
    """Lista os scanners conhecidos e se estão disponíveis no PATH (real)."""
    print("secpipe doctor - disponibilidade de ferramentas:")
    for name, factory in _SCANNER_REGISTRY.items():
        available = factory().is_available()
        mark = "OK " if available else "-- "
        print(f"  [{mark}] {name}{'' if available else '  (nao encontrado no PATH)'}")
    print("\n'secpipe scan' executa os scanners disponiveis, normaliza (SARIF) e aplica o gate.")
    return 0


NO_SCANNER_WARN = (
    "AVISO: 0 scanners rodaram (nenhum disponivel). O gate passou por AUSENCIA de scanners, "
    "nao por seguranca. Instale com `python install.py` ou use o container "
    "`ghcr.io/pablodlz/secpipe-ai`; veja `secpipe doctor`."
)


_REPORTERS: dict[str, Callable[[], ReporterPort]] = {
    "json": JsonReporter, "sarif": SarifReporter, "html": HtmlReporter,
    "md": MarkdownReporter, "github": GithubAnnotationsReporter,
}


def _write_or_print(text: str, output: str | None) -> None:
    if output:
        with open(output, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"secpipe: escrito em {output}", file=sys.stderr)
    else:
        print(text)


def _cmd_scan(config_path: str | None, target: str, fmt: str, enrich: bool = False,
              output: str | None = None) -> int:
    cfg = Config.load(config_path)
    report, decision = build(cfg).run(target)
    do_epss, do_kev = enrich or cfg.enrich_epss, enrich or cfg.enrich_kev
    if do_epss or do_kev:
        # EPSS/KEV: anota (fail-open) e re-avalia o gate (KEV pode bloquear).
        report = enrich_report(report, cfg.cache_dir, epss=do_epss, kev=do_kev)
        decision = build_policy(cfg).evaluate(report)
    _write_or_print(_REPORTERS[fmt]().render(report), output)
    if report.ran == 0:
        print(f"\n{NO_SCANNER_WARN}", file=sys.stderr)
    verdict = "PASS" if decision.passed else "FAIL"
    print(f"\nGATE: {verdict} - {decision.reason}", file=sys.stderr)
    return 0 if decision.passed else 1


def _cmd_badge(config_path: str | None, target: str, output: str | None) -> int:
    """Gera um badge SVG (security: PASS / N blocking) a partir de um scan. Sem rede."""
    cfg = Config.load(config_path)
    report, _ = build(cfg).run(target)
    _write_or_print(render_badge(report), output)
    return 0


def _cmd_init(args: argparse.Namespace) -> int:
    result = run_init(
        args.target, force=args.force, shims=not args.no_shims,
        hooks=not args.no_hooks, workflow=not args.no_workflow,
    )
    print("secpipe init:")
    for action in result.actions:
        print("  -", action)
    print("\nProximo: `secpipe doctor` e `secpipe scan .`. A IA deve carregar o AGENTS.md antes de codar.")
    print("Scanners locais: rode `python install.py` (ou use o container). O workflow gerado ja usa a "
          "imagem com todos os scanners; para o `@v1` funcionar, o repo do secpipe mantem a tag major.")
    return 0


def _cmd_hook() -> int:
    return run_precommit()


def _cmd_mcp() -> int:
    return mcp_main()


def _cmd_fix(target: str, dry_run: bool) -> int:
    outcome = build_fixer().run(target, dry_run=dry_run)
    if not outcome.ran:
        print(f"secpipe fix: nao executado — {outcome.detail}")
        return 0
    verbo = "aplicaria" if dry_run else "aplicou"
    print(f"secpipe fix: {verbo} {outcome.changes} mudanca(s) em {outcome.files_changed} arquivo(s)")
    for codemod in outcome.codemods:
        print("  -", codemod)
    print("Rode `secpipe scan`/`secpipe verify`; o restante fica para o agente corrigir.")
    return 0


def _cmd_remember(args: argparse.Namespace) -> int:
    fix = VerifiedFix(cwe=args.cwe, tool=args.tool, rule_id=args.rule, note=args.note)
    added = FixMemory().record(fix)
    print("secpipe remember:", "registrado" if added else "ja existia", f"({args.cwe})")
    return 0


def _cmd_recall(cwe: str) -> int:
    fixes = FixMemory().recall(cwe)
    if not fixes:
        print(f"secpipe recall: nenhum padrao verificado para {cwe}")
        return 0
    print(f"secpipe recall ({cwe}) — {len(fixes)} padrao(oes) (candidatos, ainda verificados):")
    for fix in fixes:
        print(f"  - [{fix.tool}/{fix.rule_id}] {fix.note}")
    return 0


def _cmd_verify(config_path: str | None, target: str, base_ref: str) -> int:
    cfg = Config.load(config_path)
    verdict = run_verify(build(cfg), target, base_ref=base_ref, test_command=cfg.test_command)
    print(f"secpipe verify: {'ACCEPT' if verdict.accepted else 'REJECT'}")
    for reason in verdict.reasons:
        print("  -", reason)
    return 0 if verdict.accepted else 1


def _cmd_threat_model(config_path: str | None, target: str, fmt: str) -> int:
    """Gera o threat model STRIDE do app: scan real -> achados por CWE/STRIDE + superfície descoberta.
    Scaffold determinístico e KEYLESS; o agente de IA completa o raciocínio (as checklists)."""
    cfg = Config.load(config_path)
    report, _ = build(cfg).run(target)
    tm = build_threat_model(target, tuple(report.findings))
    print(tm_render_json(tm) if fmt == "json" else tm_render_md(tm))
    return 0


def _cmd_image(config_path: str | None, ref: str) -> int:
    """Escaneia uma IMAGEM de container (trivy image): SO + libs + misconfig + segredos, e aplica o gate."""
    cfg = dataclasses.replace(Config.load(config_path), scanners=("image",), image_target=ref)
    report, decision = build(cfg).run(".")
    print(JsonReporter().render(report))
    print(f"\nGATE (image): {'PASS' if decision.passed else 'FAIL'} - {decision.reason}", file=sys.stderr)
    return 0 if decision.passed else 1


def _cmd_import(config_path: str | None, sarif_path: str, tool: str) -> int:
    """Importa QUALQUER SARIF externo (CodeQL/Checkov/gosec/terceiros), normaliza e aplica o MESMO gate.
    Torna o secpipe o gate/normalizador universal do ecossistema (ADR-0004), sem reimplementar parsers."""
    cfg = Config.load(config_path)
    try:
        with open(sarif_path, encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
    except OSError as exc:
        print(f"secpipe import: nao consegui ler {sarif_path}: {exc}", file=sys.stderr)
        return 2
    try:
        findings = parse_sarif(raw, tool)
    except (ValueError, TypeError) as exc:
        result = ScanResult(tool, ScanStatus.ERROR, (), f"SARIF invalido: {str(exc)[:200]}")
    else:
        result = ScanResult(tool, ScanStatus.OK, tuple(findings), "")
    report = Report((result,))
    decision = build_policy(cfg).evaluate(report)
    print(JsonReporter().render(report))
    print(f"\nGATE (import): {'PASS' if decision.passed else 'FAIL'} - {decision.reason}", file=sys.stderr)
    return 0 if decision.passed else 1


def _cmd_config_validate(config_path: str | None) -> int:
    """Valida o .secpipe.yml (chaves/valores/scanners) — pega misconfig que enfraqueceria o gate."""
    path = config_path or ".secpipe.yml"
    known = frozenset(_SCANNER_REGISTRY) | {"dast"}
    errors = validate_config(path, known)
    if not errors:
        print(f"secpipe config-validate: OK ({path})")
        return 0
    print(f"secpipe config-validate: {len(errors)} problema(s) em {path}:", file=sys.stderr)
    for err in errors:
        print("  -", err, file=sys.stderr)
    return 1


def _cmd_dast_import(config_path: str | None, report_path: str) -> int:
    """Importa um relatório JSON do ZAP (gerado por um step no CI), normaliza e aplica o MESMO gate.
    Ponte do fluxo de CI: o ZAP roda como container à parte -> este comando junta ao contrato do secpipe."""
    cfg = Config.load(config_path)
    try:
        with open(report_path, encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
    except OSError as exc:
        print(f"secpipe dast-import: nao consegui ler {report_path}: {exc}", file=sys.stderr)
        return 2
    try:
        findings = parse_zap_report(raw)
    except (ValueError, TypeError) as exc:
        result = ScanResult("dast", ScanStatus.ERROR, (), f"relatorio ZAP invalido: {str(exc)[:200]}")
    else:
        result = ScanResult("dast", ScanStatus.OK, tuple(findings), "")
    report = Report((result,))
    decision = build_policy(cfg).evaluate(report)
    print(JsonReporter().render(report))
    verdict = "PASS" if decision.passed else "FAIL"
    print(f"\nGATE (DAST): {verdict} - {decision.reason}", file=sys.stderr)
    return 0 if decision.passed else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="secpipe", description="Motor de seguranca operado por IA.")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("doctor", help="lista ferramentas disponiveis no PATH")
    scan = sub.add_parser("scan", help="roda os scanners, normaliza e aplica o gate")
    scan.add_argument("target", nargs="?", default=".", help="diretorio alvo (default: .)")
    scan.add_argument("--config", default=None, help="caminho do .secpipe.yml (default: auto)")
    scan.add_argument("--format", dest="fmt", choices=["json", "sarif", "html", "md", "github"], default="json",
                      help="saida: json (IA) · sarif (code scanning) · html/md (humano/PR) · github (anotacoes)")
    scan.add_argument("--enrich", action="store_true",
                      help="anexa EPSS + CISA KEV aos achados com CVE (usa rede; KEV bloqueia)")
    scan.add_argument("--output", default=None, help="grava a saida num arquivo (em vez do stdout)")
    init = sub.add_parser("init", help="adota o secpipe no projeto (config + AGENTS.md + hook + workflow)")
    init.add_argument("target", nargs="?", default=".", help="diretorio do projeto (default: .)")
    init.add_argument("--force", action="store_true", help="sobrescreve arquivos existentes")
    init.add_argument("--no-shims", action="store_true", help="nao grava shims (CLAUDE.md)")
    init.add_argument("--no-hooks", action="store_true", help="nao instala o hook pre-commit")
    init.add_argument("--no-workflow", action="store_true", help="nao grava o workflow do GitHub")
    sub.add_parser("hook", help="checagem de pre-commit (anti-supressao + segredo staged)")
    sub.add_parser("mcp", help="servidor MCP (stdio) — expoe as tools do secpipe ao agente de IA")
    rem = sub.add_parser("remember", help="registra um fix VERIFICADO na memoria (padrao, nao codigo)")
    rem.add_argument("--cwe", required=True, help="ex.: CWE-89")
    rem.add_argument("--tool", default="", help="scanner de origem")
    rem.add_argument("--rule", default="", help="rule_id")
    rem.add_argument("--note", default="", help="padrao do fix (ex.: 'usar query parametrizada')")
    rec = sub.add_parser("recall", help="recupera padroes de fix verificados por CWE")
    rec.add_argument("--cwe", required=True, help="ex.: CWE-89")
    fix = sub.add_parser("fix", help="aplica fixes deterministicos (codemods) — o resto e do agente")
    fix.add_argument("target", nargs="?", default=".", help="diretorio (default: .)")
    fix.add_argument("--dry-run", action="store_true", help="mostra o que mudaria, sem escrever")
    ver = sub.add_parser("verify", help="juiz deterministico do fix (gate + anti-supressao + testes)")
    ver.add_argument("target", nargs="?", default=".", help="diretorio (default: .)")
    ver.add_argument("--config", default=None, help="caminho do .secpipe.yml")
    ver.add_argument("--base", dest="base_ref", default="HEAD", help="ref git base do diff (default: HEAD)")
    tm = sub.add_parser("threat-model", help="threat model STRIDE do app (scaffold keyless; o agente completa)")
    tm.add_argument("target", nargs="?", default=".", help="diretorio alvo (default: .)")
    tm.add_argument("--config", default=None, help="caminho do .secpipe.yml")
    tm.add_argument("--format", dest="fmt", choices=["md", "json"], default="md",
                    help="md (agente/humano) ou json (maquina). default: md")
    di = sub.add_parser("dast-import", help="importa relatorio JSON do ZAP (DAST no CI), normaliza e aplica o gate")
    di.add_argument("report", help="caminho do report.json gerado pelo ZAP baseline")
    di.add_argument("--config", default=None, help="caminho do .secpipe.yml")
    cv = sub.add_parser("config-validate", help="valida o .secpipe.yml (pega chave/valor/scanner invalido)")
    cv.add_argument("--config", default=None, help="caminho do .secpipe.yml (default: .secpipe.yml)")
    imp = sub.add_parser("import", help="importa um SARIF externo (CodeQL/Checkov/...), normaliza e aplica o gate")
    imp.add_argument("sarif", help="caminho do arquivo .sarif")
    imp.add_argument("--tool", default="external", help="nome do tool de origem (default: external)")
    imp.add_argument("--config", default=None, help="caminho do .secpipe.yml")
    img = sub.add_parser("image", help="escaneia uma imagem de container (trivy image) e aplica o gate")
    img.add_argument("ref", help="ref da imagem ou tarball (ex.: ghcr.io/org/app:tag)")
    img.add_argument("--config", default=None, help="caminho do .secpipe.yml")
    bdg = sub.add_parser("badge", help="gera um badge SVG (security: PASS / N blocking) a partir de um scan")
    bdg.add_argument("target", nargs="?", default=".", help="diretorio alvo (default: .)")
    bdg.add_argument("--config", default=None, help="caminho do .secpipe.yml")
    bdg.add_argument("--output", default=None, help="grava o SVG num arquivo (ex.: badge.svg)")
    sub.add_parser("version", help="mostra a versao")
    return parser


def _ensure_utf8_stdout() -> None:
    """Windows: o console default (cp1252) quebra em setas/simbolos fora do Latin-1 e ABORTA o comando.
    Forca utf-8 com fallback 'replace' (no-op no Linux/CI, onde stdout ja e utf-8)."""
    for stream in (sys.stdout, sys.stderr):
        reconfig = getattr(stream, "reconfigure", None)
        if reconfig is not None:
            try:
                reconfig(encoding="utf-8", errors="replace")
            except (ValueError, OSError):  # pragma: no cover - ambiente
                pass


def main(argv: list[str] | None = None) -> int:
    _ensure_utf8_stdout()
    args = build_parser().parse_args(argv)
    if args.command == "doctor":
        return _cmd_doctor()
    if args.command == "scan":
        return _cmd_scan(args.config, args.target, args.fmt, args.enrich, args.output)
    if args.command == "badge":
        return _cmd_badge(args.config, args.target, args.output)
    if args.command == "init":
        return _cmd_init(args)
    if args.command == "hook":
        return _cmd_hook()
    if args.command == "mcp":
        return _cmd_mcp()
    if args.command == "remember":
        return _cmd_remember(args)
    if args.command == "recall":
        return _cmd_recall(args.cwe)
    if args.command == "fix":
        return _cmd_fix(args.target, args.dry_run)
    if args.command == "verify":
        return _cmd_verify(args.config, args.target, args.base_ref)
    if args.command == "threat-model":
        return _cmd_threat_model(args.config, args.target, args.fmt)
    if args.command == "dast-import":
        return _cmd_dast_import(args.config, args.report)
    if args.command == "config-validate":
        return _cmd_config_validate(args.config)
    if args.command == "import":
        return _cmd_import(args.config, args.sarif, args.tool)
    if args.command == "image":
        return _cmd_image(args.config, args.ref)
    if args.command == "version":
        print(__version__)
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
