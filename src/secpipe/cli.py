"""CLI machine-first do secpipe: doctor · scan · fix · verify · init · hook · mcp · remember/recall · version.

Saída pensada para a IA consumir (JSON em `scan`). Exit code de `scan`/`verify` reflete o gate."""
from __future__ import annotations

import argparse
import sys

from secpipe import __version__
from secpipe.adapters.fix_memory import FixMemory
from secpipe.adapters.reporters import JsonReporter, SarifReporter
from secpipe.application.use_cases.init import init as run_init
from secpipe.application.use_cases.precommit import run as run_precommit
from secpipe.application.use_cases.verify import verify as run_verify
from secpipe.domain.fix_memory import VerifiedFix
from secpipe.foundation.composition_root import _SCANNER_REGISTRY, build, build_fixer
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


def _cmd_scan(config_path: str | None, target: str, fmt: str) -> int:
    cfg = Config.load(config_path)
    orchestrator = build(cfg)
    report, decision = orchestrator.run(target)
    reporter = SarifReporter() if fmt == "sarif" else JsonReporter()
    print(reporter.render(report))
    if report.ran == 0:
        print(f"\n{NO_SCANNER_WARN}", file=sys.stderr)
    verdict = "PASS" if decision.passed else "FAIL"
    print(f"\nGATE: {verdict} - {decision.reason}", file=sys.stderr)
    return 0 if decision.passed else 1


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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="secpipe", description="Motor de seguranca operado por IA.")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("doctor", help="lista ferramentas disponiveis no PATH")
    scan = sub.add_parser("scan", help="roda os scanners, normaliza e aplica o gate")
    scan.add_argument("target", nargs="?", default=".", help="diretorio alvo (default: .)")
    scan.add_argument("--config", default=None, help="caminho do .secpipe.yml (default: auto)")
    scan.add_argument("--format", dest="fmt", choices=["json", "sarif"], default="json",
                      help="formato de saida (default: json para a IA; sarif para code scanning)")
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
    sub.add_parser("version", help="mostra a versao")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "doctor":
        return _cmd_doctor()
    if args.command == "scan":
        return _cmd_scan(args.config, args.target, args.fmt)
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
    if args.command == "version":
        print(__version__)
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
