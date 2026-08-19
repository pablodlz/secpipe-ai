"""CLI machine-first do secpipe. Fase 0: `doctor` (real), `scan` (esqueleto), `version`.

Saída pensada para a IA consumir (JSON em `scan`). Exit code do `scan` reflete o gate."""
from __future__ import annotations

import argparse
import sys

from secpipe import __version__
from secpipe.adapters.reporters import JsonReporter, SarifReporter
from secpipe.application.use_cases.init import init as run_init
from secpipe.application.use_cases.precommit import run as run_precommit
from secpipe.foundation.composition_root import _SCANNER_REGISTRY, build
from secpipe.foundation.config import Config


def _cmd_doctor() -> int:
    """Lista os scanners conhecidos e se estão disponíveis no PATH (real)."""
    print("secpipe doctor - disponibilidade de ferramentas:")
    for name, factory in _SCANNER_REGISTRY.items():
        available = factory().is_available()
        mark = "OK " if available else "-- "
        print(f"  [{mark}] {name}{'' if available else '  (nao encontrado no PATH)'}")
    print("\n'secpipe scan' executa os scanners disponiveis, normaliza (SARIF) e aplica o gate.")
    return 0


def _cmd_scan(config_path: str | None, target: str, fmt: str) -> int:
    cfg = Config.load(config_path)
    orchestrator = build(cfg)
    report, decision = orchestrator.run(target)
    reporter = SarifReporter() if fmt == "sarif" else JsonReporter()
    print(reporter.render(report))
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
    return 0


def _cmd_hook() -> int:
    return run_precommit()


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
    if args.command == "version":
        print(__version__)
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
