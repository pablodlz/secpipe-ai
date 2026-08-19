"""CLI machine-first do secpipe. Fase 0: `doctor` (real), `scan` (esqueleto), `version`.

Saída pensada para a IA consumir (JSON em `scan`). Exit code do `scan` reflete o gate."""
from __future__ import annotations

import argparse
import sys

from secpipe import __version__
from secpipe.adapters.reporters import JsonReporter
from secpipe.foundation.composition_root import _SCANNER_REGISTRY, build
from secpipe.foundation.config import Config


def _cmd_doctor() -> int:
    """Lista os scanners conhecidos e se estão disponíveis no PATH (real)."""
    print("secpipe doctor - disponibilidade de ferramentas:")
    for name, factory in _SCANNER_REGISTRY.items():
        available = factory().is_available()
        mark = "OK " if available else "-- "
        print(f"  [{mark}] {name}{'' if available else '  (nao encontrado no PATH)'}")
    print("\nFase 0: 'scan' ainda nao executa os scanners (execucao real: Fase 1).")
    return 0


def _cmd_scan(config_path: str | None, target: str) -> int:
    cfg = Config.load(config_path)
    orchestrator = build(cfg)
    report, decision = orchestrator.run(target)
    print(JsonReporter().render(report))
    verdict = "PASS" if decision.passed else "FAIL"
    print(f"\nGATE: {verdict} - {decision.reason}", file=sys.stderr)
    return 0 if decision.passed else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="secpipe", description="Motor de seguranca operado por IA.")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("doctor", help="lista ferramentas disponiveis no PATH")
    scan = sub.add_parser("scan", help="roda o pipeline e aplica o gate (Fase 0: esqueleto)")
    scan.add_argument("target", nargs="?", default=".", help="diretorio alvo (default: .)")
    scan.add_argument("--config", default=None, help="caminho do .secpipe.yml (default: auto)")
    sub.add_parser("version", help="mostra a versao")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "doctor":
        return _cmd_doctor()
    if args.command == "scan":
        return _cmd_scan(args.config, args.target)
    if args.command == "version":
        print(__version__)
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
