"""Command-line interface.

Subcommands:
    run       recover the password using the config file and any overrides
    inspect   report the format, cipher, and KDF of a .kdbx (and GPU advice)
    export    write candidates to a file for use as a hashcat wordlist
    wizard    interactive guided setup that writes a config file
    gui       launch the graphical interface

With no subcommand, 'run' is assumed. CLI flags override the config file.
"""

import argparse
import sys
from multiprocessing import freeze_support
from pathlib import Path

from . import __version__
from .candidates import export_candidates
from .config import Config, check_paths, default, load, validate
from .engine import RecoveryEngine, RecoveryError
from .inspector import GpuAdvice, format_inspection, inspect_file
from .progress import ConsoleReporter
from .wizard import run_wizard

COMMANDS = {"run", "inspect", "export", "wizard", "gui"}
DEFAULT_CONFIG = "config.toml"
HELP_FLAGS = {"-h", "--help", "--version"}
DISCLAIMER = "Only recover databases you own or are authorized to recover."


def _add_common(sp: argparse.ArgumentParser) -> None:
    sp.add_argument("--config", default=DEFAULT_CONFIG, help="path to the TOML config file")
    sp.add_argument("--db", help="override the database path")
    sp.add_argument("--keyfile", help="override the keyfile path")
    sp.add_argument("--workers", type=int, help="override worker processes (0 = auto)")
    sp.add_argument("--mask", help="enable mask mode with this pattern")
    sp.add_argument("--fragments", help="enable fragments mode with this comma-separated list")
    sp.add_argument("--wordlist", help="enable wordlist mode with this file path")
    sp.add_argument("--min-fragments", type=int, default=None,
                    help="minimum fragments per attempt (1 = also try single pieces)")
    sp.add_argument("--permute", action=argparse.BooleanOptionalAction, default=None,
                    help="try all orders of the fragments (--no-permute to keep order)")
    sp.add_argument("--case-variants", action=argparse.BooleanOptionalAction, default=None,
                    help="also try lower/UPPER/Capitalized variants of each fragment")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="keepass-kdbx-recover",
        description="Universal recovery tool for KeePass KDBX databases.",
        epilog=DISCLAIMER,
    )
    parser.add_argument(
        "--version", action="version", version=f"keepass-kdbx-recover {__version__}"
    )
    sub = parser.add_subparsers(dest="command")

    run_p = sub.add_parser("run", help="recover the password", epilog=DISCLAIMER)
    _add_common(run_p)
    run_p.set_defaults(func=cmd_run)

    exp_p = sub.add_parser("export", help="write candidates for hashcat", epilog=DISCLAIMER)
    _add_common(exp_p)
    exp_p.add_argument("--out", help="output file (default: config export path)")
    exp_p.set_defaults(func=cmd_export)

    ins_p = sub.add_parser("inspect", help="inspect a .kdbx header")
    ins_p.add_argument("path", nargs="?", help="path to the .kdbx (default: config database)")
    ins_p.add_argument("--config", default=DEFAULT_CONFIG)
    ins_p.set_defaults(func=cmd_inspect)

    wiz_p = sub.add_parser("wizard", help="guided setup")
    wiz_p.add_argument("--config", default=DEFAULT_CONFIG)
    wiz_p.set_defaults(func=cmd_wizard)

    gui_p = sub.add_parser("gui", help="launch the graphical interface")
    gui_p.add_argument("--config", default=DEFAULT_CONFIG)
    gui_p.set_defaults(func=cmd_gui)

    return parser


def normalize_argv(argv: list[str]) -> list[str]:
    """Assume the 'run' subcommand when none is given.

    Top-level help/version flags are left untouched so 'keepass-kdbx-recover -h' shows the
    program help (with all subcommands and the disclaimer), not 'run' help.
    """
    if argv and argv[0] in HELP_FLAGS:
        return argv
    if not argv or argv[0].startswith("-"):
        return ["run", *argv]
    return argv


def load_config_with_overrides(args: argparse.Namespace) -> Config:
    """Load the config file (or defaults) and apply CLI overrides."""
    path = Path(args.config)
    cfg = load(path) if path.is_file() else default()

    if args.db is not None:
        cfg.database.path = args.db
    if args.keyfile is not None:
        cfg.database.keyfile = args.keyfile
    if args.workers is not None:
        cfg.recovery.workers = args.workers

    mode_given = args.mask is not None or args.fragments is not None or args.wordlist is not None
    if mode_given:
        cfg.mask.enabled = args.mask is not None
        cfg.fragments.enabled = args.fragments is not None
        cfg.wordlist.enabled = args.wordlist is not None
        if args.mask is not None:
            cfg.mask.pattern = args.mask
        if args.fragments is not None:
            cfg.fragments.pieces = [s.strip() for s in args.fragments.split(",") if s.strip()]
        if args.wordlist is not None:
            cfg.wordlist.path = args.wordlist

    # Fragment tuning applies whether or not the mode flag was given.
    if args.min_fragments is not None:
        cfg.fragments.min_fragments = args.min_fragments
    if args.permute is not None:
        cfg.fragments.permutations = args.permute
    if args.case_variants is not None:
        cfg.fragments.case_variants = args.case_variants

    return cfg


def _print_errors(errors: list[str]) -> None:
    print("Configuration problems:")
    for err in errors:
        print(f"  - {err}")


def cmd_run(args: argparse.Namespace) -> int:
    cfg = load_config_with_overrides(args)
    errors = validate(cfg) + check_paths(cfg)
    if errors:
        _print_errors(errors)
        return 2
    try:
        result = RecoveryEngine().run(cfg, ConsoleReporter())
    except RecoveryError as exc:
        print(f"Error: {exc}")
        return 3
    return 0 if result.found is not None else 1


def _print_export_advice(db_path: str, out_path: str) -> None:
    if not db_path or not Path(db_path).is_file():
        return
    try:
        insp = inspect_file(db_path)
    except (OSError, ValueError):
        return
    if insp.gpu_advice is GpuAdvice.BIG_ADVANTAGE:
        print(f"This database uses {insp.kdf}: a GPU (hashcat) gives a BIG advantage.")
        print("Extract the hash with keepass2john, then run hashcat, for example:")
        print(f"  hashcat -m 13400 -a 0 hash.txt {out_path}")
    else:
        print(f"This database uses {insp.kdf} (memory-hard): a GPU gives LITTLE advantage.")
        print("The built-in CPU recovery ('keepass-kdbx-recover run') is about as good here.")


def cmd_export(args: argparse.Namespace) -> int:
    cfg = load_config_with_overrides(args)
    cfg.export.enabled = True
    out_path = args.out or cfg.export.path

    errors = validate(cfg) + check_paths(cfg)
    if errors:
        _print_errors(errors)
        return 2

    _print_export_advice(cfg.database.path, out_path)
    try:
        written = export_candidates(
            cfg, out_path, on_progress=lambda n: print(f"  {n:,} written...")
        )
    except OSError as exc:
        print(f"Error: {exc}")
        return 3
    print(f"Wrote {written:,} candidates to {out_path}")
    return 0


def cmd_inspect(args: argparse.Namespace) -> int:
    path = args.path
    if path is None:
        cfg_path = Path(args.config)
        path = load(cfg_path).database.path if cfg_path.is_file() else ""
    if not path:
        print("No database to inspect. Pass a path or set one in the config.")
        return 2
    try:
        print(format_inspection(inspect_file(path)))
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}")
        return 3
    return 0


def cmd_wizard(args: argparse.Namespace) -> int:
    run_wizard(args.config)
    return 0


def cmd_gui(args: argparse.Namespace) -> int:
    try:
        from .gui.app import main as gui_main
    except ImportError as exc:
        print(f"The graphical interface is not available: {exc}")
        return 3
    return gui_main(config_path=args.config)


def main(argv: list[str] | None = None) -> int:
    freeze_support()
    raw = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(normalize_argv(raw))
    return args.func(args)
