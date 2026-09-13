"""Guided helper (wizard).

Walks the user through what they remember about the password and writes a valid
configuration file, then prints the exact command to run. This is the "helper for
correct usage": plain questions, no guessing.
"""

from collections.abc import Callable
from os import PathLike

from .config import Config, default, save, validate

InputFn = Callable[[str], str]
OutputFn = Callable[[str], None]


def config_from_answers(answers: dict) -> Config:
    """Build a Config from a dict of answers (pure, no IO)."""
    cfg = default()
    cfg.database.path = answers.get("db", "")
    cfg.database.keyfile = answers.get("keyfile", "")

    mode = answers.get("mode", "fragments")
    cfg.mask.enabled = mode == "mask"
    cfg.fragments.enabled = mode == "fragments"
    cfg.wordlist.enabled = False

    if mode == "mask":
        cfg.mask.pattern = answers.get("pattern", "")
    else:
        pieces = answers.get("pieces", [])
        cfg.fragments.pieces = pieces
        cfg.fragments.permutations = answers.get("permutations", True)
        cfg.fragments.case_variants = answers.get("case_variants", False)
        cfg.fragments.fixed_prefix = answers.get("fixed_prefix", "")
        cfg.fragments.min_fragments = answers.get("min_fragments", len(pieces) or 1)
    return cfg


def suggest_command(config_path: str | PathLike[str]) -> str:
    """Return the command the user should run with the written config."""
    return f"keepass-kdbx-recover run --config {config_path}"


def _ask(in_: InputFn, prompt: str, default_value: str = "") -> str:
    hint = f" [{default_value}]" if default_value else ""
    answer = in_(f"{prompt}{hint}: ").strip()
    return answer or default_value


def _ask_bool(in_: InputFn, prompt: str, default_value: bool) -> bool:
    d = "y" if default_value else "n"
    answer = in_(f"{prompt} (y/n) [{d}]: ").strip().lower()
    if not answer:
        return default_value
    return answer.startswith("y")


def run_wizard(
    config_path: str | PathLike[str],
    in_: InputFn = input,
    out: OutputFn = print,
) -> Config:
    """Interactively assemble a config, save it, and print the next command."""
    out("keepass-kdbx-recover guided setup")
    out("Only recover databases you own or are authorized to recover.")
    out("")

    answers: dict = {}
    answers["db"] = _ask(in_, "Path to your .kdbx database")
    answers["keyfile"] = _ask(in_, "Keyfile path (leave empty if none)")

    out("")
    out("How do you want to describe the password?")
    out("  1) Fragments - you remember pieces of it")
    out("  2) Mask      - you remember its structure (e.g. Word + 2 digits)")
    choice = _ask(in_, "Choose 1 or 2", "1")

    if choice == "2":
        answers["mode"] = "mask"
        answers["pattern"] = _ask(in_, "Mask pattern (?l ?u ?d ?s ?a; literals kept)")
    else:
        answers["mode"] = "fragments"
        raw = _ask(in_, "Fragments, comma-separated (e.g. sun,flower,42)")
        pieces = [p for p in (s.strip() for s in raw.split(",")) if p]
        answers["pieces"] = pieces
        answers["permutations"] = _ask_bool(in_, "Try all orders of the fragments?", True)
        answers["case_variants"] = _ask_bool(in_, "Also try upper/lower/Capitalized?", False)
        answers["fixed_prefix"] = _ask(in_, "A fragment always used first (empty for none)")
        default_min = str(len(pieces) or 1)
        raw_min = _ask(in_, "Minimum fragments per attempt", default_min)
        try:
            answers["min_fragments"] = int(raw_min)
        except ValueError:
            out(f"'{raw_min}' is not a number; using {default_min}.")
            answers["min_fragments"] = int(default_min)

    cfg = config_from_answers(answers)
    save(cfg, config_path)

    out("")
    out(f"Configuration written to {config_path}")

    errors = validate(cfg)
    if errors:
        out("The configuration is incomplete:")
        for err in errors:
            out(f"  - {err}")
        out("Fix these in the file (or re-run the wizard) before running a recovery.")
    else:
        out("Run it with:")
        out(f"  {suggest_command(config_path)}")
    return cfg
