"""Configuration model, loading, validation, and saving.

The configuration replaces every value that used to be hardcoded. It is read
from a TOML file with the standard-library ``tomllib`` and written back with
``tomlkit`` so the guidance comments survive a round-trip (the GUI can save it).
"""

import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field, fields
from os import PathLike
from pathlib import Path
from typing import Any

import tomlkit

from .mask import find_unknown_placeholders

PathArg = str | PathLike[str]


@dataclass
class DatabaseCfg:
    path: str = ""
    keyfile: str = ""


@dataclass
class RecoveryCfg:
    workers: int = 0  # 0 = auto
    progress_interval: float = 2.0


@dataclass
class MaskCfg:
    enabled: bool = False
    pattern: str = "Summer?a?a?a?a"


@dataclass
class FragmentsCfg:
    enabled: bool = True
    pieces: list[str] = field(default_factory=lambda: ["1", "2", "3", "fill"])
    permutations: bool = True
    case_variants: bool = False
    fixed_prefix: str = ""
    min_fragments: int = 1  # 1 = also try each single piece; raise to prune the search


@dataclass
class WordlistCfg:
    enabled: bool = False
    path: str = ""


@dataclass
class ExportCfg:
    enabled: bool = False
    path: str = "candidates.txt"


@dataclass
class Config:
    database: DatabaseCfg = field(default_factory=DatabaseCfg)
    recovery: RecoveryCfg = field(default_factory=RecoveryCfg)
    mask: MaskCfg = field(default_factory=MaskCfg)
    fragments: FragmentsCfg = field(default_factory=FragmentsCfg)
    wordlist: WordlistCfg = field(default_factory=WordlistCfg)
    export: ExportCfg = field(default_factory=ExportCfg)


_SECTIONS: dict[str, type] = {
    "database": DatabaseCfg,
    "recovery": RecoveryCfg,
    "mask": MaskCfg,
    "fragments": FragmentsCfg,
    "wordlist": WordlistCfg,
    "export": ExportCfg,
}


def default() -> Config:
    """Return a Config populated with the built-in defaults."""
    return Config()


def _build_section(cls: type, data: Mapping[str, Any]):
    """Construct a section dataclass, taking known keys and ignoring the rest."""
    known = {f.name for f in fields(cls)}
    kwargs = {k: v for k, v in data.items() if k in known}
    return cls(**kwargs)


def load(path: PathArg) -> Config:
    """Load a Config from a TOML file. Missing sections fall back to defaults."""
    with open(path, "rb") as handle:
        raw = tomllib.load(handle)
    sections = {name: _build_section(cls, raw.get(name, {})) for name, cls in _SECTIONS.items()}
    return Config(**sections)


def _is_int(value: object) -> bool:
    # bool is a subclass of int, but a flag is never a valid count.
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value: object) -> bool:
    return _is_int(value) or isinstance(value, float)


def validate(cfg: Config) -> list[str]:
    """Return a list of human-readable structural errors (empty means valid).

    Pure: performs no filesystem access. Use ``check_paths`` for existence checks.
    Type errors are reported (never raised) so a malformed config file yields a
    clean message and a non-zero exit instead of a traceback.
    """
    errors: list[str] = []

    if not (cfg.mask.enabled or cfg.fragments.enabled or cfg.wordlist.enabled):
        errors.append("Enable at least one mode (mask, fragments, or wordlist).")

    if cfg.mask.enabled:
        if not isinstance(cfg.mask.pattern, str):
            errors.append("mask.pattern must be a string.")
        elif not cfg.mask.pattern:
            errors.append("Mask mode is enabled but the pattern is empty.")
        elif unknown := find_unknown_placeholders(cfg.mask.pattern):
            errors.append(
                f"Unknown mask placeholder(s): {', '.join(dict.fromkeys(unknown))}. "
                "Use ?l ?u ?d ?s ?a, or ?? for a literal question mark."
            )

    if cfg.fragments.enabled:
        if not isinstance(cfg.fragments.pieces, list):
            errors.append("fragments.pieces must be a list of strings.")
        elif not cfg.fragments.pieces:
            errors.append("Fragments mode is enabled but no fragment pieces were given.")
        elif not all(isinstance(p, str) for p in cfg.fragments.pieces):
            errors.append("Every fragment piece must be a string.")
        elif cfg.fragments.fixed_prefix and cfg.fragments.fixed_prefix not in cfg.fragments.pieces:
            errors.append("fragments.fixed_prefix must be one of the fragment pieces.")
        if not _is_int(cfg.fragments.min_fragments):
            errors.append("fragments.min_fragments must be an integer.")
        elif cfg.fragments.min_fragments < 1:
            errors.append("fragments.min_fragments must be at least 1.")

    if cfg.wordlist.enabled and not cfg.wordlist.path:
        errors.append("Wordlist mode is enabled but no wordlist path was given.")

    if cfg.export.enabled and not cfg.export.path:
        errors.append("Export mode is enabled but no export path was given.")

    if not _is_int(cfg.recovery.workers):
        errors.append("recovery.workers must be an integer (0 = auto).")
    elif cfg.recovery.workers < 0:
        errors.append("recovery.workers must be 0 (auto) or a positive number.")

    if not _is_number(cfg.recovery.progress_interval):
        errors.append("recovery.progress_interval must be a number.")
    elif cfg.recovery.progress_interval <= 0:
        errors.append("recovery.progress_interval must be greater than 0.")

    return errors


def check_paths(cfg: Config) -> list[str]:
    """Return errors for input files that are required but missing on disk."""
    errors: list[str] = []

    # The database is only needed when we will actually test passwords in-process.
    if not cfg.export.enabled:
        if not cfg.database.path:
            errors.append("No database path is set.")
        elif not Path(cfg.database.path).is_file():
            errors.append(f"Database file not found: {cfg.database.path}")

    if cfg.database.keyfile and not Path(cfg.database.keyfile).is_file():
        errors.append(f"Keyfile not found: {cfg.database.keyfile}")

    if cfg.wordlist.enabled and cfg.wordlist.path and not Path(cfg.wordlist.path).is_file():
        errors.append(f"Wordlist file not found: {cfg.wordlist.path}")

    return errors


def _add(table, key: str, value: Any, comment: str | None = None) -> None:
    """Add a key/value to a tomlkit table, optionally with an inline comment."""
    item = tomlkit.item(value)
    if comment:
        item.comment(comment)
    table.add(key, item)


def _to_document(cfg: Config) -> tomlkit.TOMLDocument:
    """Build a commented tomlkit document from a Config."""
    doc = tomlkit.document()
    doc.add(tomlkit.comment("keepass-kdbx-recover configuration. Edit these values, then run."))
    doc.add(tomlkit.comment("Only recover databases you own or are authorized to recover."))
    doc.add(tomlkit.nl())

    database = tomlkit.table()
    _add(database, "path", cfg.database.path, "path to your .kdbx file")
    _add(database, "keyfile", cfg.database.keyfile, "optional keyfile; empty if unused")
    doc.add("database", database)

    recovery = tomlkit.table()
    _add(recovery, "workers", cfg.recovery.workers, "0 = auto; Argon2 is memory-hard")
    _add(recovery, "progress_interval", cfg.recovery.progress_interval, "seconds between updates")
    doc.add("recovery", recovery)

    mask = tomlkit.table()
    mask.add(tomlkit.comment("hashcat-style: ?l lower ?u upper ?d digit ?s symbol ?a any"))
    _add(mask, "enabled", cfg.mask.enabled)
    _add(mask, "pattern", cfg.mask.pattern)
    doc.add("mask", mask)

    fragments = tomlkit.table()
    fragments.add(tomlkit.comment("remembered pieces recombined into candidates"))
    _add(fragments, "enabled", cfg.fragments.enabled)
    _add(fragments, "pieces", cfg.fragments.pieces)
    _add(fragments, "permutations", cfg.fragments.permutations, "try all orders")
    _add(fragments, "case_variants", cfg.fragments.case_variants, "also try case variants")
    _add(fragments, "fixed_prefix", cfg.fragments.fixed_prefix, "piece used first; empty disables")
    _add(fragments, "min_fragments", cfg.fragments.min_fragments, "1 tries single pieces too")
    doc.add("fragments", fragments)

    wordlist = tomlkit.table()
    _add(wordlist, "enabled", cfg.wordlist.enabled)
    _add(wordlist, "path", cfg.wordlist.path)
    doc.add("wordlist", wordlist)

    export = tomlkit.table()
    export.add(tomlkit.comment("write candidates for hashcat (worthwhile only for AES-KDF)"))
    _add(export, "enabled", cfg.export.enabled)
    _add(export, "path", cfg.export.path)
    doc.add("export", export)

    return doc


def _section_values(cfg: Config) -> dict[str, dict[str, Any]]:
    """Flatten the Config into {section: {key: value}} for writing."""
    return {
        "database": {"path": cfg.database.path, "keyfile": cfg.database.keyfile},
        "recovery": {
            "workers": cfg.recovery.workers,
            "progress_interval": cfg.recovery.progress_interval,
        },
        "mask": {"enabled": cfg.mask.enabled, "pattern": cfg.mask.pattern},
        "fragments": {
            "enabled": cfg.fragments.enabled,
            "pieces": cfg.fragments.pieces,
            "permutations": cfg.fragments.permutations,
            "case_variants": cfg.fragments.case_variants,
            "fixed_prefix": cfg.fragments.fixed_prefix,
            "min_fragments": cfg.fragments.min_fragments,
        },
        "wordlist": {"enabled": cfg.wordlist.enabled, "path": cfg.wordlist.path},
        "export": {"enabled": cfg.export.enabled, "path": cfg.export.path},
    }


def _apply_values(doc: tomlkit.TOMLDocument, cfg: Config) -> None:
    """Update the values of an existing document in place, keeping its comments,
    ordering, and any out-of-schema keys the user added."""
    for section, values in _section_values(cfg).items():
        if section not in doc:
            doc.add(section, tomlkit.table())
        table = doc[section]
        for key, value in values.items():
            table[key] = value


def save(cfg: Config, path: PathArg) -> None:
    """Write the Config to a TOML file.

    If the file already exists it is edited in place, so user-authored comments,
    ordering, and extra keys are preserved. A new file is created from the built-in
    commented template.
    """
    p = Path(path)
    if p.is_file():
        try:
            doc = tomlkit.parse(p.read_text(encoding="utf-8"))
        except Exception:
            doc = _to_document(cfg)
        else:
            _apply_values(doc, cfg)
    else:
        doc = _to_document(cfg)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(tomlkit.dumps(doc))
